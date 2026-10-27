// SPDX-License-Identifier: GPL-2.0-only
/*
 * http.c - HTTP proxy protocol logic (CONNECT tunneling and forwarding).
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "http.h"
#include "http1.h"
#include "auth.h"
#include "common.h"

struct gwp_http_conn {
	struct gwnet_http_hdr_pctx	ctx_hdr;
	struct gwnet_http_req_hdr	req_hdr;

	/*
	 * Bytes of request header consumed so far, summed across every call.
	 * The caller hands us only what it has and advances its buffer by what
	 * we took, so a header that spans several reads is parsed in pieces
	 * and ctx_hdr.off describes the last piece alone -- never the whole
	 * header. Sizing anything from that is wrong; use this.
	 */
	size_t				hdr_len;

	/*
	 * How much of the not-yet-consumed request bytes has been searched for
	 * a line end without finding one. The parser only takes complete
	 * lines, so it is run again only once a new line end has arrived;
	 * otherwise a long line received in small pieces would be parsed from
	 * its start on every read, at a cost quadratic in its length.
	 */
	size_t				scan;

	/*
	 * True for a forwarding request (absolute-form target, e.g.
	 * "GET http://host/path") as opposed to a CONNECT tunnel.
	 */
	bool				is_forward;

	/* Rewritten origin-form request header for a forwarding request. */
	char				*fwd_req;
	size_t				fwd_req_len;

	/* Authenticated username (Basic auth), for ACL "-m user" matching. */
	bool				have_user;
	char				user[256];

	/*
	 * Framing of a forwarding request's body (enum req_body), and what is
	 * left of it: the bytes of a Content-Length body, or the size or data
	 * bytes of the current chunk. Nothing after the body is forwarded.
	 */
	uint8_t				req_body;
	uint8_t				chunk_st;
	uint8_t				chunk_digits;
	uint64_t			req_rem;

	/*
	 * The origin's response to a forwarding request. Its header is held
	 * back in @res_buf until complete, so nothing the origin says reaches
	 * the client before it has been rewritten; @res_scan is how far the
	 * search for the blank line that ends it has got.
	 */
	uint8_t				res_state;
	char				*res_buf;
	size_t				res_len;
	size_t				res_cap;
	size_t				res_scan;
};

/* Longest request header accepted, in bytes. */
#define REQ_HDR_MAX		16384

struct gwp_http_conn *gwp_http_conn_alloc(void)
{
	struct gwp_http_conn *hc = calloc(1, sizeof(*hc));

	if (!hc)
		return NULL;

	if (gwnet_http_hdr_pctx_init(&hc->ctx_hdr) < 0) {
		free(hc);
		return NULL;
	}
	hc->ctx_hdr.max_len = REQ_HDR_MAX;

	return hc;
}

void gwp_http_conn_free(struct gwp_http_conn *hc)
{
	if (!hc)
		return;

	gwnet_http_hdr_pctx_free(&hc->ctx_hdr);
	gwnet_http_req_hdr_free(&hc->req_hdr);
	free(hc->fwd_req);
	free(hc->res_buf);
	free(hc);
}

bool gwp_http_conn_is_forward(const struct gwp_http_conn *hc)
{
	return hc->is_forward;
}

const char *gwp_http_conn_username(const struct gwp_http_conn *hc)
{
	return hc->have_user ? hc->user : NULL;
}

/*
 * Map a parsed HTTP method code back to its request-line token. Returns NULL
 * for a method the forwarding proxy does not re-emit.
 */
static const char *http_method_str(uint8_t method)
{
	switch (method) {
	case GWNET_HTTP_METHOD_GET:	return "GET";
	case GWNET_HTTP_METHOD_POST:	return "POST";
	case GWNET_HTTP_METHOD_PUT:	return "PUT";
	case GWNET_HTTP_METHOD_DELETE:	return "DELETE";
	case GWNET_HTTP_METHOD_HEAD:	return "HEAD";
	case GWNET_HTTP_METHOD_OPTIONS:	return "OPTIONS";
	case GWNET_HTTP_METHOD_PATCH:	return "PATCH";
	case GWNET_HTTP_METHOD_TRACE:	return "TRACE";
	default:			return NULL;
	}
}

/*
 * Split a "host:port" authority (a CONNECT target, or the authority of an
 * absolute-form URI) into NUL-terminated @host_p/@port_p in place. Any
 * userinfo is discarded. IPv6 literals in brackets ("[::1]:80") are unwrapped.
 * With no ":port", @default_port is used; pass NULL to require an explicit
 * port. Returns 0 on success or -EINVAL on a malformed authority.
 */
static int split_authority(char *authority, char **host_p, char **port_p,
			   char *default_port)
{
	char *host = authority, *colon = NULL, *end, *at;

	if (!*authority)
		return -EINVAL;

	/*
	 * RFC 3986 s3.2: userinfo runs up to the LAST '@' and is not part of
	 * the host. Drop it before looking for the port separator, or an
	 * authority like "A:B@C" is split on the colon inside the userinfo and
	 * yields host "A" -- attacker-chosen, while the authority still reads
	 * as "C" to anything inspecting the URL.
	 */
	at = strrchr(host, '@');
	if (at)
		host = at + 1;

	if (*host == '[') {
		char *rb = strchr(host, ']');

		if (!rb || rb == host + 1)
			return -EINVAL;
		host++;			/* skip '[' */
		*rb = '\0';		/* terminate the host */
		end = rb + 1;
		if (*end == ':')
			colon = end;
		else if (*end != '\0')
			return -EINVAL;
	} else {
		colon = strrchr(host, ':');
	}

	if (colon) {
		*colon = '\0';
		*port_p = colon + 1;
		if (!**port_p)
			return -EINVAL;
	} else {
		if (!default_port)
			return -EINVAL;
		*port_p = default_port;
	}

	if (!*host)
		return -EINVAL;

	*host_p = host;
	return 0;
}

/*
 * Well-known hop-by-hop / connection-specific request header fields that a
 * proxy must not forward (RFC 9110 Section 7.6.1). Transfer-Encoding and
 * Content-Length are deliberately absent: this proxy relays the body verbatim,
 * so the origin still needs them to frame it. Expect is absent too, so a
 * "100-continue" expectation is forwarded to the origin (RFC 9110 Section
 * 10.1.1). "Proxy-Connection" is non-standard but sent by some clients.
 */
static bool is_hop_by_hop(const char *k, size_t klen)
{
#define HBH(s)	{ s, sizeof(s) - 1 }
	static const struct {
		const char	*name;
		size_t		len;
	} hbh[] = {
		HBH("Connection"), HBH("Proxy-Connection"), HBH("Keep-Alive"),
		HBH("TE"), HBH("Trailer"), HBH("Upgrade"),
		HBH("Proxy-Authorization"), HBH("Proxy-Authenticate"),
	};
#undef HBH
	size_t i;

	for (i = 0; i < sizeof(hbh) / sizeof(hbh[0]); i++) {
		if (hbh[i].len == klen && !strncasecmp(k, hbh[i].name, klen))
			return true;
	}
	return false;
}

/*
 * Most distinct connection-options accepted in a message's Connection
 * header(s). Real messages name one or two; the limit keeps checking every
 * other field against them cheap.
 */
#define CONN_MAX_TOKENS		32

/* A connection-option: @len bytes at @p, not NUL-terminated. */
struct conn_tok {
	const char	*p;
	size_t		len;
};

/*
 * Add the connection-options of the Connection value at @v (@len bytes) to
 * the @nr already in @toks, skipping empty list elements and options already
 * there (case-insensitively). Returns the new count, or -E2BIG if that would
 * take more than CONN_MAX_TOKENS.
 */
static int conn_tokenise(const char *v, size_t len, struct conn_tok *toks,
			 int nr)
{
	const char *p = v, *end = v + len;

	while (p < end) {
		const char *e;
		size_t tlen;
		int i;

		while (p < end && (*p == ',' || *p == ' ' || *p == '\t'))
			p++;
		if (p == end)
			break;
		e = memchr(p, ',', (size_t)(end - p));
		if (!e)
			e = end;
		tlen = (size_t)(e - p);
		while (tlen > 0 && (p[tlen - 1] == ' ' || p[tlen - 1] == '\t'))
			tlen--;

		for (i = 0; i < nr; i++) {
			if (toks[i].len == tlen &&
			    !strncasecmp(toks[i].p, p, tlen))
				break;
		}
		if (i == nr) {
			if (nr >= CONN_MAX_TOKENS)
				return -E2BIG;
			toks[nr].p = p;
			toks[nr].len = tlen;
			nr++;
		}
		p = e;
	}
	return nr;
}

/* Whether the field name @k (@klen bytes) is one of the @nr options. */
static bool conn_toks_have(const struct conn_tok *toks, int nr, const char *k,
			   size_t klen)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (toks[i].len == klen && !strncasecmp(toks[i].p, k, klen))
			return true;
	}
	return false;
}

/* Append @len bytes at @p to @buf (@cap bytes, @n used); false if full. */
static bool buf_add(char *buf, size_t cap, size_t *n, const char *p,
		    size_t len)
{
	if (len > cap - *n)
		return false;
	memcpy(buf + *n, p, len);
	*n += len;
	return true;
}

/*
 * Rebuild the request in origin-form into hc->fwd_req: the absolute-form
 * request-target is replaced by @path, hop-by-hop / connection-specific
 * headers are dropped and "Connection: close" is appended (this proxy handles
 * one request per connection). @authority is the URI's authority, passed as
 * pointer+length because at this point it is still part of the request line
 * and not NUL-terminated. @hdr_len is the length of the parsed request
 * header, used to size the scratch buffer (the rewrite is never materially
 * larger). Returns 0 or a negative error.
 */
static int build_forward_request(struct gwp_http_conn *hc, const char *path,
				 const char *authority, size_t auth_len,
				 size_t hdr_len)
{
	static const char cls[] = "Connection: close\r\n\r\n";
	struct gwnet_http_req_hdr *req = &hc->req_hdr;
	const char *method = http_method_str(req->method);
	const char *ver = (req->version == GWNET_HTTP_VER_1_0) ?
			  " HTTP/1.0\r\n" : " HTTP/1.1\r\n";
	const char *conn = gwnet_http_hdr_fields_get(&req->fields, "Connection");
	struct conn_tok toks[CONN_MAX_TOKENS];
	size_t cap = hdr_len * 2 + 64, n = 0, i;
	int nr_toks = 0;
	bool ok;
	char *buf;

	if (!method)
		return -EINVAL;

	/* Too many options to check every field against is not plausible. */
	if (conn) {
		nr_toks = conn_tokenise(conn, strlen(conn), toks, 0);
		if (nr_toks < 0)
			return -EBADMSG;
	}

	/*
	 * Fields the Connection header names are dropped below, as RFC 9110
	 * Section 7.6.1 asks. That must never take the framing fields with
	 * them: the body follows the header unchanged, so an origin that no
	 * longer sees Content-Length or Transfer-Encoding reads the body as
	 * the next request -- a client-chosen request line and Host smuggled
	 * past the rewrite above. Host is replaced anyway, and listing it is
	 * just as meaningless. Nothing legitimate does this; refuse it.
	 */
	if (conn_toks_have(toks, nr_toks, "Content-Length", 14) ||
	    conn_toks_have(toks, nr_toks, "Transfer-Encoding", 17) ||
	    conn_toks_have(toks, nr_toks, "Host", 4))
		return -EBADMSG;

	buf = malloc(cap);
	if (!buf)
		return -ENOMEM;

	ok = buf_add(buf, cap, &n, method, strlen(method)) &&
	     buf_add(buf, cap, &n, " ", 1) &&
	     buf_add(buf, cap, &n, path, strlen(path)) &&
	     buf_add(buf, cap, &n, ver, 11);
	if (!ok)
		goto too_big;

	/*
	 * RFC 9112 s3.2.2: with an absolute-form target the proxy MUST ignore
	 * the Host the client sent and use the authority from the URI instead.
	 * Forwarding the client's copy lets it point us at one host while
	 * telling the origin another (vhost confusion, and a way around an ACL
	 * that matched on the name), and a client that sends no Host at all
	 * would otherwise leave us emitting an invalid HTTP/1.1 request.
	 *
	 * The authority is copied verbatim so an IPv6 literal keeps its
	 * brackets and an absent port stays absent -- except for userinfo,
	 * which is not part of the host and must not reach the origin.
	 */
	{
		const char *host = authority;
		size_t hlen = auth_len;
		const char *at = memrchr(authority, '@', auth_len);

		if (at) {
			host = at + 1;
			hlen = auth_len - (size_t)(host - authority);
		}
		if (!hlen) {
			free(buf);
			return -EINVAL;
		}

		ok = buf_add(buf, cap, &n, "Host: ", 6) &&
		     buf_add(buf, cap, &n, host, hlen) &&
		     buf_add(buf, cap, &n, "\r\n", 2);
		if (!ok)
			goto too_big;
	}

	for (i = 0; i < req->fields.nr; i++) {
		const struct gwnet_http_hdr_field *f = &req->fields.ff[i];

		/* Drop hop-by-hop and Connection-listed headers, and the
		 * client's Host -- ours is already in place above. */
		if (is_hop_by_hop(f->key, f->klen) ||
		    conn_toks_have(toks, nr_toks, f->key, f->klen) ||
		    (f->klen == 4 && !strncasecmp(f->key, "Host", 4)))
			continue;

		ok = buf_add(buf, cap, &n, f->key, f->klen) &&
		     buf_add(buf, cap, &n, ": ", 2) &&
		     buf_add(buf, cap, &n, f->val, f->vlen) &&
		     buf_add(buf, cap, &n, "\r\n", 2);
		if (!ok)
			goto too_big;
	}

	/* NUL-terminated as well, for whoever wants to log or search it. */
	if (!buf_add(buf, cap, &n, cls, sizeof(cls)))
		goto too_big;
	n--;

	free(hc->fwd_req);
	hc->fwd_req = buf;
	hc->fwd_req_len = n;
	return 0;

too_big:
	free(buf);
	return -E2BIG;
}

enum req_body {
	REQ_BODY_DONE = 0,	/* No body, or all of it has been seen. */
	REQ_BODY_LENGTH,	/* Content-Length; req_rem bytes to go. */
	REQ_BODY_CHUNKED,	/* Transfer-Encoding: chunked; see chunk_st. */
};

/*
 * Work out how the request body is delimited (RFC 9112 Section 6.3), so that
 * exactly that body follows the header to the origin and nothing after it
 * does. Anything the origin might delimit differently from us is refused
 * rather than guessed at: both Content-Length and Transfer-Encoding, a
 * Transfer-Encoding other than plain "chunked" (or any, from an HTTP/1.0
 * client, which cannot use it), and a Content-Length that is not a number.
 * Returns 0 or -EBADMSG.
 */
static int set_req_framing(struct gwp_http_conn *hc)
{
	const struct gwnet_http_hdr_fields *ff = &hc->req_hdr.fields;
	const char *te = gwnet_http_hdr_fields_get(ff, "Transfer-Encoding");
	const char *cl = gwnet_http_hdr_fields_get(ff, "Content-Length");
	uint64_t len = 0;

	if (te && cl)
		return -EBADMSG;

	if (te) {
		if (hc->req_hdr.version == GWNET_HTTP_VER_1_0 ||
		    strcasecmp(te, "chunked"))
			return -EBADMSG;
		hc->req_body = REQ_BODY_CHUNKED;
		return 0;
	}

	if (cl) {
		if (!*cl)
			return -EBADMSG;
		for (; *cl; cl++) {
			if (*cl < '0' || *cl > '9' || len > (UINT64_MAX - 9) / 10)
				return -EBADMSG;
			len = len * 10 + (uint64_t)(*cl - '0');
		}
	}

	hc->req_rem = len;
	hc->req_body = len ? REQ_BODY_LENGTH : REQ_BODY_DONE;
	return 0;
}

/*
 * Classify a fully-parsed forwarding request: rebuild it in origin-form and
 * split the http:// authority into host/port. Returns GWP_HTTP_FORWARD,
 * GWP_HTTP_BAD_REQUEST or GWP_HTTP_ERR.
 */
static int classify_forward(struct gwp_http_conn *hc, size_t hdr_len,
			    char **host_p, char **port_p,
			    const char **req_p, size_t *req_len_p)
{
	static char default_port[] = "80";
	char *uri = hc->req_hdr.uri, *authority, *slash;
	const char *path;
	int r;

	/* Only absolute-form http:// URIs are supported (no TLS termination). */
	if (!uri || strncasecmp(uri, "http://", 7))
		return GWP_HTTP_ERR;

	authority = uri + 7;

	/* The origin-form path is everything from the first '/', else "/". */
	slash = authority;
	while (*slash && *slash != '/')
		slash++;
	if (slash == authority)
		return GWP_HTTP_ERR;		/* empty authority */
	path = (*slash == '/') ? slash : "/";

	/*
	 * Build the rewritten request now, while @path is still intact; the
	 * authority is isolated (and the path's leading '/' overwritten) only
	 * afterwards.
	 */
	r = set_req_framing(hc);
	if (!r)
		r = build_forward_request(hc, path, authority,
					  (size_t)(slash - authority), hdr_len);
	if (r == -EBADMSG)
		return GWP_HTTP_BAD_REQUEST;
	if (r < 0)
		return GWP_HTTP_ERR;

	if (*slash == '/')
		*slash = '\0';
	if (split_authority(authority, host_p, port_p, default_port) < 0)
		return GWP_HTTP_ERR;

	hc->is_forward = true;
	*req_p = hc->fwd_req;
	*req_len_p = hc->fwd_req_len;
	return GWP_HTTP_FORWARD;
}

int gwp_http_conn_process(struct gwp_http_conn *hc, struct gwp_auth *auth,
			  const void *in, size_t *in_len,
			  char **host_p, char **port_p,
			  const char **req_p, size_t *req_len_p)
{
	struct gwnet_http_req_hdr *req = &hc->req_hdr;
	size_t hdr_len, len = *in_len, used;
	const char *p = in;
	int r;

	/*
	 * Nothing to do until a line is complete: only the bytes not searched
	 * yet are looked at. Past the length limit the parser runs anyway, to
	 * refuse the header.
	 */
	if (hc->scan > len)
		hc->scan = 0;
	if (hc->hdr_len + len <= REQ_HDR_MAX &&
	    !memchr(p + hc->scan, '\n', len - hc->scan)) {
		hc->scan = len;
		*in_len = 0;
		return GWP_HTTP_NEED_MORE;
	}

	hc->ctx_hdr.buf = in;
	hc->ctx_hdr.len = len;
	hc->ctx_hdr.off = 0;
	r = gwnet_http_req_hdr_parse(&hc->ctx_hdr, req);
	used = hc->ctx_hdr.off;
	*in_len = used;
	hc->hdr_len += used;
	if (r == -EAGAIN) {
		/*
		 * Every complete line has been taken; what is left is the
		 * start of the next one. Should the parser ever leave a line
		 * end behind, search from the start again so it is not missed.
		 */
		hc->scan = memchr(p + used, '\n', len - used) ? 0 : len - used;
		return GWP_HTTP_NEED_MORE;
	}
	/*
	 * A repeated field that may appear only once (Host, Content-Length,
	 * ...) is a well-formed line in an unacceptable request; say so
	 * rather than drop the connection without a word.
	 */
	if (r == -EEXIST)
		return GWP_HTTP_BAD_REQUEST;
	if (r == -E2BIG)
		return GWP_HTTP_TOO_LARGE;
	if (r < 0)
		return GWP_HTTP_ERR;

	/* Header complete. */
	hdr_len = hc->hdr_len;

	/*
	 * "Basic" proxy authentication (shared with SOCKS5) applies to CONNECT
	 * and forwarding requests alike.
	 */
	if (auth) {
		const char *cred = gwnet_http_hdr_fields_get(&req->fields,
							     "Proxy-Authorization");
		if (!gwp_auth_check_basic_ex(auth, cred, hc->user,
					     sizeof(hc->user)))
			return GWP_HTTP_NEED_AUTH;
		hc->have_user = true;
	}

	/* A non-CONNECT method is a forwarding request (absolute-form target). */
	if (req->method != GWNET_HTTP_METHOD_CONNECT)
		return classify_forward(hc, hdr_len, host_p, port_p, req_p,
					req_len_p);

	/* CONNECT: the target is an authority-form "host:port" to tunnel to. */
	if (split_authority(req->uri, host_p, port_p, NULL) < 0)
		return GWP_HTTP_ERR;

	hc->is_forward = false;
	return GWP_HTTP_CONNECT;
}

/*
 * Response header fields that describe the proxy-to-origin connection only
 * and are not passed on to the client. Content-Length and Transfer-Encoding
 * are absent because the body is relayed verbatim and the client needs them
 * to frame it; Trailer stays with Transfer-Encoding for the same reason.
 * Proxy-Authenticate and Proxy-Authentication-Info are addressed to a proxy:
 * coming from an origin they could only be an attempt to have the client
 * offer its proxy credentials.
 */
static bool is_res_hop_by_hop(const char *k, size_t klen)
{
#define HBH(s)	{ s, sizeof(s) - 1 }
	static const struct {
		const char	*name;
		size_t		len;
	} hbh[] = {
		HBH("Connection"), HBH("Proxy-Connection"), HBH("Keep-Alive"),
		HBH("Upgrade"), HBH("TE"), HBH("Proxy-Authenticate"),
		HBH("Proxy-Authentication-Info"),
	};
#undef HBH
	size_t i;

	for (i = 0; i < sizeof(hbh) / sizeof(hbh[0]); i++) {
		if (hbh[i].len == klen && !strncasecmp(k, hbh[i].name, klen))
			return true;
	}
	return false;
}

static bool is_framing_field(const char *k, size_t klen)
{
	return (klen == 14 && !strncasecmp(k, "Content-Length", 14)) ||
	       (klen == 17 && !strncasecmp(k, "Transfer-Encoding", 17));
}

static bool is_tchar(unsigned char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return true;
	return c && strchr("!#$%&'*+-.^_`|~", c);
}

/*
 * Field values and the reason phrase may hold HTAB, SP, VCHAR and obs-text
 * (RFC 9110 Section 5.5); a bare CR, NUL or any other control byte is not
 * valid anywhere in a header and would let the origin split the line it is
 * copied into.
 */
static bool is_field_char(unsigned char c)
{
	return c == '\t' || (c >= 0x20 && c != 0x7f);
}

/*
 * States of the chunked body scanner (RFC 9112 Section 7.1). It only finds
 * where the body ends; the bytes themselves pass through unchanged. Line ends
 * must be CRLF: being stricter than the origin is harmless, being more lenient
 * would let the two disagree on where the body stops.
 */
enum {
	CH_SIZE = 0,	/* chunk-size hex digits */
	CH_BWS,		/* whitespace between chunk-size and ';' */
	CH_EXT,		/* chunk extensions, up to CR */
	CH_SIZE_LF,	/* LF ending the chunk-size line */
	CH_DATA,	/* chunk data, req_rem bytes to go */
	CH_DATA_CR,	/* CRLF after chunk data */
	CH_DATA_LF,
	CH_TRAILER,	/* start of a trailer line, or the final CRLF */
	CH_TRAILER_NAME,	/* trailer field-name, up to ':' */
	CH_TRAILER_VALUE,	/* trailer field-value, up to CR */
	CH_TRAILER_LF,
	CH_END_LF,	/* LF of the final CRLF */
};

static int hex_val(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c |= 0x20;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * Largest chunk accepted. Nothing legitimate sends a 2 GiB chunk, and a size
 * near 2^64 is where implementations that parse it into a narrower or signed
 * type start to disagree with us about where the chunk ends.
 */
#define CHUNK_SIZE_MAX	0x7fffffffull

/*
 * Scan @len bytes of a chunked body. *@used is set to how many of them belong
 * to it; fewer than @len only once the body has ended. Returns 0, or -EBADMSG
 * on a malformed body.
 */
static int scan_chunked(struct gwp_http_conn *hc, const unsigned char *p,
			size_t len, size_t *used)
{
	size_t i = 0, n;
	int d;

	while (i < len && hc->req_body == REQ_BODY_CHUNKED) {
		unsigned char c = p[i];

		switch (hc->chunk_st) {
		case CH_SIZE:
			d = hex_val(c);
			if (d >= 0) {
				/* Leading zeros count too; keep it bounded. */
				if (++hc->chunk_digits > 16)
					return -EBADMSG;
				hc->req_rem = (hc->req_rem << 4) | (uint64_t)d;
				if (hc->req_rem > CHUNK_SIZE_MAX)
					return -EBADMSG;
				break;
			}
			if (!hc->chunk_digits)
				return -EBADMSG;
			if (c == '\r')
				hc->chunk_st = CH_SIZE_LF;
			else if (c == ';')
				hc->chunk_st = CH_EXT;
			else if (c == ' ' || c == '\t')
				hc->chunk_st = CH_BWS;
			else
				return -EBADMSG;
			break;
		case CH_BWS:
			/* BWS is only allowed ahead of a chunk extension. */
			if (c == ';')
				hc->chunk_st = CH_EXT;
			else if (c != ' ' && c != '\t')
				return -EBADMSG;
			break;
		case CH_EXT:
			if (c == '\r')
				hc->chunk_st = CH_SIZE_LF;
			else if (!is_field_char(c))
				return -EBADMSG;
			break;
		case CH_SIZE_LF:
			if (c != '\n')
				return -EBADMSG;
			hc->chunk_st = hc->req_rem ? CH_DATA : CH_TRAILER;
			break;
		case CH_DATA:
			n = len - i;
			if (n > hc->req_rem)
				n = (size_t)hc->req_rem;
			hc->req_rem -= n;
			if (!hc->req_rem)
				hc->chunk_st = CH_DATA_CR;
			i += n;
			continue;
		case CH_DATA_CR:
			if (c != '\r')
				return -EBADMSG;
			hc->chunk_st = CH_DATA_LF;
			break;
		case CH_DATA_LF:
			if (c != '\n')
				return -EBADMSG;
			hc->chunk_st = CH_SIZE;
			hc->chunk_digits = 0;
			break;
		case CH_TRAILER:
			if (c == '\r')
				hc->chunk_st = CH_END_LF;
			else if (is_tchar(c))
				hc->chunk_st = CH_TRAILER_NAME;
			else
				return -EBADMSG;
			break;
		case CH_TRAILER_NAME:
			/*
			 * A trailer is a field line, "name: value". Anything
			 * else -- a request line, say -- is where an origin
			 * that ends the body early would find a request of
			 * the client's choosing.
			 */
			if (c == ':')
				hc->chunk_st = CH_TRAILER_VALUE;
			else if (!is_tchar(c))
				return -EBADMSG;
			break;
		case CH_TRAILER_VALUE:
			if (c == '\r')
				hc->chunk_st = CH_TRAILER_LF;
			else if (!is_field_char(c))
				return -EBADMSG;
			break;
		case CH_TRAILER_LF:
			if (c != '\n')
				return -EBADMSG;
			hc->chunk_st = CH_TRAILER;
			break;
		case CH_END_LF:
			if (c != '\n')
				return -EBADMSG;
			hc->req_body = REQ_BODY_DONE;
			break;
		}
		i++;
	}

	*used = i;
	return 0;
}

int gwp_http_fwd_req_body(struct gwp_http_conn *hc, const void *in,
			  size_t len, size_t *fwd_len)
{
	switch (hc->req_body) {
	case REQ_BODY_LENGTH:
		if (len > hc->req_rem)
			len = (size_t)hc->req_rem;
		hc->req_rem -= len;
		if (!hc->req_rem)
			hc->req_body = REQ_BODY_DONE;
		*fwd_len = len;
		return 0;
	case REQ_BODY_CHUNKED:
		return scan_chunked(hc, in, len, fwd_len);
	default:
		*fwd_len = 0;
		return 0;
	}
}

/*
 * Return the line after the one at @p, which ends before @end; *@n is set to
 * the length of the line at @p without its terminator (LF or CRLF).
 */
static const char *next_line(const char *p, const char *end, size_t *n)
{
	const char *lf = memchr(p, '\n', (size_t)(end - p));

	*n = (size_t)(lf - p);
	if (*n && p[*n - 1] == '\r')
		(*n)--;
	return lf + 1;
}

/*
 * Most field lines accepted in one response header. Ordinary responses have
 * a few dozen; without a limit the work per header grows with the size of
 * the hold-back buffer (-T).
 */
#define RES_MAX_FIELDS		256

/* Where a field line sits in the header: offset, length and name length. */
struct res_line {
	uint32_t	off;
	uint32_t	len;
	uint32_t	klen;
};

/*
 * Rewrite one complete response header (@len bytes, ending with its blank
 * line) into @out: lines are normalised to CRLF, hop-by-hop fields and fields
 * named by Connection are dropped and, for a final response, the client is
 * told that the connection closes after it. *@code is set to the status code.
 *
 * Returns the length written, -EBADMSG for a header that is not valid
 * HTTP/1.x, or -E2BIG if @out is too small or the header has more than
 * RES_MAX_FIELDS field lines or CONN_MAX_TOKENS connection-options.
 */
/* Not inlined: its stack frame must not add up with its callers'. */
static noinline ssize_t rewrite_res_hdr(const char *hdr, size_t len, char *out,
					size_t out_cap, int *code)
{
	static const char cls[] = "Connection: close\r\n"
				  "Proxy-Connection: close\r\n";
	struct res_line lines[RES_MAX_FIELDS];
	struct conn_tok toks[CONN_MAX_TOKENS];
	const char *p = hdr, *end = hdr + len, *q;
	int nr_toks = 0, nr_lines = 0, l;
	size_t n, o, i;

	/* Status line: HTTP/1.x SP 3DIGIT [ SP reason-phrase ] */
	q = next_line(p, end, &n);
	if (n < 12 || memcmp(p, "HTTP/1.", 7) || (p[7] != '0' && p[7] != '1') ||
	    p[8] != ' ' || p[9] < '1' || p[9] > '5' || p[10] < '0' ||
	    p[10] > '9' || p[11] < '0' || p[11] > '9' ||
	    (n > 12 && p[12] != ' '))
		return -EBADMSG;
	for (i = 12; i < n; i++) {
		if (!is_field_char(p[i]))
			return -EBADMSG;
	}
	*code = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
	if (n + 2 > out_cap)
		return -E2BIG;
	memcpy(out, p, n);
	memcpy(out + n, "\r\n", 2);
	o = n + 2;

	/*
	 * Validate the field lines, note where each one is and collect the
	 * connection-options first: a field may be named by a Connection line
	 * that comes after it.
	 */
	for (p = q; ; p = q) {
		const char *colon, *v;

		q = next_line(p, end, &n);
		if (!n)
			break;
		if (nr_lines == RES_MAX_FIELDS)
			return -E2BIG;
		/* obs-fold (RFC 9112 Section 5.2) is refused, not unfolded. */
		colon = memchr(p, ':', n);
		if (!colon || colon == p)
			return -EBADMSG;
		for (v = p; v < colon; v++) {
			if (!is_tchar(*v))
				return -EBADMSG;
		}
		for (v = colon + 1; v < p + n; v++) {
			if (!is_field_char(*v))
				return -EBADMSG;
		}
		lines[nr_lines].off = (uint32_t)(p - hdr);
		lines[nr_lines].len = (uint32_t)n;
		lines[nr_lines].klen = (uint32_t)(colon - p);
		nr_lines++;
		if (colon - p == 10 && !strncasecmp(p, "Connection", 10)) {
			nr_toks = conn_tokenise(colon + 1, n - 11, toks,
						nr_toks);
			if (nr_toks < 0)
				return nr_toks;
		}
	}

	for (l = 0; l < nr_lines; l++) {
		const char *k = hdr + lines[l].off;
		size_t klen = lines[l].klen;

		n = lines[l].len;
		if (is_res_hop_by_hop(k, klen))
			continue;
		if (!is_framing_field(k, klen) &&
		    conn_toks_have(toks, nr_toks, k, klen))
			continue;
		if (o + n + 2 > out_cap)
			return -E2BIG;
		memcpy(out + o, k, n);
		memcpy(out + o + n, "\r\n", 2);
		o += n + 2;
	}

	/* An interim response says nothing about the connection. */
	n = (*code >= 200) ? sizeof(cls) - 1 : 0;
	if (o + n + 2 > out_cap)
		return -E2BIG;
	memcpy(out + o, cls, n);
	memcpy(out + o + n, "\r\n", 2);
	return (ssize_t)(o + n + 2);
}

/*
 * Return the length of the header at the start of @buf up to and including
 * the blank line that ends it, or 0 if it is not complete yet. *@scan is where
 * the search resumes, so a header dribbled in byte by byte is not rescanned
 * from the start on every call.
 */
static size_t find_hdr_end(const char *buf, size_t len, size_t *scan)
{
	size_t i;

	for (i = *scan; i < len; i++) {
		if (buf[i] != '\n')
			continue;
		if (i + 1 >= len)
			break;
		if (buf[i + 1] == '\n')
			return i + 2;
		if (buf[i + 1] != '\r')
			continue;
		if (i + 2 >= len)
			break;
		if (buf[i + 2] == '\n')
			return i + 3;
	}
	*scan = i;
	return 0;
}

int gwp_http_fwd_res_init(struct gwp_http_conn *hc, size_t max_hdr)
{
	/* The hold-back buffer is allocated only if a header spans reads. */
	free(hc->res_buf);
	hc->res_buf = NULL;
	hc->res_cap = max_hdr;
	hc->res_len = 0;
	hc->res_scan = 0;
	hc->res_state = GWP_HTTP_RES_HDR;
	return 0;
}

int gwp_http_fwd_res_state(const struct gwp_http_conn *hc)
{
	return hc->res_state;
}

size_t gwp_http_fwd_res_pending(const struct gwp_http_conn *hc)
{
	return hc->res_len;
}

/*
 * The rewrite of a final header that arrived whole in one read is built here,
 * on the stack, rather than in the hold-back buffer. Larger ones take the
 * general path.
 */
#define RES_FAST_MAX		4096

/*
 * The usual case: nothing is held back and @in holds the whole final header.
 * Rewrite it straight from @in, with no hold-back copy and no allocation.
 * Returns 1 if the response was not handled (no complete header, an interim
 * response, or a rewrite too large for the stack) and the general path must
 * take it, else 0 or a negative error as res_input().
 */
static int res_input_fast(struct gwp_http_conn *hc, const char *in,
			  size_t len, char *out, size_t out_cap,
			  size_t *out_len)
{
	char tmp[RES_FAST_MAX];
	size_t scan = 0, end, body;
	ssize_t w;
	int code;

	end = find_hdr_end(in, len, &scan);
	if (!end) {
		/* The general path resumes the search from here. */
		hc->res_scan = scan;
		return 1;
	}

	w = rewrite_res_hdr(in, end, tmp,
			    out_cap < sizeof(tmp) ? out_cap : sizeof(tmp),
			    &code);
	if (w == -E2BIG)
		return 1;
	if (w < 0)
		return (int)w;
	if (code < 200)
		return 1;
	if (code == 407)
		return -EACCES;

	/* @in may alias @out: move the body before the header goes in. */
	body = len - end;
	if (body > out_cap - (size_t)w)
		return -E2BIG;
	memmove(out + w, in + end, body);
	memcpy(out, tmp, (size_t)w);
	free(hc->res_buf);	/* Left from an interim response, if any. */
	hc->res_buf = NULL;
	hc->res_state = GWP_HTTP_RES_BODY;
	*out_len = (size_t)w + body;
	return 0;
}

static int res_input(struct gwp_http_conn *hc, const void *in, size_t len,
		     bool eof, char *out, size_t out_cap, size_t *out_len)
{
	size_t o = 0, end;
	ssize_t w;
	int code;

	if (len > hc->res_cap - hc->res_len)
		return -E2BIG;

	if (!hc->res_len) {
		int r = res_input_fast(hc, in, len, out, out_cap, out_len);

		if (r <= 0)
			return r;
	}

	if (!hc->res_buf) {
		hc->res_buf = malloc(hc->res_cap);
		if (!hc->res_buf)
			return -ENOMEM;
	}
	memcpy(hc->res_buf + hc->res_len, in, len);
	hc->res_len += len;

	for (;;) {
		end = find_hdr_end(hc->res_buf, hc->res_len, &hc->res_scan);
		if (!end) {
			if (eof)
				return -EBADMSG;
			if (hc->res_len >= hc->res_cap)
				return -E2BIG;
			*out_len = o;
			return 0;
		}

		w = rewrite_res_hdr(hc->res_buf, end, out + o, out_cap - o,
				    &code);
		if (w < 0)
			return (int)w;

		/*
		 * The proxy took the Upgrade header out of the request, so a
		 * 101 is not something the client asked for. A 407 is the
		 * origin asking for the client's proxy credentials, which are
		 * none of its business.
		 */
		if (code == 101)
			return -EBADMSG;
		if (code == 407)
			return -EACCES;

		o += (size_t)w;
		hc->res_len -= end;
		memmove(hc->res_buf, hc->res_buf + end, hc->res_len);
		hc->res_scan = 0;

		/* Interim (1xx): pass it on and wait for the next header. */
		if (code < 200)
			continue;

		/* Body bytes that came in behind the header follow it. */
		if (hc->res_len > out_cap - o)
			return -E2BIG;
		memcpy(out + o, hc->res_buf, hc->res_len);
		o += hc->res_len;
		free(hc->res_buf);
		hc->res_buf = NULL;
		hc->res_len = 0;
		hc->res_state = GWP_HTTP_RES_BODY;
		*out_len = o;
		return 0;
	}
}

int gwp_http_fwd_res_input(struct gwp_http_conn *hc, const void *in,
			   size_t len, bool eof, void *out, size_t out_cap,
			   size_t *out_len)
{
	int r;

	*out_len = 0;
	if (hc->res_state != GWP_HTTP_RES_HDR)
		return 0;

	r = res_input(hc, in, len, eof, out, out_cap, out_len);
	if (r < 0) {
		*out_len = 0;
		free(hc->res_buf);
		hc->res_buf = NULL;
		hc->res_len = 0;
		hc->res_state = GWP_HTTP_RES_FAILED;
	}
	return r;
}

int gwp_http_build_connect_reply(const struct gwp_http_conn *hc, void *out,
				 size_t out_cap)
{
	static const char ok[] = "HTTP/1.1 200 OK\r\n\r\n";
	size_t len = sizeof(ok) - 1;

	if (hc->is_forward)
		return 0;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, ok, len);
	return (int)len;
}

int gwp_http_build_auth_required_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 407 Proxy Authentication Required\r\n"
		"Proxy-Authenticate: Basic realm=\"gwproxy\"\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

int gwp_http_build_bad_request_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 400 Bad Request\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

int gwp_http_build_forbidden_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

int gwp_http_build_bad_gateway_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 502 Bad Gateway\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

int gwp_http_build_gateway_timeout_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 504 Gateway Timeout\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

int gwp_http_build_too_large_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 431 Request Header Fields Too Large\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}

/* Base64-encode @in into the NUL-terminated @out (RFC 4648). */
static void base64_encode(const unsigned char *in, size_t inlen, char *out)
{
	static const char t[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, o = 0;

	for (i = 0; i + 2 < inlen; i += 3) {
		out[o++] = t[in[i] >> 2];
		out[o++] = t[((in[i] & 0x3) << 4) | (in[i + 1] >> 4)];
		out[o++] = t[((in[i + 1] & 0xf) << 2) | (in[i + 2] >> 6)];
		out[o++] = t[in[i + 2] & 0x3f];
	}
	if (i < inlen) {
		out[o++] = t[in[i] >> 2];
		if (i + 1 < inlen) {
			out[o++] = t[((in[i] & 0x3) << 4) | (in[i + 1] >> 4)];
			out[o++] = t[(in[i + 1] & 0xf) << 2];
		} else {
			out[o++] = t[(in[i] & 0x3) << 4];
			out[o++] = '=';
		}
		out[o++] = '=';
	}
	out[o] = '\0';
}

/*
 * Build an upstream "CONNECT @authority HTTP/1.1" request into @out, optionally
 * with a Basic Proxy-Authorization header. @authority is a "host:port" (or
 * "[ipv6]:port") string. On success *out_len holds the byte count; -ENOBUFS if
 * @out_cap is too small.
 */
int gwp_http_cli_build_connect(const char *authority, const char *user,
			       uint8_t ulen, const char *pass, uint8_t plen,
			       void *out, size_t out_cap, size_t *out_len)
{
	char auth_hdr[8 + ((255 + 1 + 255 + 2) / 3) * 4 + 4] = "";
	int n;

	if (user && ulen) {
		unsigned char raw[255 + 1 + 255];
		char b64[((sizeof(raw)) / 3 + 1) * 4 + 4];
		size_t rl = 0;

		memcpy(raw, user, ulen);
		rl = ulen;
		raw[rl++] = ':';
		if (pass && plen) {
			memcpy(raw + rl, pass, plen);
			rl += plen;
		}
		base64_encode(raw, rl, b64);
		n = snprintf(auth_hdr, sizeof(auth_hdr),
			     "Proxy-Authorization: Basic %s\r\n", b64);
		if (n < 0 || (size_t)n >= sizeof(auth_hdr))
			return -EINVAL;
	}

	n = snprintf(out, out_cap,
		     "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",
		     authority, authority, auth_hdr);
	if (n < 0)
		return -EINVAL;
	if ((size_t)n >= out_cap)
		return -ENOBUFS;

	*out_len = (size_t)n;
	return 0;
}

/*
 * Parse an upstream HTTP CONNECT reply. Returns -EAGAIN until the status line
 * and header terminator ("\r\n\r\n") have both arrived. On completion it sets
 * *status to the HTTP status code and *consumed to the number of bytes up to and
 * including the blank line (any bytes after that are early tunnel data), and
 * returns 0. Returns -EINVAL on a malformed status line.
 */
int gwp_http_cli_parse_connect_reply(const void *buf, size_t len, int *status,
				     size_t *consumed)
{
	const char *p = buf, *end;
	int code;

	/* Need the full header block. */
	end = memmem(p, len, "\r\n\r\n", 4);
	if (!end)
		return -EAGAIN;

	/* Status line: "HTTP/1.x SSS ...". */
	if (len < 12 || memcmp(p, "HTTP/1.", 7))
		return -EINVAL;
	if (p[8] != ' ')
		return -EINVAL;
	if (p[9] < '0' || p[9] > '9' || p[10] < '0' || p[10] > '9' ||
	    p[11] < '0' || p[11] > '9')
		return -EINVAL;

	code = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
	*status = code;
	*consumed = (size_t)(end - p) + 4;
	return 0;
}
