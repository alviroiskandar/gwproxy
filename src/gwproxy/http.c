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

struct gwp_http_conn *gwp_http_conn_alloc(void)
{
	struct gwp_http_conn *hc = calloc(1, sizeof(*hc));

	if (!hc)
		return NULL;

	if (gwnet_http_hdr_pctx_init(&hc->ctx_hdr) < 0) {
		free(hc);
		return NULL;
	}

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
static bool is_hop_by_hop(const char *k)
{
	static const char *const hbh[] = {
		"Connection", "Proxy-Connection", "Keep-Alive", "TE",
		"Trailer", "Upgrade", "Proxy-Authorization",
		"Proxy-Authenticate",
	};
	size_t i;

	for (i = 0; i < sizeof(hbh) / sizeof(hbh[0]); i++) {
		if (!strcasecmp(k, hbh[i]))
			return true;
	}
	return false;
}

/*
 * Whether @name appears as one of the comma-separated connection-options in a
 * Connection header value @conn (which may be NULL). Such fields are
 * connection-specific and must also be dropped (RFC 9110 Section 7.6.1).
 */
static bool conn_listsl(const char *conn, const char *name, size_t nlen)
{
	const char *p = conn;

	if (!conn)
		return false;

	while (*p) {
		const char *e;
		size_t tlen;

		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;
		for (e = p; *e && *e != ','; e++)
			;
		tlen = (size_t)(e - p);
		while (tlen > 0 && (p[tlen - 1] == ' ' || p[tlen - 1] == '\t'))
			tlen--;
		if (tlen == nlen && !strncasecmp(p, name, nlen))
			return true;
		p = e;
	}
	return false;
}

static bool conn_lists(const char *conn, const char *name)
{
	return conn_listsl(conn, name, strlen(name));
}

/*
 * Rebuild the request in origin-form into hc->fwd_req: the absolute-form
 * request-target is replaced by @path, hop-by-hop / connection-specific
 * headers are dropped and "Connection: close" is appended (this proxy handles
 * one request per connection). @hdr_len is the length of the parsed request
 * header, used to size the scratch buffer (the rewrite is never materially
 * larger). Returns 0 or a negative error.
 */
/*
 * Build the origin-form request forwarded upstream. @authority is the URI's
 * authority, passed as pointer+length because at this point it is still part
 * of the request line and not NUL-terminated.
 */
static int build_forward_request(struct gwp_http_conn *hc, const char *path,
				 const char *authority, size_t auth_len,
				 size_t hdr_len)
{
	struct gwnet_http_req_hdr *req = &hc->req_hdr;
	const char *method = http_method_str(req->method);
	const char *ver = (req->version == GWNET_HTTP_VER_1_0) ? "1.0" : "1.1";
	const char *conn = gwnet_http_hdr_fields_get(&req->fields, "Connection");
	size_t cap = hdr_len * 2 + 64, n = 0, i;
	char *buf;
	int w;

	if (!method)
		return -EINVAL;

	/*
	 * Fields the Connection header names are dropped below, as RFC 9110
	 * Section 7.6.1 asks. That must never take the framing fields with
	 * them: the body follows the header unchanged, so an origin that no
	 * longer sees Content-Length or Transfer-Encoding reads the body as
	 * the next request -- a client-chosen request line and Host smuggled
	 * past the rewrite above. Host is replaced anyway, and listing it is
	 * just as meaningless. Nothing legitimate does this; refuse it.
	 */
	if (conn_lists(conn, "Content-Length") ||
	    conn_lists(conn, "Transfer-Encoding") ||
	    conn_lists(conn, "Host"))
		return -EBADMSG;

	buf = malloc(cap);
	if (!buf)
		return -ENOMEM;

	w = snprintf(buf, cap, "%s %s HTTP/%s\r\n", method, path, ver);
	if (w < 0 || (size_t)w >= cap)
		goto too_big;
	n = (size_t)w;

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

		w = snprintf(buf + n, cap - n, "Host: %.*s\r\n", (int)hlen,
			     host);
		if (w < 0 || (size_t)w >= cap - n)
			goto too_big;
		n += (size_t)w;
	}

	for (i = 0; i < req->fields.nr; i++) {
		const char *k = req->fields.ff[i].key;
		const char *v = req->fields.ff[i].val;

		/* Drop hop-by-hop and Connection-listed headers, and the
		 * client's Host -- ours is already in place above. */
		if (is_hop_by_hop(k) || conn_lists(conn, k) ||
		    !strcasecmp(k, "Host"))
			continue;

		w = snprintf(buf + n, cap - n, "%s: %s\r\n", k, v);
		if (w < 0 || (size_t)w >= cap - n)
			goto too_big;
		n += (size_t)w;
	}

	w = snprintf(buf + n, cap - n, "Connection: close\r\n\r\n");
	if (w < 0 || (size_t)w >= cap - n)
		goto too_big;
	n += (size_t)w;

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
	size_t hdr_len;
	int r;

	hc->ctx_hdr.buf = in;
	hc->ctx_hdr.len = *in_len;
	hc->ctx_hdr.off = 0;
	r = gwnet_http_req_hdr_parse(&hc->ctx_hdr, req);
	*in_len = hc->ctx_hdr.off;
	hc->hdr_len += hc->ctx_hdr.off;
	if (r == -EAGAIN)
		return GWP_HTTP_NEED_MORE;
	/*
	 * A repeated field that may appear only once (Host, Content-Length,
	 * ...) is a well-formed line in an unacceptable request; say so
	 * rather than drop the connection without a word.
	 */
	if (r == -EEXIST)
		return GWP_HTTP_BAD_REQUEST;
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
	static const char *const hbh[] = {
		"Connection", "Proxy-Connection", "Keep-Alive", "Upgrade",
		"TE", "Proxy-Authenticate", "Proxy-Authentication-Info",
	};
	size_t i;

	for (i = 0; i < sizeof(hbh) / sizeof(hbh[0]); i++) {
		if (strlen(hbh[i]) == klen && !strncasecmp(k, hbh[i], klen))
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
 * Return the length of the line at @p (at most @len bytes, which always
 * include its LF) excluding the line terminator, which is LF or CRLF.
 */
static size_t line_len(const char *p, size_t len)
{
	const char *lf = memchr(p, '\n', len);
	size_t n = (size_t)(lf - p);

	if (n && p[n - 1] == '\r')
		n--;
	return n;
}

/* The line after the one at @p; the header ending at @end has one. */
static const char *next_line(const char *p, const char *end)
{
	return (const char *)memchr(p, '\n', (size_t)(end - p)) + 1;
}

/*
 * Rewrite one complete response header (@len bytes, ending with its blank
 * line) into @out: lines are normalised to CRLF, hop-by-hop fields and fields
 * named by Connection are dropped and, for a final response, the client is
 * told that the connection closes after it. *@code is set to the status code.
 *
 * Returns the length written, -EBADMSG for a header that is not valid
 * HTTP/1.x, or -E2BIG if @out is too small.
 */
static ssize_t rewrite_res_hdr(const char *hdr, size_t len, char *out,
			       size_t out_cap, int *code)
{
	static const char cls[] = "Connection: close\r\n"
				  "Proxy-Connection: close\r\n";
	const char *p = hdr, *end = hdr + len, *q;
	char *conn = NULL;
	size_t n, o = 0, conn_len = 0, i;
	ssize_t ret = -EBADMSG;

	/* Status line: HTTP/1.x SP 3DIGIT [ SP reason-phrase ] */
	n = line_len(p, (size_t)(end - p));
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
	p = next_line(p, end);

	/*
	 * Validate the field lines and gather every Connection value into one
	 * list first: a field may be named by a Connection line that comes
	 * after it.
	 */
	conn = malloc(len + 1);
	if (!conn)
		return -ENOMEM;
	for (q = p; ; ) {
		const char *colon, *v;

		n = line_len(q, (size_t)(end - q));
		if (!n)
			break;
		/* obs-fold (RFC 9112 Section 5.2) is refused, not unfolded. */
		colon = memchr(q, ':', n);
		if (!colon || colon == q)
			goto out;
		for (v = q; v < colon; v++) {
			if (!is_tchar(*v))
				goto out;
		}
		for (v = colon + 1; v < q + n; v++) {
			if (!is_field_char(*v))
				goto out;
		}
		if (colon - q == 10 && !strncasecmp(q, "Connection", 10)) {
			conn[conn_len++] = ',';
			memcpy(conn + conn_len, colon + 1, n - 11);
			conn_len += n - 11;
		}
		q = next_line(q, end);
	}
	conn[conn_len] = '\0';

	for (;;) {
		const char *colon;
		size_t klen;

		n = line_len(p, (size_t)(end - p));
		if (!n)
			break;
		colon = memchr(p, ':', n);
		klen = (size_t)(colon - p);
		if (!is_res_hop_by_hop(p, klen) &&
		    (is_framing_field(p, klen) || !conn_listsl(conn, p, klen))) {
			if (o + n + 2 > out_cap) {
				ret = -E2BIG;
				goto out;
			}
			memcpy(out + o, p, n);
			memcpy(out + o + n, "\r\n", 2);
			o += n + 2;
		}
		p = next_line(p, end);
	}

	/* An interim response says nothing about the connection. */
	n = (*code >= 200) ? sizeof(cls) - 1 : 0;
	if (o + n + 2 > out_cap) {
		ret = -E2BIG;
		goto out;
	}
	memcpy(out + o, cls, n);
	memcpy(out + o + n, "\r\n", 2);
	ret = (ssize_t)(o + n + 2);
out:
	free(conn);
	return ret;
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
	free(hc->res_buf);
	hc->res_buf = malloc(max_hdr);
	if (!hc->res_buf)
		return -ENOMEM;
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

static int res_input(struct gwp_http_conn *hc, const void *in, size_t len,
		     bool eof, char *out, size_t out_cap, size_t *out_len)
{
	size_t o = 0, end;
	ssize_t w;
	int code;

	if (len > hc->res_cap - hc->res_len)
		return -E2BIG;
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
