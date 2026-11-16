// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Whose fault a failed upstream proxy handshake is. A failure says either
 * that the upstream proxy itself is unusable (it cannot be reached, refuses
 * our credentials, answers garbage or nothing), that the destination behind
 * it is (the upstream reached out and was refused), or nothing certain about
 * either (a policy refusal, a generic error). Only the first kind should count
 * against the upstream's health.
 *
 * Also how an upstream URL is written: its schemes (gwp_upstream_scheme()),
 * its credentials (gwp_upstream_split_creds()) and how it names its host, for
 * TLS (gwp_upstream_url_host()). The --upstream-proxy parser and the ACL's
 * check of a pool server's URL share these, so they take the same URLs.
 *
 * Self-contained (libc only) so it can be unit-tested alone.
 */
#ifndef GWP_UPSTREAM_H
#define GWP_UPSTREAM_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * target.buf holds the handshake with an upstream proxy. The longest request
 * is an HTTP CONNECT: twice an authority of up to 261 bytes, Basic credentials
 * of 684 and the fixed text take 1264 bytes.
 */
#define GWP_UPSTREAM_MIN_TARGET_BUF	1280

/*
 * The longest reply a client can be owed once the tunnel is up: SOCKS5 with an
 * IPv6 bound address. An HTTP client's is 19 bytes. While the upstream's reply
 * to a CONNECT is awaited, target.cap holds this much back for it.
 */
#define GWP_UPSTREAM_CLIENT_REPLY_MAX	22

/*
 * The longest reply a SOCKS5 upstream can send to a CONNECT: VER, REP, RSV,
 * ATYP, a domain BND.ADDR of a length byte and up to 255 bytes, and BND.PORT.
 */
#define GWP_UPSTREAM_S5_REPLY_MAX	(4 + 1 + 255 + 2)

/*
 * The SOCKS5 reply parser does not check for a full buffer: with the smallest
 * target buffer allowed, the room left while that reply is awaited must hold
 * the longest one, or a worker could wait for bytes it has no room to read.
 */
_Static_assert(GWP_UPSTREAM_MIN_TARGET_BUF - GWP_UPSTREAM_CLIENT_REPLY_MAX >=
	       GWP_UPSTREAM_S5_REPLY_MAX,
	       "the smallest target buffer must hold the longest SOCKS5 reply");

enum gwp_upstream_fail_class {
	GWP_UPSTREAM_FAIL_NEUTRAL	= 0,	/* not counted */
	GWP_UPSTREAM_FAIL_UPSTREAM	= 1,	/* the upstream's fault */
	GWP_UPSTREAM_FAIL_DESTINATION	= 2,	/* the destination's fault */
};

/*
 * How an upstream handshake ended, and what @val in
 * gwp_upstream_fail_classify() then holds.
 */
enum gwp_upstream_end {
	GWP_UPSTREAM_END_CONNECT,	/* TCP connect failed; errno, any sign */
	GWP_UPSTREAM_END_TLS,		/* TLS failed before the reply */
	GWP_UPSTREAM_END_S5_METHOD,	/* SOCKS5 method we cannot use */
	GWP_UPSTREAM_END_S5_AUTH,	/* SOCKS5 user/password status */
	GWP_UPSTREAM_END_S5_REP,	/* SOCKS5 CONNECT REP */
	GWP_UPSTREAM_END_HTTP,		/* HTTP CONNECT status code */
	GWP_UPSTREAM_END_MALFORMED,	/* reply does not parse */
	GWP_UPSTREAM_END_HUP,		/* upstream hung up; errno, or 0 */
	/*
	 * Out of time; 0 while the upstream still owed us its part before
	 * our CONNECT request (the TCP connect, the TLS handshake, the
	 * SOCKS5 method and auth), else (waiting for the CONNECT's reply,
	 * which the destination may hold up) not the upstream's fault.
	 */
	GWP_UPSTREAM_END_TIMEOUT,
};

/* How an upstream handshake ended, for a log line. */
static inline const char *gwp_upstream_end_str(enum gwp_upstream_end end)
{
	switch (end) {
	case GWP_UPSTREAM_END_CONNECT:
		return "connect";
	case GWP_UPSTREAM_END_TLS:
		return "tls";
	case GWP_UPSTREAM_END_S5_METHOD:
		return "socks5-method";
	case GWP_UPSTREAM_END_S5_AUTH:
		return "socks5-auth";
	case GWP_UPSTREAM_END_S5_REP:
		return "socks5-rep";
	case GWP_UPSTREAM_END_HTTP:
		return "http-status";
	case GWP_UPSTREAM_END_MALFORMED:
		return "malformed";
	case GWP_UPSTREAM_END_HUP:
		return "hangup";
	case GWP_UPSTREAM_END_TIMEOUT:
	default:
		return "timeout";
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_s5_rep_class(int rep)
{
	switch (rep) {
	case 0x00:	/* succeeded */
	case 0x01:	/* general failure: could be either side */
	case 0x02:	/* not allowed by ruleset: policy */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	case 0x03:	/* network unreachable */
	case 0x04:	/* host unreachable */
	case 0x05:	/* connection refused */
	case 0x06:	/* TTL expired */
		return GWP_UPSTREAM_FAIL_DESTINATION;
	case 0x07:	/* command not supported */
	case 0x08:	/* address type not supported */
	default:	/* unassigned: not a reply we can trust */
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_http_class(int status)
{
	if (status < 100 || status > 599)
		return GWP_UPSTREAM_FAIL_UPSTREAM;	/* not a status code */
	switch (status) {
	case 407:	/* proxy authentication required */
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	case 502:	/* bad gateway */
	case 504:	/* gateway timeout */
		return GWP_UPSTREAM_FAIL_DESTINATION;
	default:	/* 2xx success; 403, 500, 503 and the rest: unclear */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_connect_class(int err)
{
	switch (err < 0 ? -err : err) {
	case ECONNREFUSED:
	case ETIMEDOUT:
	case ECONNRESET:
	case ECONNABORTED:
	case EPIPE:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EHOSTDOWN:
	case ENETDOWN:
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	default:	/* local trouble: no memory, no fds, no ports, ... */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	}
}

/*
 * Classify how an upstream handshake ended (@end, with @val as documented
 * on enum gwp_upstream_end). Pure: no state, no I/O. An outcome that is not
 * a failure (SOCKS5 status or REP 0x00, an HTTP 2xx) is NEUTRAL.
 */
static inline enum gwp_upstream_fail_class
gwp_upstream_fail_classify(enum gwp_upstream_end end, int val)
{
	switch (end) {
	case GWP_UPSTREAM_END_CONNECT:
		return gwp_upstream_connect_class(val);
	case GWP_UPSTREAM_END_S5_AUTH:
		return val ? GWP_UPSTREAM_FAIL_UPSTREAM :
			     GWP_UPSTREAM_FAIL_NEUTRAL;
	case GWP_UPSTREAM_END_S5_REP:
		return gwp_upstream_s5_rep_class(val);
	case GWP_UPSTREAM_END_HTTP:
		return gwp_upstream_http_class(val);
	case GWP_UPSTREAM_END_TIMEOUT:
		/* A destination that never answers holds the CONNECT up. */
		return val ? GWP_UPSTREAM_FAIL_NEUTRAL :
			     GWP_UPSTREAM_FAIL_UPSTREAM;
	case GWP_UPSTREAM_END_TLS:
	case GWP_UPSTREAM_END_S5_METHOD:
	case GWP_UPSTREAM_END_MALFORMED:
	case GWP_UPSTREAM_END_HUP:
	default:
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	}
}

static inline const char *
gwp_upstream_fail_class_str(enum gwp_upstream_fail_class c)
{
	switch (c) {
	case GWP_UPSTREAM_FAIL_UPSTREAM:
		return "upstream";
	case GWP_UPSTREAM_FAIL_DESTINATION:
		return "destination";
	case GWP_UPSTREAM_FAIL_NEUTRAL:
	default:
		return "neutral";
	}
}

enum {
	GWP_UPSTREAM_SOCKS5	= 0,
	GWP_UPSTREAM_HTTP	= 1,
};

/* What an upstream URL's scheme says about the proxy it names. */
struct gwp_upstream_scheme {
	const char	*prefix;	/* "socks5://" and so on */
	uint8_t		len;		/* strlen(@prefix) */
	uint8_t		type;		/* GWP_UPSTREAM_SOCKS5 / HTTP */
	bool		remote_dns;	/* the proxy resolves the target */
	bool		use_tls;	/* TLS to the proxy */
	uint16_t	def_port;	/* when the URL names none */
};

/*
 * The longest user name and password an upstream URL or auth file may give:
 * SOCKS5 user/password authentication (RFC 1929) has a length byte for each.
 */
#define GWP_UPSTREAM_CRED_MAX	255

/* The room for what follows an upstream URL's scheme, NUL included. */
#define GWP_UPSTREAM_REST_MAX	512

/*
 * The scheme @url starts with, and *@rest set to what follows it; NULL when
 * it is none of socks5://, socks5h://, http:// and https://.
 */
static inline const struct gwp_upstream_scheme *
gwp_upstream_scheme(const char *url, const char **rest)
{
	static const struct gwp_upstream_scheme schemes[] = {
		{ "socks5h://",	10, GWP_UPSTREAM_SOCKS5, true,  false, 1080 },
		{ "socks5://",	9,  GWP_UPSTREAM_SOCKS5, false, false, 1080 },
		/* The HTTP proxy resolves the CONNECT host. */
		{ "https://",	8,  GWP_UPSTREAM_HTTP,   true,  true,  8080 },
		{ "http://",	7,  GWP_UPSTREAM_HTTP,   true,  false, 8080 },
	};
	size_t i;

	for (i = 0; i < sizeof(schemes) / sizeof(schemes[0]); i++) {
		if (!strncmp(url, schemes[i].prefix, schemes[i].len)) {
			*rest = url + schemes[i].len;
			return &schemes[i];
		}
	}
	return NULL;
}

/*
 * Find the credentials in @rest, an upstream URL after its scheme: the
 * "user[:pass]" before its last '@', the password after the first ':' in it.
 * Returns false when there is no '@'; otherwise sets *@at to the '@', and
 * *@ul and *@pl to the lengths of the user name at @rest and of the password
 * at @rest + *@ul + 1 (0 when there is none). Nothing is checked or copied.
 */
static inline bool gwp_upstream_split_creds(const char *rest, const char **at,
					    size_t *ul, size_t *pl)
{
	const char *colon;

	*at = strrchr(rest, '@');
	if (!*at)
		return false;
	colon = memchr(rest, ':', (size_t)(*at - rest));
	*ul = colon ? (size_t)(colon - rest) : (size_t)(*at - rest);
	*pl = colon ? (size_t)(*at - colon - 1) : 0;
	return true;
}

/*
 * The host of an upstream URL's "host[:port]" or "[v6addr]:port", without the
 * port and the brackets: the name a TLS upstream's certificate must carry.
 * Copies it to @out (@size bytes, NUL included) and sets *@is_ip when it is an
 * IPv4 or IPv6 address literal, which is checked against the certificate's IP
 * addresses and never sent as SNI, rather than a DNS name. Returns 0, or
 * -EINVAL when the host is empty or does not fit.
 */
static inline int gwp_upstream_url_host(const char *hostport, char *out,
					size_t size, bool *is_ip)
{
	unsigned char addr[16];
	const char *end;
	size_t n;

	if (hostport[0] == '[') {
		end = strchr(++hostport, ']');
		if (!end)
			return -EINVAL;
	} else {
		end = strchr(hostport, ':');
		if (!end)
			end = hostport + strlen(hostport);
	}

	n = (size_t)(end - hostport);
	if (!n || n >= size)
		return -EINVAL;
	memcpy(out, hostport, n);
	out[n] = '\0';
	*is_ip = inet_pton(AF_INET, out, addr) == 1 ||
		 inet_pton(AF_INET6, out, addr) == 1;
	return 0;
}

#endif /* GWP_UPSTREAM_H */
