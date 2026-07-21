#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdint.h>

#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>

/*
 * Upstream proxy chaining: the SOCKS5/HTTP CONNECT handshake this proxy speaks
 * to an upstream proxy is the same logic in both event loops; only the send and
 * recv primitives differ. This file holds the transport-agnostic half so it
 * lives once. It references no io_uring symbols and is compiled into every
 * build (part of the base GWPROXY_CC_SOURCES).
 */

int gwp_upstream_splice_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      size_t consumed)
{
	uint8_t rbuf[512];
	size_t rlen = 0;
	int r;

	/* Build the downstream reply for the client (before any early data). */
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		rlen = sizeof(rbuf);
		r = gwp_socks5_build_connect_reply(w, gcp, 0, rbuf, &rlen);
		if (unlikely(r))
			return r;
	} else if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		r = gwp_http_build_connect_reply(gcp->http_conn, rbuf,
						 sizeof(rbuf));
		if (unlikely(r < 0))
			return r;
		rlen = (size_t)r;
	}

	/* Drop the proxy's CONNECT reply, keep any early destination data. */
	gwp_conn_buf_advance(&gcp->target, consumed);

	if (rlen) {
		if (gcp->target.len + rlen > gcp->target.cap)
			return -ENOBUFS;
		memmove(gcp->target.buf + rlen, gcp->target.buf,
			gcp->target.len);
		memcpy(gcp->target.buf, rbuf, rlen);
		gcp->target.len += rlen;
	}
	return 0;
}
