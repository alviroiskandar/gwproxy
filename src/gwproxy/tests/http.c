// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unit tests for the HTTP proxy module (src/gwproxy/http.c).
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/http.h>
#include <gwproxy/auth.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#define PRTEST_OK()					\
do {							\
	static int __printed;				\
	if (!__printed) {				\
		printf("Test passed: %s\n", __func__);	\
		__printed = 1;				\
	}						\
} while (0)

/*
 * Create a unique temporary file from @tmpl (an mkstemp(3) template, rewritten
 * in place) and write @len bytes of @data to it. See tests/socks5.c for why
 * mkstemp() is used rather than a fixed path. The caller unlink()s @tmpl.
 */
static ssize_t write_temp_file(char *tmpl, const void *data, size_t len)
{
	ssize_t w;
	int fd;

	fd = mkstemp(tmpl);
	if (fd < 0)
		return -1;

	w = write(fd, data, len);
	close(fd);
	return w;
}

/* Run gwp_http_conn_process() on a full request buffer in one shot. */
static int run(struct gwp_http_conn *hc, struct gwp_auth *auth, const char *buf,
	       char **host, char **port, const char **req, size_t *req_len)
{
	size_t in_len = strlen(buf);
	int r = gwp_http_conn_process(hc, auth, buf, &in_len, host, port, req,
				      req_len);

	/* On a complete request the whole buffer is consumed. */
	if (r != GWP_HTTP_NEED_MORE && r != GWP_HTTP_ERR)
		assert(in_len == strlen(buf));
	return r;
}

static void test_connect_ipv4(void)
{
	static const char buf[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Host: example.com:443\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	uint8_t out[64];
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!gwp_http_conn_is_forward(hc));
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "443"));

	/* A CONNECT tunnel replies "200 OK" once connected. */
	r = gwp_http_build_connect_reply(hc, out, sizeof(out));
	assert(r == 19);
	assert(!memcmp(out, "HTTP/1.1 200 OK\r\n\r\n", 19));

	/* Too-small output buffer is rejected. */
	assert(gwp_http_build_connect_reply(hc, out, 5) == -ENOBUFS);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_connect_ipv6(void)
{
	static const char buf[] =
		"CONNECT [::1]:8080 HTTP/1.1\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "::1"));		/* brackets unwrapped */
	assert(!strcmp(port, "8080"));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_get(void)
{
	static const char buf[] =
		"GET http://example.com:8080/a/b?q=1 HTTP/1.1\r\n"
		"Host: example.com:8080\r\n"
		"User-Agent: gwtest\r\n"
		"Proxy-Connection: keep-alive\r\n"
		"Proxy-Authorization: Basic Zm9v\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	uint8_t out[64];
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(gwp_http_conn_is_forward(hc));
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "8080"));

	/* The rewritten request is origin-form and NUL-friendly for strstr. */
	assert(req && req_len == strlen(req));
	assert(!strncmp(req, "GET /a/b?q=1 HTTP/1.1\r\n", 22));
	assert(strstr(req, "Host: example.com:8080\r\n"));
	assert(strstr(req, "User-Agent: gwtest\r\n"));
	/* Hop-by-hop / proxy-only headers are dropped. */
	assert(!strstr(req, "Proxy-Connection"));
	assert(!strstr(req, "Proxy-Authorization"));
	/* Exactly one Connection header, "close", and it ends the header. */
	assert(strstr(req, "\r\nConnection: close\r\n\r\n"));

	/* A forwarding request has no client reply once connected. */
	r = gwp_http_build_connect_reply(hc, out, sizeof(out));
	assert(r == 0);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_default_port(void)
{
	static const char buf[] =
		"GET http://example.com HTTP/1.1\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "80"));		/* default when absent */
	/* An empty URI path becomes "/". */
	assert(!strncmp(req, "GET / HTTP/1.1\r\n", 16));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_hop_by_hop(void)
{
	/*
	 * Every hop-by-hop / connection-specific request header must be dropped
	 * from the forwarded request, including a field named by the Connection
	 * header (X-Custom). Expect (100-continue must be forwarded), the body-
	 * framing headers and end-to-end Authorization must be kept.
	 */
	static const char buf[] =
		"POST http://example.com/x HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Authorization: Bearer tok\r\n"
		"Expect: 100-continue\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Keep-Alive: timeout=5\r\n"
		"TE: trailers\r\n"
		"Trailer: X-Trace\r\n"
		"Upgrade: h2c\r\n"
		"X-Keep: keep-me\r\n"
		"X-Custom: drop-me\r\n"
		"Connection: keep-alive, X-Custom\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(!strncmp(req, "POST /x HTTP/1.1\r\n", 17));

	/* Kept. */
	assert(strstr(req, "Host: example.com\r\n"));
	assert(strstr(req, "Authorization: Bearer tok\r\n"));
	assert(strstr(req, "Expect: 100-continue\r\n"));
	assert(strstr(req, "Transfer-Encoding: chunked\r\n"));
	assert(strstr(req, "X-Keep: keep-me\r\n"));

	/* Dropped (hop-by-hop). */
	assert(!strstr(req, "Keep-Alive"));
	assert(!strstr(req, "\r\nTE:"));
	assert(!strstr(req, "Trailer:"));
	assert(!strstr(req, "Upgrade"));
	/* Dropped (named by Connection). */
	assert(!strstr(req, "X-Custom"));
	/* The original Connection header is replaced by exactly "close". */
	assert(!strstr(req, "keep-alive"));
	assert(strstr(req, "\r\nConnection: close\r\n\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_conn_lists_framing(void)
{
	/*
	 * A Connection header naming a framing field (or Host) would make the
	 * rewrite drop it while the body is still relayed, so the origin would
	 * read the body as a second request. Such a request is refused with
	 * 400 rather than rewritten.
	 */
	static const char *const bad[] = {
		("POST http://example.com/a HTTP/1.1\r\n"
		 "Connection: Content-Length\r\n"
		 "Content-Length: 4\r\n\r\n"),
		("POST http://example.com/a HTTP/1.1\r\n"
		 "Connection: keep-alive, transfer-encoding\r\n"
		 "Transfer-Encoding: chunked\r\n\r\n"),
		("GET http://example.com/a HTTP/1.1\r\n"
		 "Connection: Host\r\n\r\n"),
	};
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, i;
	uint8_t out[128];
	int r;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		hc = gwp_http_conn_alloc();
		assert(hc);
		r = run(hc, NULL, bad[i], &host, &port, &req, &req_len);
		assert(r == GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}

	r = gwp_http_build_bad_request_reply(out, sizeof(out));
	assert(r > 0 && !strncmp((char *)out, "HTTP/1.1 400 ", 13));
	assert(gwp_http_build_bad_request_reply(out, 5) == -ENOBUFS);
	PRTEST_OK();
}

/*
 * Classify @hdr as a forwarding request, then pass @body through the request
 * body filter @step bytes at a time. Returns the filter's first error, or 0
 * with *@fwd set to how many body bytes it let through.
 */
static int req_body(const char *hdr, const char *body, size_t step,
		    size_t *fwd)
{
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t len = strlen(body), i, n, f;
	char *host, *port;
	const char *req;
	size_t req_len;
	bool held = false;
	int r = 0;

	assert(hc);
	assert(run(hc, NULL, hdr, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	*fwd = 0;
	for (i = 0; i < len; i += n) {
		n = (len - i < step) ? len - i : step;
		r = gwp_http_fwd_req_body(hc, body + i, n, &f);
		if (r)
			break;
		/* Once something is held back, nothing more gets through. */
		assert(!held || !f);
		held = f < n;
		*fwd += f;
	}
	gwp_http_conn_free(hc);
	return r;
}

/*
 * The forwarded request drops what Connection names, checked against the
 * options split once; more than 32 distinct options is refused with 400.
 */
static void test_forward_conn_limit(void)
{
	static char buf[4096];
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, n;
	int i;

	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\n"
			    "X-0: a\r\nConnection: ");
	for (i = 0; i < 32; i++)
		n += (size_t)sprintf(buf + n, "x-%d, X-%d,", i, i);
	n += (size_t)sprintf(buf + n, "\r\nX-31: b\r\nX-32: c\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	{
		static const char want[] =
			"GET / HTTP/1.1\r\nHost: example.com\r\n"
			"X-32: c\r\nConnection: close\r\n\r\n";

		assert(req_len == strlen(want) && !memcmp(req, want, req_len));
	}
	gwp_http_conn_free(hc);

	sprintf(buf + n - 2, "Connection: X-32\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_BAD_REQUEST);
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_req_framing(void)
{
	static const char next[] = "GET http://other/ HTTP/1.1\r\n\r\n";
	static const char chunked[] =
		"5\r\nhello\r\n"
		"1A;ext=\"v\"\r\nabcdefghijklmnopqrstuvwxyz\r\n"
		"0003 ;x\r\nabc\r\n"
		"0\r\nX-Trailer: t\r\nX-T: v\r\n\r\n";
	static const char *const bad_hdr[] = {
		"POST http://h/ HTTP/1.1\r\nContent-Length: 1\r\n"
		"Transfer-Encoding: chunked\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
		"POST http://h/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nContent-Length: 1x\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\n"
		"Content-Length: 99999999999999999999\r\n\r\n",
	};
	static const char *const bad_chunked[] = {
		"5\nhello\r\n0\r\n\r\n",	/* bare LF */
		"5\r\nhelloX\r\n0\r\n\r\n",	/* data longer than its size */
		"g\r\n",
		"\r\n",
		"11111111111111111\r\n",	/* more than 64 bits */
		"0\r\nX: a\nb\r\n\r\n",
		/* A request smuggled in as "trailers". */
		"0\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
		"0\r\nX\r\n\r\n",		/* no colon */
		"0\r\nX : v\r\n\r\n",	/* space before colon */
		"80000000\r\n",		/* chunk of 2 GiB */
		"100000005\r\nhello\r\n0\r\n\r\n",
		"5 6\r\nhello\r\n0\r\n\r\n",	/* bare-space extension */
		"5 \r\nhello\r\n0\r\n\r\n",
	};
	char body[256];
	size_t fwd, step, i;
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req;
	size_t req_len;

	for (step = 1; step <= 64; step *= 4) {
		/* Content-Length: exactly that many bytes, the rest dropped. */
		snprintf(body, sizeof(body), "hello%s", next);
		assert(!req_body("POST http://h/ HTTP/1.1\r\n"
				 "Content-Length: 5\r\n\r\n", body, step, &fwd));
		assert(fwd == 5);

		/* No framing: no body; a pipelined request goes nowhere. */
		assert(!req_body("GET http://h/ HTTP/1.1\r\n\r\n", next, step,
				 &fwd));
		assert(fwd == 0);

		/* Chunked, extensions and trailers included. */
		snprintf(body, sizeof(body), "%s%s", chunked, next);
		assert(!req_body("POST http://h/ HTTP/1.1\r\n"
				 "Transfer-Encoding: Chunked\r\n\r\n", body,
				 step, &fwd));
		assert(fwd == strlen(chunked));

		for (i = 0; i < sizeof(bad_chunked) / sizeof(bad_chunked[0]);
		     i++)
			assert(req_body("POST http://h/ HTTP/1.1\r\n"
					"Transfer-Encoding: chunked\r\n\r\n",
					bad_chunked[i], step, &fwd) == -EBADMSG);
	}

	for (i = 0; i < sizeof(bad_hdr) / sizeof(bad_hdr[0]); i++) {
		hc = gwp_http_conn_alloc();
		assert(hc);
		assert(run(hc, NULL, bad_hdr[i], &host, &port, &req,
			   &req_len) == GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}
	PRTEST_OK();
}

/* Feed @in to a fresh response filter in one go; returns its result. */
static int res_feed(struct gwp_http_conn *hc, const char *in, bool eof,
		    char *out, size_t out_cap, size_t *out_len)
{
	assert(!gwp_http_fwd_res_init(hc, 1024));
	return gwp_http_fwd_res_input(hc, in, strlen(in), eof, out, out_cap,
				      out_len);
}

static void test_res_rewrite(void)
{
	/*
	 * The client must learn that the connection closes, whatever the
	 * origin claims, and must not see the origin's hop-by-hop fields. The
	 * framing fields stay even when Connection names them (the body is
	 * relayed as is), and so do duplicates such as Set-Cookie.
	 */
	static const char in[] =
		"HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive, X-Drop, Content-Length\r\n"
		"Keep-Alive: timeout=100\r\n"
		"Proxy-Authenticate: Basic realm=\"evil\"\r\n"
		"X-Drop: 1\r\n"
		"Set-Cookie: a=1\r\n"
		"Set-Cookie: b=2\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"hello";
	static const char want[] =
		"HTTP/1.1 200 OK\r\n"
		"Set-Cookie: a=1\r\n"
		"Set-Cookie: b=2\r\n"
		"Content-Length: 5\r\n"
		"Connection: close\r\n"
		"Proxy-Connection: close\r\n"
		"\r\n"
		"hello";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024];
	size_t out_len, i;

	assert(hc);
	assert(res_feed(hc, in, false, out, sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	assert(out_len == strlen(want) && !memcmp(out, want, out_len));

	/* Same, dribbled in a byte at a time, with LF-only line ends. */
	assert(!gwp_http_fwd_res_init(hc, 1024));
	{
		static const char lf[] =
			"HTTP/1.0 200 OK\nKeep-Alive: x\nA: b\n\nbody";
		static const char lf_want[] =
			"HTTP/1.0 200 OK\r\nA: b\r\n"
			"Connection: close\r\nProxy-Connection: close\r\n\r\n"
			"body";
		size_t o = 0;

		/* Nothing comes out until the blank line is in. */
		for (i = 0; gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_HDR; i++) {
			assert(gwp_http_fwd_res_input(hc, lf + i, 1, false,
						      out, sizeof(out),
						      &out_len) == 0);
			if (i < strlen(lf) - 5)
				assert(!out_len);
		}
		/* From there on the body is the caller's to relay. */
		memcpy(out + out_len, lf + i, strlen(lf) - i);
		o = out_len + strlen(lf) - i;
		assert(o == strlen(lf_want) && !memcmp(out, lf_want, o));
	}

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_res_interim(void)
{
	/* A 100 Continue is passed on at once, without "Connection: close". */
	static const char in[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 20";
	static const char rest[] = "4 No Content\r\n\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024];
	size_t out_len;

	assert(hc);
	assert(res_feed(hc, in, false, out, sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_HDR);
	assert(out_len == 25 && !memcmp(out, "HTTP/1.1 100 Continue\r\n\r\n", 25));
	assert(gwp_http_fwd_res_pending(hc) == 11);

	assert(gwp_http_fwd_res_input(hc, rest, strlen(rest), false, out,
				      sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	assert(strstr(out, "HTTP/1.1 204 No Content\r\nConnection: close\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * The response rewrite checks every field against the Connection options, so
 * both are bounded: at most 256 field lines and 32 distinct options, past
 * which the response is refused (the caller answers 502). Repeated options
 * count once, and the options may come from several Connection lines,
 * before or after the fields they name.
 */
static void test_res_limits(void)
{
	static char in[40000], out[40000];
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t n, out_len;
	int i;

	assert(hc);

	/* 256 field lines: fine. 257: refused. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\n");
	for (i = 0; i < 256; i++)
		n += (size_t)sprintf(in + n, "X-%d: v\r\n", i);
	sprintf(in + n, "\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	sprintf(in + n, "X-x: v\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == -E2BIG);

	/* 32 distinct options over two lines, each repeated: fine. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\nX-0: drop\r\n"
			    "Connection: ");
	for (i = 0; i < 16; i++)
		n += (size_t)sprintf(in + n, "x-%d, X-%d ,", i, i);
	n += (size_t)sprintf(in + n, "\r\nKeep: me\r\nConnection: ");
	for (i = 16; i < 32; i++)
		n += (size_t)sprintf(in + n, ",, X-%d,x-%d", i, i);
	n += (size_t)sprintf(in + n, "\r\nX-31: drop\r\n");
	sprintf(in + n, "\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	{
		static const char want[] =
			"HTTP/1.1 200 OK\r\nKeep: me\r\n"
			"Connection: close\r\nProxy-Connection: close\r\n"
			"\r\n";

		assert(out_len == strlen(want) && !memcmp(out, want, out_len));
	}

	/* A 33rd distinct option: refused. */
	sprintf(in + n, "Connection: X-32\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == -E2BIG);

	/* A long list of one repeated option is one option. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\nConnection: a");
	for (i = 0; i < 5000; i++)
		n += (size_t)sprintf(in + n, ",a");
	sprintf(in + n, "\r\nA: x\r\nB: y\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	assert(out_len == strlen("HTTP/1.1 200 OK\r\nB: y\r\n"
				 "Connection: close\r\n"
				 "Proxy-Connection: close\r\n\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_res_reject(void)
{
	static const char *const bad[] = {
		("HTTP/1.1 407 Proxy Authentication Required\r\n"
		 "Proxy-Authenticate: Basic realm=\"x\"\r\n\r\n"),
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
		"SSH-2.0-OpenSSH\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",	/* bare CR */
		"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n",	/* obs-fold */
		"HTTP/1.1 200 OK\r\nX : a\r\n\r\n",
		"HTTP/1.1 600 OK\r\n\r\n",
	};
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024], big[1100];
	size_t out_len, i;

	assert(hc);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		assert(res_feed(hc, bad[i], false, out, sizeof(out),
				&out_len) < 0);
		assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_FAILED);
		assert(!out_len);
	}
	assert(res_feed(hc, bad[0], false, out, sizeof(out), &out_len) ==
	       -EACCES);

	/* The origin closing before the header is complete. */
	assert(res_feed(hc, "HTTP/1.1 200 OK\r\n", true, out, sizeof(out),
			&out_len) == -EBADMSG);

	/* A header that cannot fit in what the filter may hold back. */
	memset(big, 'a', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	memcpy(big, "HTTP/1.1 200 OK\r\nX: ", 20);
	assert(res_feed(hc, big, false, out, sizeof(out), &out_len) == -E2BIG);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_need_more(void)
{
	/* Request line complete, header fields not yet terminated. */
	static const char part1[] = "CONNECT example.com:443 HTTP/1.1\r\n";
	static const char part2[] = "\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, in_len;
	int r;

	assert(hc);
	in_len = strlen(part1);
	r = gwp_http_conn_process(hc, NULL, part1, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_NEED_MORE);
	assert(in_len == strlen(part1));	/* request line consumed */

	/* Feeding the terminating blank line completes the request. */
	in_len = strlen(part2);
	r = gwp_http_conn_process(hc, NULL, part2, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "443"));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_errors(void)
{
	static const char https[] =	/* unsupported scheme (no TLS) */
		"GET https://example.com/ HTTP/1.1\r\n\r\n";
	static const char bare[] =	/* neither origin- nor absolute-form */
		"GET foo HTTP/1.1\r\n\r\n";
	static const char badmethod[] =
		"WAT http://example.com/ HTTP/1.1\r\n\r\n";
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, https, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, bare, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, badmethod, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	PRTEST_OK();
}

/*
 * A field that may appear only once, sent twice, is answered with 400 rather
 * than a silent close; repeated list fields are still merged.
 */
static void test_duplicate_field(void)
{
	static const char *const dups[] = {
		"GET http://example.com/ HTTP/1.1\r\n"
		"Host: example.com\r\nHost: evil.example\r\n\r\n",
		"POST http://example.com/ HTTP/1.1\r\n"
		"Content-Length: 1\r\nContent-Length: 2\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic a\r\n"
		"proxy-authorization: Basic b\r\n\r\n",
	};
	static const char list[] =
		"GET http://example.com/ HTTP/1.1\r\n"
		"Accept: a\r\nAccept: b\r\n\r\n";
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, i;

	for (i = 0; i < sizeof(dups) / sizeof(dups[0]); i++) {
		size_t in_len = strlen(dups[i]);

		/* Not run(): the request is refused before it is all read. */
		hc = gwp_http_conn_alloc();
		assert(hc);
		assert(gwp_http_conn_process(hc, NULL, dups[i], &in_len, &host,
					     &port, &req, &req_len) ==
		       GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, list, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	assert(memmem(req, req_len, "\r\nAccept: a, b\r\n", 16));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * A request header may hold at most GWNET_HTTP_HDR_MAX_FIELDS (128) field
 * lines and 16 KiB; past either it is refused with 431 instead of being
 * parsed at a cost that grows with the square of the field count.
 */
static void test_header_limits(void)
{
	static char buf[20000];
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, n, in_len;
	int i, r;

	/* Exactly at the limit: accepted. */
	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\n");
	for (i = 0; i < 128; i++)
		n += (size_t)sprintf(buf + n, "X-%d: v\r\n", i);
	n += (size_t)sprintf(buf + n, "\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	gwp_http_conn_free(hc);

	/* One more field line, even a merged list field: refused. */
	sprintf(buf + n - 2, "Accept: a\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	in_len = strlen(buf);
	r = gwp_http_conn_process(hc, NULL, buf, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_TOO_LARGE);
	gwp_http_conn_free(hc);

	/* A single field longer than 16 KiB: refused, not dropped. */
	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\nX: ");
	memset(buf + n, 'a', 17000);
	n += 17000;
	sprintf(buf + n, "\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	in_len = strlen(buf);
	r = gwp_http_conn_process(hc, NULL, buf, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_TOO_LARGE);
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_auth(void)
{
	static const char no_cred[] =
		"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
	static const char good[] =	/* Basic base64("user:pass") */
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
	static const char bad[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n";
	static const char cred_data[] = "user:pass\n";
	char cred_file[] = "/tmp/gwp_http_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	uint8_t out[128];
	ssize_t w;
	int r;

	w = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(w == (ssize_t)(sizeof(cred_data) - 1));
	r = gwp_auth_create(&auth, cred_file);
	assert(!r);
	assert(auth);

	/* No credentials -> challenge. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, no_cred, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	gwp_http_conn_free(hc);

	/* Wrong credentials -> challenge. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, bad, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	gwp_http_conn_free(hc);

	/* Correct credentials -> proceed. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, good, &host, &port, &req, &req_len) == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "example.com"));
	gwp_http_conn_free(hc);

	/* The 407 challenge reply is well-formed and bounds-checked. */
	r = gwp_http_build_auth_required_reply(out, sizeof(out));
	assert(r > 0 && (size_t)r == strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"
					    "Proxy-Authenticate: Basic realm=\"gwproxy\"\r\n"
					    "Content-Length: 0\r\n"
					    "Connection: close\r\n\r\n"));
	assert(!strncmp((char *)out, "HTTP/1.1 407 ", 13));
	assert(gwp_http_build_auth_required_reply(out, 5) == -ENOBUFS);

	gwp_auth_destroy(auth);
	unlink(cred_file);
	PRTEST_OK();
}

int main(void)
{
	size_t i;

	for (i = 0; i < 1000; i++) {
		test_connect_ipv4();
		test_connect_ipv6();
		test_forward_get();
		test_forward_default_port();
		test_forward_hop_by_hop();
		test_forward_conn_lists_framing();
		test_forward_conn_limit();
		test_req_framing();
		test_res_rewrite();
		test_res_interim();
		test_res_reject();
		test_res_limits();
		test_need_more();
		test_errors();
		test_duplicate_field();
		test_header_limits();
		test_auth();
	}

	printf("All tests passed!\n");
	return 0;
}
