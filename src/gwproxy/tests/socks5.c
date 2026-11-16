// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/socks5.h>
#include <gwproxy/auth.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_util.h"

static void test_socks5_init_ctx_no_auth(struct gwp_socks5_ctx **ctx)
{
	int r;

	r = gwp_socks5_ctx_init(ctx, NULL);
	assert(!r);
	assert(*ctx);
	assert((*ctx)->auth == NULL);
}

/* A context that asks for @auth's credentials and allows UDP ASSOCIATE. */
static void test_socks5_init_ctx_auth(struct gwp_socks5_ctx **ctx,
				      struct gwp_auth *auth)
{
	const struct gwp_socks5_cfg cfg = {
		.auth = auth,
		.udp_associate = true,
	};
	int r;

	r = gwp_socks5_ctx_init(ctx, &cfg);
	assert(!r);
	assert(*ctx);
	assert((*ctx)->auth == auth);
}

static struct gwp_socks5_conn *
test_socks5_alloc_conn(struct gwp_socks5_ctx *ctx)
{
	struct gwp_socks5_conn *conn;

	conn = gwp_socks5_conn_alloc(ctx);
	assert(conn);
	assert(conn->state == GWP_SOCKS5_ST_INIT);
	assert(conn->ctx == ctx);
	return conn;
}

/* Abort, naming the caller's @line, when the check @what (@ok) failed. */
static void check_at(int line, bool ok, const char *what)
{
	if (ok)
		return;
	fprintf(stderr, "%s:%d: %s does not match\n", __FILE__, line, what);
	abort();
}

/*
 * Feed the @in_len bytes at @in to @conn with room for @out_cap bytes of
 * reply, and check that gwp_socks5_conn_handle_data() returns @want_r, takes
 * @want_in bytes, writes exactly the @want_out_len bytes at @want_out and
 * leaves @conn in @want_state.
 */
static void feed_at(int line, struct gwp_socks5_conn *conn, const void *in,
		    size_t in_len, size_t out_cap, int want_r, size_t want_in,
		    const void *want_out, size_t want_out_len, int want_state)
{
	size_t out_len = out_cap;
	uint8_t out[4096];
	int r;

	assert(out_cap <= sizeof(out));
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	check_at(line, r == want_r, "return value");
	check_at(line, in_len == want_in, "in_len");
	check_at(line, out_len == want_out_len, "out_len");
	if (want_out_len)
		check_at(line, !memcmp(out, want_out, want_out_len), "reply");
	check_at(line, conn->state == want_state, "state");
}

/*
 * The expected reply @lit is a string literal, its length taken without the
 * terminating NUL, so it may hold NUL bytes; the "" makes anything but a
 * literal fail to build. A macro for that and for the caller's __LINE__.
 */
#define FEED(conn, in, in_len, cap, r, used, lit, st)			\
	feed_at(__LINE__, (conn), (in), (in_len), (cap), (r), (used),	\
		"" lit, sizeof("" lit) - 1, (st))

typedef int (*test_socks5_res_t)(struct gwp_socks5_conn *conn,
				 const struct gwp_socks5_addr *bind_addr,
				 uint8_t rep, void *out_buf, size_t *out_len);

/*
 * Make @conn's success reply with @res (the CONNECT or the UDP ASSOCIATE
 * one) and @bind_addr, and check that it is exactly the @want_len bytes at
 * @want and leaves @conn in @want_state.
 */
static void reply_at(int line, struct gwp_socks5_conn *conn,
		     test_socks5_res_t res,
		     const struct gwp_socks5_addr *bind_addr, const void *want,
		     size_t want_len, int want_state)
{
	uint8_t out[64];
	size_t out_len = sizeof(out);
	int r;

	r = res(conn, bind_addr, GWP_SOCKS5_REP_SUCCESS, out, &out_len);
	check_at(line, !r, "return value");
	check_at(line, out_len == want_len, "out_len");
	check_at(line, !memcmp(out, want, want_len), "reply");
	check_at(line, conn->state == want_state, "state");
}

/* A macro for the same reasons as FEED(). */
#define REPLY(conn, res, bind_addr, lit, st)				\
	reply_at(__LINE__, (conn), (res), (bind_addr), "" lit,		\
		 sizeof("" lit) - 1, (st))

/* ATYP, BND.ADDR and BND.PORT of the reply when no address is given. */
#define BND_IP4_ZERO							\
	"\x01"			/* ATYP: IPv4 address */		\
	"\x00\x00\x00\x00"	/* BND.ADDR: 0.0.0.0 */			\
	"\x00\x00"		/* BND.PORT: 0 */

#define REP_OK_IP4_ZERO							\
	"\x05\x00\x00"		/* VER, REP: succeeded, RSV */		\
	BND_IP4_ZERO

#define REP_OK_IP4_LO							\
	"\x05\x00\x00"		/* VER, REP: succeeded, RSV */		\
	"\x01"			/* ATYP: IPv4 address */		\
	"\x7f\x00\x00\x01"	/* BND.ADDR: 127.0.0.1 */		\
	"\xaa\xaa"		/* BND.PORT */

#define REP_OK_IP6_LO							\
	"\x05\x00\x00"		/* VER, REP: succeeded, RSV */		\
	"\x04"			/* ATYP: IPv6 address */		\
	"\x00\x00\x00\x00\x00\x00\x00\x00"				\
	"\x00\x00\x00\x00\x00\x00\x00\x01" /* BND.ADDR: ::1 */		\
	"\xaa\xaa"		/* BND.PORT */

/* The request's DST is 127.0.0.1:80. */
static void test_socks5_assert_dst_ipv4_lo80(const struct gwp_socks5_conn *conn)
{
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));
}

static void test_socks5_do_handshake_no_auth(struct gwp_socks5_conn *conn)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00 /* VER, NMETHODS, METHOD */
	};

	FEED(conn, in, sizeof(in), 10, 0, 3,
	     "\x05\x00" /* VER, METHOD: NO AUTHENTICATION REQUIRED */,
	     GWP_SOCKS5_ST_CMD);
}

static void test_connect_ipv4(void)
{
	/* Test connect to 127.0.0.1:80 */
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);

	FEED(conn, in, sizeof(in), 4096, 0, sizeof(in), "",
	     GWP_SOCKS5_ST_CMD_CONNECT);
	test_socks5_assert_dst_ipv4_lo80(conn);

	/* Reply with connect success. */
	REPLY(conn, gwp_socks5_conn_cmd_connect_res, &bind_addr, REP_OK_IP4_LO,
	      GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_connect_ipv6(void)
{
	/* Test connect to ::1:80 */
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x04, /* VER, CMD, RSV, ATYP */
		0x00, 0x00, 0x00, 0x00, /* DST.ADDR: ::1 */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV6,
		.port = 0xaaaa,
		.ip6 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);

	FEED(conn, in, sizeof(in), 4096, 0, sizeof(in), "",
	     GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV6);
	assert(!memcmp(conn->dst_addr.ip6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	REPLY(conn, gwp_socks5_conn_cmd_connect_res, &bind_addr, REP_OK_IP6_LO,
	      GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static int test_connect_domain(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x03, /* VER, CMD, RSV, ATYP */
		/* DST.ADDR: example.com */
		0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x50  /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 },
		.port = 0xaaaa
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);
	FEED(conn, in, sizeof(in), 4096, 0, sizeof(in), "",
	     GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_DOMAIN);
	assert(conn->dst_addr.domain.len == 11);
	assert(!memcmp(conn->dst_addr.domain.str, "example.com", 11));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	REPLY(conn, gwp_socks5_conn_cmd_connect_res, &bind_addr, REP_OK_IP4_LO,
	      GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	return 0;
}

static void test_short_recv(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, /* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	const uint8_t *inb;
	size_t i;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);

	inb = in;
	for (i = 0; i < 3; i++)
		FEED(conn, inb, i, 4096, -EAGAIN, 0, "", GWP_SOCKS5_ST_INIT);
	FEED(conn, inb, 3, 4096, 0, 3,
	     "\x05\x00" /* VER, METHOD: NO AUTHENTICATION REQUIRED */,
	     GWP_SOCKS5_ST_CMD);
	inb += 3;

	for (i = 0; i < (sizeof(in) - 3); i++)
		FEED(conn, inb, i, 4096, -EAGAIN, 0, "", GWP_SOCKS5_ST_CMD);
	FEED(conn, inb, sizeof(in) - 3, 4096, 0, sizeof(in) - 3, "",
	     GWP_SOCKS5_ST_CMD_CONNECT);
	test_socks5_assert_dst_ipv4_lo80(conn);

	/* Reply with connect success. */
	REPLY(conn, gwp_socks5_conn_cmd_connect_res, &bind_addr, REP_OK_IP4_LO,
	      GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_auth_userpass(void)
{
	static const uint8_t in[] = {
		0x05, 0x02, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x04,			/* PLEN */
		'p', 'a', 's', 's',	/* PASSWD */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50, /* DST.PORT: 80 */
	};
	static const char cred_data[] = "user:pass\n";
	char *cred_file;
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_auth *auth;
	const uint8_t *inb;

	auth = gwp_test_auth_from_buf("gwp_socks5_auth", cred_data,
				      sizeof(cred_data) - 1, &cred_file);
	test_socks5_init_ctx_auth(&ctx, auth);
	conn = test_socks5_alloc_conn(ctx);

	inb = in;
	/* VER, NMETHODS, {USER/PASS} */
	FEED(conn, inb, 4, 4096, 0, 4, "\x05\x02" /* VER, METHOD: USER/PASS */,
	     GWP_SOCKS5_ST_AUTH_USERPASS);
	inb += 4;

	/* VER, ULEN, UNAME, PLEN, PASSWD */
	FEED(conn, inb, 11, 4096, 0, 11, "\x01\x00" /* VER, REP: succeeded */,
	     GWP_SOCKS5_ST_CMD);
	inb += 11;

	/* Remaining data */
	FEED(conn, inb, sizeof(in) - 15, 4096, 0, sizeof(in) - 15, "",
	     GWP_SOCKS5_ST_CMD_CONNECT);
	test_socks5_assert_dst_ipv4_lo80(conn);

	/* Reply with connect success. */
	REPLY(conn, gwp_socks5_conn_cmd_connect_res, NULL, REP_OK_IP4_ZERO,
	      GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_test_auth_put(auth, cred_file);
}

/*
 * Load a credential file made of the @len bytes at @data; returns
 * gwp_auth_create()'s result and destroys the store again.
 */
static int try_cred_buf(const char *data, size_t len)
{
	char *cred_file;
	struct gwp_auth *auth = NULL;
	ssize_t w;
	int r;

	w = gwp_test_write_tmp(&cred_file, "gwp_socks5_auth", data, len);
	assert(w == (ssize_t)len);
	r = gwp_auth_create(&auth, cred_file);
	if (!r)
		gwp_auth_destroy(auth);
	unlink(cred_file);
	free(cred_file);
	return r;
}

static int try_cred_file(const char *data)
{
	return try_cred_buf(data, strlen(data));
}

/*
 * The credential file takes "user:password" lines, both parts 1 to 255
 * bytes, plus comments and blank lines. A line with no colon used to become
 * a user with an empty password, which a client could log in as by sending
 * none (PLEN 0); a comment line did the same.
 */
/*
 * The password comparison walks a fixed number of positions whatever the
 * lengths; it must still match only the exact password: no prefix, no
 * extension, nothing longer than any stored password, and the longest one
 * a store can hold.
 */
static void test_auth_check_lengths(void)
{
	char *cred_file;
	char data[16 + 256 + 1], pw[300];
	struct gwp_auth *auth;
	int n;

	memset(pw, 'q', sizeof(pw));
	n = snprintf(data, sizeof(data), "user:pass\nlong:%.*s\n", 255, pw);
	assert(n > 0 && (size_t)n < sizeof(data));
	auth = gwp_test_auth_from_buf("gwp_socks5_auth", data, (size_t)n,
				      &cred_file);

	assert(gwp_auth_check(auth, "user", 4, "pass", 4));
	assert(!gwp_auth_check(auth, "user", 4, "pas", 3));
	assert(!gwp_auth_check(auth, "user", 4, "passs", 5));
	assert(!gwp_auth_check(auth, "user", 4, "pasS", 4));
	assert(!gwp_auth_check(auth, "user", 4, NULL, 0));
	assert(!gwp_auth_check(auth, "nouser", 6, "pass", 4));

	assert(gwp_auth_check(auth, "long", 4, pw, 255));
	assert(!gwp_auth_check(auth, "long", 4, pw, 254));
	assert(!gwp_auth_check(auth, "long", 4, pw, 256));
	assert(!gwp_auth_check(auth, "long", 4, pw, sizeof(pw)));
	pw[254] = 'r';
	assert(!gwp_auth_check(auth, "long", 4, pw, 255));

	gwp_test_auth_put(auth, cred_file);
}

static void test_auth_file_lines(void)
{
	char longline[5000];

	assert(!try_cred_file("# admins\n\nuser:pw\n  # indented\n"));
	assert(try_cred_file("user\n") == -EINVAL);
	assert(try_cred_file("user:pw\n#\nother\n") == -EINVAL);
	assert(try_cred_file("user:\n") == -EINVAL);
	assert(try_cred_file(":pw\n") == -EINVAL);

	/* Too long for one read: an error, not two entries. */
	memset(longline, 'a', sizeof(longline) - 2);
	longline[sizeof(longline) - 2] = '\n';
	longline[sizeof(longline) - 1] = '\0';
	memcpy(longline + 4100, ":pw", 3);
	assert(try_cred_file(longline) == -EINVAL);

}

/*
 * A NUL byte anywhere in a line refuses the file. One at the start of a line
 * used to make it read as blank and be skipped, so a line could be hidden
 * from the loader; one inside a line was refused only by accident, as a line
 * too long.
 */
static void test_auth_file_nul(void)
{
	static const char lead[] = "user:pw\n\0other:pw\n";
	static const char lead_only[] = "user:pw\n\0\n";
	static const char mid[] = "user:pw\nother\0:pw\n";
	static const char tail[] = "user:pw\nother:pw\0\n";
	static const char last[] = "user:pw\nother:pw\0";
	static const char good[] = "user:pw\n";
	char *cred_file;
	struct gwp_auth *auth;

	assert(try_cred_buf(lead, sizeof(lead) - 1) == -EINVAL);
	assert(try_cred_buf(lead_only, sizeof(lead_only) - 1) == -EINVAL);
	assert(try_cred_buf(mid, sizeof(mid) - 1) == -EINVAL);
	assert(try_cred_buf(tail, sizeof(tail) - 1) == -EINVAL);
	assert(try_cred_buf(last, sizeof(last) - 1) == -EINVAL);
	assert(!try_cred_buf(good, sizeof(good) - 1));

	/* A reload that meets one keeps the credentials in force. */
	auth = gwp_test_auth_from_buf("gwp_socks5_auth", good,
				      sizeof(good) - 1, &cred_file);
	gwp_test_rewrite_file(cred_file, lead, sizeof(lead) - 1);
	assert(gwp_auth_reload(auth) == -EINVAL);
	assert(gwp_auth_check(auth, "user", 4, "pw", 2));
	assert(!gwp_auth_check(auth, "other", 5, "pw", 2));
	gwp_test_auth_put(auth, cred_file);
}

/*
 * A client that sends no password (PLEN == 0) is refused, and the check is
 * made with p == NULL and plen == 0 without dereferencing the NULL password
 * pointer (a plain memcmp(NULL, ..., 0) is UB and trips UBSan).
 */
static void test_auth_userpass_empty_password(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x00,			/* PLEN = 0 (no password) */
	};
	static const char cred_data[] = "user:pw\n";
	char *cred_file;
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_auth *auth;

	auth = gwp_test_auth_from_buf("gwp_socks5_auth", cred_data,
				      sizeof(cred_data) - 1, &cred_file);
	test_socks5_init_ctx_auth(&ctx, auth);
	conn = test_socks5_alloc_conn(ctx);

	/* greeting */
	FEED(conn, in, 3, 64, 0, 3, "\x05\x02" /* VER, METHOD: USER/PASS */,
	     GWP_SOCKS5_ST_AUTH_USERPASS);

	/* VER, ULEN, UNAME(4), PLEN */
	FEED(conn, in + 3, 7, 64, 0, 7, "\x01\x01" /* VER, STATUS: failure */,
	     GWP_SOCKS5_ST_ERR);
	/* The rejected name is kept for the log, not as the user. */
	assert(!gwp_socks5_conn_username(conn));
	{
		const char *bad;
		size_t blen = 0;

		bad = gwp_socks5_conn_rejected_user(conn, &blen);
		assert(bad && blen == 4 && !memcmp(bad, "user", 4));
	}

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_test_auth_put(auth, cred_file);
}

static void test_offered_methods_no_match(void)
{
	static const uint8_t in[] = {
		0x05, 0x05, /* VER, NMETHODS */
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e /* METHODS */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	FEED(conn, in, sizeof(in), 10, 0, sizeof(in),
	     "\x05\xff" /* VER, REP: no acceptable methods */,
	     GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

/*
 * Regression test for the info-leak where the state driver's default case
 * returned without setting *out_len. A greeting with no acceptable method
 * moves the connection to ST_ERR while returning success; a byte pipelined
 * after it re-enters the driver in ST_ERR (the "default" case). The driver
 * must report the real number of bytes produced (2, the method reply), not
 * leave *out_len at the caller-supplied output buffer capacity -- otherwise
 * the caller flushes that many bytes of uninitialized heap to the client.
 */
static void test_err_state_pipelined_byte(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x02, /* VER, NMETHODS, {USER/PASS} -- unacceptable */
		0x00              /* one pipelined trailing byte */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	/*
	 * Only the 3 greeting bytes are consumed, and only the 2-byte method
	 * reply is produced -- NOT the 64 bytes of room.
	 */
	FEED(conn, in, sizeof(in), 64, -EINVAL, 3,
	     "\x05\xff" /* VER, METHOD: no acceptable methods */,
	     GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_version(void)
{
	static const uint8_t in[] = {
		0xaa, 0x02,	/* VER, NMETHODS */
		0x01, 0x02	/* METHODS */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	FEED(conn, in, sizeof(in), 10, -EINVAL, 0, "", GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_connect_addr_type(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0xff, /* VER, CMD, RSV, ATYP */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);
	FEED(conn, in, sizeof(in), 10, -EINVAL, 0,
	     "\x05\x08\x00" /* VER, REP: address type not supported, RSV */
	     BND_IP4_ZERO, GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_command(void)
{
	static const uint8_t in[] = {
		0x05, 0xff, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);
	FEED(conn, in, sizeof(in), 10, -EINVAL, 0,
	     "\x05\x07\x00" /* VER, REP: command not supported, RSV */
	     BND_IP4_ZERO, GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_multi_state_at_once(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00,	/* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	FEED(conn, in, sizeof(in), 4096, 0, sizeof(in),
	     "\x05\x00" /* VER, METHOD: NO AUTHENTICATION REQUIRED */,
	     GWP_SOCKS5_ST_CMD_CONNECT);
	test_socks5_assert_dst_ipv4_lo80(conn);

	REPLY(conn, gwp_socks5_conn_cmd_connect_res, NULL, REP_OK_IP4_ZERO,
	      GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_enobufs(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, /* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t out_len;
	uint8_t out[4096];
	size_t i;
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);

	/*
	 * Prepare authentication data.
	 */
	FEED(conn, in, 3, 1, -ENOBUFS, 0, "", GWP_SOCKS5_ST_INIT);
	FEED(conn, in, 3, 2, 0, 3,
	     "\x05\x00" /* VER, METHOD: NO AUTHENTICATION REQUIRED */,
	     GWP_SOCKS5_ST_CMD);

	/*
	 * Prepare connect data.
	 */
	FEED(conn, in + 3, 10, 0, 0, 10, "", GWP_SOCKS5_ST_CMD_CONNECT);
	test_socks5_assert_dst_ipv4_lo80(conn);

	for (i = 0; i < 10; i++) {
		out_len = i;
		r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
						    GWP_SOCKS5_REP_SUCCESS, out,
						    &out_len);
		assert(r == -ENOBUFS);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	}

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_enobufs_combined_with_multi_state_at_once(void)
{
	static const uint8_t in[] = {
		0x05, 0x02, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x04,			/* PLEN */
		'p', 'a', 's', 's',	/* PASSWD */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50, /* DST.PORT: 80 */
	};
	static const char cred_data[] = "user:pass\n";
	char *cred_file;
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_auth *auth;
	size_t blen, out_len;
	uint8_t out[4096];
	ssize_t r;
	size_t i;

	auth = gwp_test_auth_from_buf("gwp_socks5_auth", cred_data,
				      sizeof(cred_data) - 1, &cred_file);
	test_socks5_init_ctx_auth(&ctx, auth);
	conn = test_socks5_alloc_conn(ctx);

	/* Nothing is consumed, so nothing is reported written. */
	for (i = 0; i < 4; i++)
		FEED(conn, in, sizeof(in), i, -ENOBUFS, 0, "",
		     GWP_SOCKS5_ST_INIT);

	FEED(conn, in, sizeof(in), 4, 0, sizeof(in),
	     "\x05\x02" /* VER, METHOD: USER/PASS */
	     "\x01\x00" /* VER, STATUS: succeeded */,
	     GWP_SOCKS5_ST_CMD_CONNECT);
	assert(!strcmp(gwp_socks5_conn_username(conn), "user"));
	assert(!gwp_socks5_conn_rejected_user(conn, &blen));
	test_socks5_assert_dst_ipv4_lo80(conn);

	/* Reply with connect success. */
	for (i = 0; i < 10; i++) {
		out_len = i;
		r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
						    GWP_SOCKS5_REP_SUCCESS, out,
						    &out_len);
		assert(r == -ENOBUFS);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	}

	REPLY(conn, gwp_socks5_conn_cmd_connect_res, NULL, REP_OK_IP4_ZERO,
	      GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_test_auth_put(auth, cred_file);
}

static void test_udp_associate(void)
{
	/* UDP ASSOCIATE with DST 0.0.0.0:0 (client source not yet known). */
	static const uint8_t in[] = {
		0x05, 0x03, 0x00, 0x01, /* VER, CMD=UDP ASSOCIATE, RSV, ATYP */
		0x00, 0x00, 0x00, 0x00, /* DST.ADDR: 0.0.0.0 */
		0x00, 0x00              /* DST.PORT: 0 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(conn);

	FEED(conn, in, sizeof(in), 64, 0, sizeof(in), "",
	     GWP_SOCKS5_ST_CMD_UDP_ASSOCIATE);

	/* Reply with the relay endpoint. */
	REPLY(conn, gwp_socks5_conn_cmd_udp_associate_res, &bind_addr,
	      REP_OK_IP4_LO, GWP_SOCKS5_ST_UDP_ASSOCIATED);

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_udp_hdr_codec(void)
{
	struct gwp_socks5_addr a, got;
	uint8_t buf[GWP_SOCKS5_UDP_HDR_MAX + 16];
	uint8_t dg[128];
	size_t hlen, plen;
	int r;

	/* IPv4 round-trip, with trailing DATA on parse. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_IPV4;
	memcpy(a.ip4, "\x08\x08\x08\x08", 4);
	memcpy(&a.port, "\x00\x35", 2);		/* 53 */
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 4 + 2);
	assert(buf[0] == 0 && buf[1] == 0 && buf[2] == 0);
	assert(buf[3] == GWP_SOCKS5_ATYP_IPV4);
	memcpy(dg, buf, hlen);
	memcpy(dg + hlen, "hello", 5);
	r = gwp_socks5_udp_parse_hdr(dg, hlen + 5, &got, &plen);
	assert(!r && plen == hlen);
	assert(got.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(got.ip4, a.ip4, 4));
	assert(!memcmp(&got.port, &a.port, 2));
	assert(!memcmp(dg + plen, "hello", 5));

	/* IPv6 round-trip. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_IPV6;
	memcpy(a.ip6, "\x20\x01\x0d\xb8\x00\x00\x00\x00"
		      "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&a.port, "\x01\xbb", 2);		/* 443 */
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 16 + 2);
	r = gwp_socks5_udp_parse_hdr(buf, hlen, &got, &plen);
	assert(!r && plen == hlen && got.ver == GWP_SOCKS5_ATYP_IPV6);
	assert(!memcmp(got.ip6, a.ip6, 16));

	/* Domain round-trip. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_DOMAIN;
	a.domain.len = 11;
	memcpy(a.domain.str, "example.com", 12);
	memcpy(&a.port, "\x00\x50", 2);
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 1 + 11 + 2);
	r = gwp_socks5_udp_parse_hdr(buf, hlen, &got, &plen);
	assert(!r && got.ver == GWP_SOCKS5_ATYP_DOMAIN && got.domain.len == 11);
	assert(!memcmp(got.domain.str, "example.com", 11));

	/* FRAG != 0 -> unsupported. */
	memcpy(dg, "\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35", 10);
	r = gwp_socks5_udp_parse_hdr(dg, 10, &got, &plen);
	assert(r == -ENOTSUP);

	/* Truncated header -> need more. */
	r = gwp_socks5_udp_parse_hdr(dg, 3, &got, &plen);
	assert(r == -EAGAIN);

	/* Unknown ATYP -> malformed. */
	memcpy(dg, "\x00\x00\x00\x09\x00\x00\x00\x00", 8);
	r = gwp_socks5_udp_parse_hdr(dg, 8, &got, &plen);
	assert(r == -EINVAL);

	/* Build into too small a buffer. */
	r = gwp_socks5_udp_build_hdr(&a, buf, 4, &hlen);
	assert(r == -ENOBUFS);
}

/* The client side's UDP ASSOCIATE request and the reply's BND.ADDR:PORT. */
static void test_cli_udp_associate(void)
{
	struct gwp_socks5_addr a, bnd;
	uint8_t buf[300];
	size_t len, used;
	uint8_t rep;
	int r;

	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_IPV4;
	memcpy(a.ip4, "\x7f\x00\x00\x01", 4);
	memcpy(&a.port, "\x12\x34", 2);
	len = sizeof(buf);
	r = gwp_socks5_cli_build_udp_associate(&a, buf, &len);
	assert(!r && len == 10);
	assert(!memcmp(buf, "\x05\x03\x00\x01\x7f\x00\x00\x01\x12\x34", 10));

	/* CONNECT is the same request with its own command. */
	len = sizeof(buf);
	r = gwp_socks5_cli_build_connect(&a, buf, &len);
	assert(!r && len == 10 && buf[1] == 0x01);

	len = 9;
	r = gwp_socks5_cli_build_udp_associate(&a, buf, &len);
	assert(r == -ENOBUFS && len == 10);

	/* An IPv4 BND, with a byte of something else behind it. */
	memcpy(buf, "\x05\x00\x00\x01\x0a\x00\x00\x02\x30\x39\xff", 11);
	for (len = 0; len < 10; len++) {
		r = gwp_socks5_cli_parse_reply(buf, len, &rep, &bnd, &used);
		assert(r == -EAGAIN);
	}
	r = gwp_socks5_cli_parse_reply(buf, 11, &rep, &bnd, &used);
	assert(!r && rep == 0 && used == 10);
	assert(bnd.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(bnd.ip4, "\x0a\x00\x00\x02", 4));
	assert(!memcmp(&bnd.port, "\x30\x39", 2));
	r = gwp_socks5_cli_parse_connect(buf, 11, &rep, &used);
	assert(!r && rep == 0 && used == 10);

	/* An IPv6 one, refused. */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, "\x05\x07\x00\x04", 4);
	buf[19] = 1;
	memcpy(buf + 20, "\x00\x35", 2);
	r = gwp_socks5_cli_parse_reply(buf, 21, &rep, &bnd, &used);
	assert(r == -EAGAIN);
	r = gwp_socks5_cli_parse_reply(buf, 22, &rep, &bnd, &used);
	assert(!r && rep == 0x07 && used == 22);
	assert(bnd.ver == GWP_SOCKS5_ATYP_IPV6 && bnd.ip6[15] == 1);
	assert(!memcmp(&bnd.port, "\x00\x35", 2));

	/* A domain one. */
	memcpy(buf, "\x05\x00\x00\x03\x04host\x00\x50", 11);
	r = gwp_socks5_cli_parse_reply(buf, 4, &rep, &bnd, &used);
	assert(r == -EAGAIN);
	r = gwp_socks5_cli_parse_reply(buf, 10, &rep, &bnd, &used);
	assert(r == -EAGAIN);
	r = gwp_socks5_cli_parse_reply(buf, 11, &rep, &bnd, &used);
	assert(!r && used == 11 && bnd.ver == GWP_SOCKS5_ATYP_DOMAIN);
	assert(bnd.domain.len == 4 && !strcmp(bnd.domain.str, "host"));
	assert(!memcmp(&bnd.port, "\x00\x50", 2));
	r = gwp_socks5_cli_parse_reply(buf, 11, &rep, NULL, &used);
	assert(!r && used == 11);

	/* Not SOCKS5, or an address type there is none of. */
	buf[0] = 0x04;
	r = gwp_socks5_cli_parse_reply(buf, 11, &rep, &bnd, &used);
	assert(r == -EINVAL);
	memcpy(buf, "\x05\x00\x00\x02", 4);
	r = gwp_socks5_cli_parse_reply(buf, 11, &rep, &bnd, &used);
	assert(r == -EINVAL);
}

/* The client side's two-byte replies: method selection and RFC 1929 status. */
static void test_cli_parse_two_byte_replies(void)
{
	uint8_t v;
	int r;

	v = 0xaa;
	r = gwp_socks5_cli_parse_method("\x05", 1, &v);
	assert(r == -EAGAIN && v == 0xaa);
	r = gwp_socks5_cli_parse_method("\x01\x00", 2, &v);
	assert(r == -EINVAL && v == 0xaa);
	r = gwp_socks5_cli_parse_method("\x05\x02\xff", 3, &v);
	assert(!r && v == 0x02);

	v = 0xaa;
	r = gwp_socks5_cli_parse_userpass("\x01", 1, &v);
	assert(r == -EAGAIN && v == 0xaa);
	r = gwp_socks5_cli_parse_userpass("\x05\x00", 2, &v);
	assert(r == -EINVAL && v == 0xaa);
	r = gwp_socks5_cli_parse_userpass("\x01\x01", 2, &v);
	assert(!r && v == 0x01);
}

static void gwp_socks5_run_tests(void)
{
	size_t i;

	/* Once: each refused file prints its parse error. */
	test_auth_file_lines();
	test_auth_file_nul();
	test_auth_check_lengths();

	for (i = 0; i < 5000; i++) {
		test_udp_associate();
		test_udp_hdr_codec();
		test_cli_udp_associate();
		test_cli_parse_two_byte_replies();
		test_connect_ipv4();
		test_connect_ipv6();
		test_connect_domain();
		test_short_recv();
		test_auth_userpass();
		test_auth_userpass_empty_password();
		test_offered_methods_no_match();
		test_err_state_pipelined_byte();
		test_invalid_version();
		test_invalid_connect_addr_type();
		test_invalid_command();
		test_multi_state_at_once();
		test_enobufs();
		test_enobufs_combined_with_multi_state_at_once();
	}

	printf("All tests passed!\n");
}

int main(void)
{
	gwp_socks5_run_tests();
	return 0;
}
