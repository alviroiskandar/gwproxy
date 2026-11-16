// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the upstream handshake failure classes (upstream.h): every
 * way a handshake can end, and whose fault it is. Also the host an upstream
 * URL names, as TLS checks it, and the host names it may give.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/upstream.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <gwproxy/common.h>

#define U	GWP_UPSTREAM_FAIL_UPSTREAM
#define D	GWP_UPSTREAM_FAIL_DESTINATION
#define N	GWP_UPSTREAM_FAIL_NEUTRAL

static unsigned nr_checks;

static void check(enum gwp_upstream_end end, int val,
		  enum gwp_upstream_fail_class want, int line)
{
	enum gwp_upstream_fail_class got = gwp_upstream_fail_classify(end, val);

	if (got != want) {
		fprintf(stderr, "line %d: end=%d val=%d: got %s, want %s\n",
			line, (int)end, val, gwp_upstream_fail_class_str(got),
			gwp_upstream_fail_class_str(want));
		assert(0);
	}
	nr_checks++;
}

#define CHECK(end, val, want) check(GWP_UPSTREAM_END_##end, (val), (want), \
				    __LINE__)

/* TCP connect to the upstream: refused, timed out or reset count. */
static void test_connect(void)
{
	static const int up[] = {
		ECONNREFUSED, ETIMEDOUT, ECONNRESET, ECONNABORTED, EPIPE,
		EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN,
	};
	static const int local[] = {
		ENOMEM, EMFILE, ENFILE, ENOBUFS, EADDRNOTAVAIL, EAFNOSUPPORT,
		EINVAL, 0,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(up); i++) {
		CHECK(CONNECT, up[i], U);
		CHECK(CONNECT, -up[i], U);	/* either sign */
	}
	for (i = 0; i < ARRAY_SIZE(local); i++) {
		CHECK(CONNECT, local[i], N);
		CHECK(CONNECT, -local[i], N);
	}
}

/*
 * Out of time waiting for the CONNECT's reply: the destination may be the
 * one that does not answer, so it does not count.
 */
static void test_timeout_reply(void)
{
	CHECK(TIMEOUT, 1, N);
}

/* The ends that always count, whatever @val holds. */
static void test_always_upstream(void)
{
	CHECK(TLS, 0, U);
	CHECK(MALFORMED, 0, U);
	CHECK(HUP, 0, U);
	/* Out of time before the CONNECT was out: the upstream's. */
	CHECK(TIMEOUT, 0, U);

	/* No acceptable method, or one we never offered. */
	CHECK(S5_METHOD, 0xff, U);
	CHECK(S5_METHOD, 0x01, U);
	CHECK(S5_METHOD, 0x02, U);
	CHECK(S5_METHOD, 0x80, U);
}

static void test_s5_auth(void)
{
	int st;

	CHECK(S5_AUTH, 0x00, N);	/* not a failure */
	for (st = 0x01; st <= 0xff; st++)
		CHECK(S5_AUTH, st, U);
}

static void test_s5_rep(void)
{
	int rep;

	CHECK(S5_REP, 0x00, N);		/* succeeded: not a failure */
	CHECK(S5_REP, 0x01, N);		/* general failure */
	CHECK(S5_REP, 0x02, N);		/* not allowed by ruleset */
	CHECK(S5_REP, 0x03, D);		/* network unreachable */
	CHECK(S5_REP, 0x04, D);		/* host unreachable */
	CHECK(S5_REP, 0x05, D);		/* connection refused */
	CHECK(S5_REP, 0x06, D);		/* TTL expired */
	CHECK(S5_REP, 0x07, U);		/* command not supported */
	CHECK(S5_REP, 0x08, U);		/* address type not supported */
	for (rep = 0x09; rep <= 0xff; rep++)
		CHECK(S5_REP, rep, U);	/* unassigned */
}

static void test_http(void)
{
	int st;

	CHECK(HTTP, 407, U);
	CHECK(HTTP, 502, D);
	CHECK(HTTP, 504, D);
	CHECK(HTTP, 403, N);
	CHECK(HTTP, 500, N);
	CHECK(HTTP, 503, N);

	/* Every other status, 2xx (not a failure) or not, is neutral. */
	for (st = 100; st <= 599; st++) {
		if (st == 407 || st == 502 || st == 504)
			continue;
		CHECK(HTTP, st, N);
	}

	/* Not a status code at all: the reply is garbage. */
	CHECK(HTTP, -1, U);
	CHECK(HTTP, 0, U);
	CHECK(HTTP, 99, U);
	CHECK(HTTP, 600, U);
	CHECK(HTTP, 999, U);
}

static void test_str(void)
{
	assert(!strcmp(gwp_upstream_fail_class_str(U), "upstream"));
	assert(!strcmp(gwp_upstream_fail_class_str(D), "destination"));
	assert(!strcmp(gwp_upstream_fail_class_str(N), "neutral"));
}

static void check_host(const char *hostport, int want_r, const char *want,
		       bool want_ip, int line)
{
	char out[16];
	bool is_ip = !want_ip;
	int r;

	memset(out, 'x', sizeof(out));
	r = gwp_upstream_url_host(hostport, out, sizeof(out), &is_ip);
	if (r != want_r || (!r && (strcmp(out, want) || is_ip != want_ip))) {
		fprintf(stderr, "line %d: '%s': got %d '%.*s' ip=%d, want %d '%s' ip=%d\n",
			line, hostport, r, (int)sizeof(out), out, is_ip,
			want_r, want ? want : "", want_ip);
		assert(0);
	}
	nr_checks++;
}

#define HOST(hp, name, ip)	check_host((hp), 0, (name), (ip), __LINE__)
#define BAD_HOST(hp)		check_host((hp), -EINVAL, NULL, false, __LINE__)

/*
 * The host an https:// upstream is checked against: a DNS name goes out as
 * SNI and is matched against the certificate's names, an address literal is
 * matched against its IP addresses only.
 */
static void test_url_host(void)
{
	HOST("proxy.example:443", "proxy.example", false);
	HOST("proxy.example", "proxy.example", false);
	HOST("localhost:8080", "localhost", false);
	HOST("127.0.0.1:3128", "127.0.0.1", true);
	HOST("127.0.0.1", "127.0.0.1", true);
	HOST("[::1]:443", "::1", true);
	HOST("[2001:db8::7]", "2001:db8::7", true);
	/* Not an address literal inet_pton() accepts: a name. */
	HOST("127.1:80", "127.1", false);
	HOST("1.2.3.4.5:80", "1.2.3.4.5", false);
	/* Just fits: 15 bytes and the NUL. */
	HOST("abcdefghijklmno:1", "abcdefghijklmno", false);

	BAD_HOST("");
	BAD_HOST(":443");
	BAD_HOST("[]:443");
	BAD_HOST("[::1:443");
	BAD_HOST("abcdefghijklmnop:1");
}

static void check_name(const char *in, bool want_ok, const char *want,
		       bool want_v4, int line)
{
	struct in_addr a4 = { 0 };
	char host[300], ip[INET_ADDRSTRLEN] = "";
	bool ok, is_v4 = !want_v4;

	assert(strlen(in) < sizeof(host));
	strcpy(host, in);
	ok = gwp_upstream_name_ok(host, &a4, &is_v4);
	if (ok && is_v4)
		assert(inet_ntop(AF_INET, &a4, ip, sizeof(ip)));
	if (ok != want_ok ||
	    (ok && (is_v4 != want_v4 || strcmp(is_v4 ? ip : host, want)))) {
		fprintf(stderr, "line %d: '%s': got %d '%s' v4=%d, want %d '%s' v4=%d\n",
			line, in, ok, is_v4 ? ip : host, is_v4, want_ok,
			want ? want : "", want_v4);
		assert(0);
	}
	nr_checks++;
}

#define NAME(in, out)	check_name((in), true, (out), false, __LINE__)
#define V4(in, out)	check_name((in), true, (out), true, __LINE__)
#define BAD_NAME(in)	check_name((in), false, NULL, false, __LINE__)

/* Fill @buf with @n labels of @len 'a's, dot-separated, and @tail after. */
static char *labels(char *buf, int n, int len, const char *tail)
{
	char *p = buf;
	int i;

	for (i = 0; i < n; i++) {
		if (i)
			*p++ = '.';
		memset(p, 'a', (size_t)len);
		p += len;
	}
	strcpy(p, tail);
	return buf;
}

/*
 * The host names an upstream URL may give: what can resolve as a DNS name,
 * with no '-' at either end of a label, or an IPv4 address in a form
 * inet_aton() reads.
 */
static void test_name(void)
{
	char a[300], b[300];

	NAME("proxy.example", "proxy.example");
	NAME("localhost.", "localhost");
	NAME("a", "a");
	NAME("a-b.c_d.E9", "a-b.c_d.E9");
	NAME("_srv.example", "_srv.example");
	NAME("0x7f.1", "0x7f.1");
	NAME("1.2.3.4a", "1.2.3.4a");
	V4("127.1", "127.0.0.1");
	V4("10.0.0.1", "10.0.0.1");
	V4("10.0.0.1.", "10.0.0.1");
	V4("2130706433", "127.0.0.1");

	BAD_NAME("");
	BAD_NAME(".");
	BAD_NAME("..");
	BAD_NAME("a..b");
	BAD_NAME(".a");
	BAD_NAME("a.b..");
	BAD_NAME("-");
	BAD_NAME("-a.example");
	BAD_NAME("a-.example");
	BAD_NAME("a.-b");
	BAD_NAME("a.b-");
	BAD_NAME("a b");
	BAD_NAME("a:1");
	BAD_NAME("999.999.1.1");
	BAD_NAME("1.2.3.4.5");

	/* A label of 63 characters, but not 64. */
	NAME(labels(a, 1, 63, ".example"), labels(b, 1, 63, ".example"));
	BAD_NAME(labels(a, 1, 64, ".example"));
	BAD_NAME(labels(a, 2, 64, ""));
	/* 253 characters (and a root dot), but not 254. */
	NAME(labels(a, 4, 62, ".a"), labels(b, 4, 62, ".a"));
	assert(strlen(a) == 253);
	NAME(labels(a, 4, 62, ".a."), labels(b, 4, 62, ".a"));
	BAD_NAME(labels(a, 4, 62, ".ab"));
	BAD_NAME(labels(a, 4, 62, ".ab."));

	/* Without @ldh, a '-' may start or end a label. */
	assert(gwp_dns_name_ok("-a-.b-", 6, false));
	assert(!gwp_dns_name_ok("-a-.b-", 6, true));
	assert(!gwp_dns_name_ok("a..b", 4, false));
	assert(gwp_dns_name_ok("ab", 1, true));
	nr_checks += 4;
}

static void check_scheme(const char *url, const char *prefix, int type,
			 bool remote_dns, bool use_tls, uint16_t def_port)
{
	const struct gwp_upstream_scheme *sc;
	const char *rest = NULL;

	sc = gwp_upstream_scheme(url, &rest);
	if (!prefix) {
		assert(!sc);
		nr_checks++;
		return;
	}
	assert(sc && !strcmp(sc->prefix, prefix));
	assert(sc->len == strlen(prefix) && rest == url + sc->len);
	assert(sc->type == type && sc->remote_dns == remote_dns);
	assert(sc->use_tls == use_tls && sc->def_port == def_port);
	nr_checks++;
}

/* The four schemes, each with its properties, and nothing else. */
static void test_scheme(void)
{
	check_scheme("socks5://h", "socks5://", GWP_UPSTREAM_SOCKS5, false,
		     false, 1080);
	check_scheme("socks5h://h", "socks5h://", GWP_UPSTREAM_SOCKS5, true,
		     false, 1080);
	check_scheme("http://h:1", "http://", GWP_UPSTREAM_HTTP, true, false,
		     8080);
	check_scheme("https://", "https://", GWP_UPSTREAM_HTTP, true, true,
		     8080);
	check_scheme("", NULL, 0, false, false, 0);
	check_scheme("socks5", NULL, 0, false, false, 0);
	check_scheme("socks5:/h", NULL, 0, false, false, 0);
	check_scheme("socks4://h", NULL, 0, false, false, 0);
	check_scheme("SOCKS5://h", NULL, 0, false, false, 0);
	check_scheme("httpx://h", NULL, 0, false, false, 0);
	check_scheme("ftp://h", NULL, 0, false, false, 0);
}

static void check_creds(const char *rest, bool want, size_t want_ul,
			size_t want_pl, size_t want_at)
{
	size_t ul = 1234, pl = 1234;
	const char *at = NULL;

	assert(gwp_upstream_split_creds(rest, &at, &ul, &pl) == want);
	if (want) {
		assert(at == rest + want_at && *at == '@');
		assert(ul == want_ul && pl == want_pl);
	}
	nr_checks++;
}

/*
 * The credentials end at the last '@', the user name at the first ':' before
 * it; the lengths are only measured, so the callers' limits apply to them.
 */
static void test_split_creds(void)
{
	char big[600];

	check_creds("h:1", false, 0, 0, 0);
	check_creds("", false, 0, 0, 0);
	check_creds("u@h", true, 1, 0, 1);
	check_creds("u:p@h", true, 1, 1, 3);
	check_creds("u:@h", true, 1, 0, 2);
	check_creds(":p@h", true, 0, 1, 2);
	check_creds("@h", true, 0, 0, 0);
	check_creds("u:p:q@h", true, 1, 3, 5);
	check_creds("u:p@q@h:1", true, 1, 3, 5);
	check_creds("u@p:q@h", true, 3, 1, 5);

	/* Long ones are only measured: the callers refuse what is too long. */
	memset(big, 'u', 256);
	strcpy(big + 256, ":p@h");
	check_creds(big, true, 256, 1, 258);
	memset(big, 'p', 255);
	big[0] = 'u';
	big[1] = ':';
	strcpy(big + 255, "@h");
	check_creds(big, true, 1, 253, 255);
	assert(GWP_UPSTREAM_CRED_MAX == 255 && GWP_UPSTREAM_REST_MAX == 512);
}

int main(void)
{
	test_connect();
	test_always_upstream();
	test_timeout_reply();
	test_s5_auth();
	test_s5_rep();
	test_http();
	test_str();
	test_url_host();
	test_name();
	test_scheme();
	test_split_creds();
	printf("upstream: %u checks passed\n", nr_checks);
	return 0;
}
