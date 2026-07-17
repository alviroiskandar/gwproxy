// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the iptables-style ACL parser and matcher (acl.c).
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/acl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static struct gwp_sockaddr sa4(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	s.i4.sin_family = AF_INET;
	assert(inet_pton(AF_INET, ip, &s.i4.sin_addr) == 1);
	s.i4.sin_port = htons(port);
	return s;
}

static struct gwp_sockaddr sa6(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	s.i6.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &s.i6.sin6_addr) == 1);
	s.i6.sin6_port = htons(port);
	return s;
}

/* An IPv4 address as the v4-mapped IPv6 the dual-stack UDP relay would see. */
static struct gwp_sockaddr sa4mapped(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;
	uint8_t v4[4];

	memset(&s, 0, sizeof(s));
	s.i6.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET, ip, v4) == 1);
	s.i6.sin6_addr.s6_addr[10] = 0xff;
	s.i6.sin6_addr.s6_addr[11] = 0xff;
	memcpy(&s.i6.sin6_addr.s6_addr[12], v4, 4);
	s.i6.sin6_port = htons(port);
	return s;
}

static enum gwp_acl_verdict out(struct gwp_acl *a, struct gwp_sockaddr *t,
				const char *dom, uint16_t dport,
				enum gwp_acl_proto p)
{
	struct gwp_acl_req req = {
		.target = t, .domain = dom, .dport = dport, .proto = p,
	};

	return gwp_acl_eval_output(a, &req);
}

static enum gwp_acl_verdict out_user(struct gwp_acl *a, struct gwp_sockaddr *t,
				     const char *user, uint16_t dport)
{
	struct gwp_acl_req req = {
		.target = t, .user = user, .dport = dport,
		.proto = GWP_ACL_PROTO_TCP,
	};

	return gwp_acl_eval_output(a, &req);
}

static enum gwp_acl_verdict in(struct gwp_acl *a, struct gwp_sockaddr *c,
			       uint16_t sport, enum gwp_acl_proto p)
{
	struct gwp_acl_req req = {
		.client = c, .sport = sport, .proto = p,
	};

	return gwp_acl_eval_input(a, &req);
}

static const char DEFAULT_RULES[] =
	"-P INPUT ACCEPT\n"
	"-A OUTPUT ! --dports 80,443 -j REJECT\n"
	"-A OUTPUT -d 10.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 127.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 192.168.0.0/16 -j REJECT\n"
	"-A OUTPUT -d 172.16.0.0/12 -j REJECT\n"
	"-A OUTPUT -d fe80::/10 -j REJECT\n"
	"-A OUTPUT -d fc00::/7 -j REJECT\n"
	"-P OUTPUT ACCEPT\n";

static void test_default_ruleset(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;
	int r;

	r = gwp_acl_parse_str(&a, DEFAULT_RULES);
	assert(!r && a);

	/* Public IP on an allowed port is accepted. */
	s = sa4("8.8.8.8", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4("8.8.8.8", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* Public IP on a disallowed port is rejected (! --dports). */
	s = sa4("8.8.8.8", 22);
	assert(out(a, &s, NULL, 22, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* Private / loopback ranges rejected even on an allowed port. */
	s = sa4("127.0.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("10.1.2.3", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("192.168.5.5", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("172.16.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("172.31.255.255", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* 172.15/16 is just outside 172.16.0.0/12 -> allowed. */
	s = sa4("172.15.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* v4-mapped loopback must also hit the 127.0.0.0/8 rule. */
	s = sa4mapped("127.0.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* IPv6 link-local / ULA rejected; public v6 allowed. */
	s = sa6("fe80::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa6("fc00::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa6("2606:4700::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa6("2606:4700::1", 22);
	assert(out(a, &s, NULL, 22, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	gwp_acl_destroy(a);
}

static void test_ports_and_negation(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	/* Port ranges and lists. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 --dports 1000-2000,8080 -j REJECT\n"));
	s = sa4("1.2.3.4", 1500);
	assert(out(a, &s, NULL, 1500, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("1.2.3.4", 8080);
	assert(out(a, &s, NULL, 8080, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("1.2.3.4", 3000);
	assert(out(a, &s, NULL, 3000, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Negated source: reject everything except 10.0.0.0/8. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A INPUT ! -s 10.0.0.0/8 -j REJECT\n"));
	s = sa4("10.5.5.5", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4("8.8.8.8", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
}

static void test_input_and_proto(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"-P INPUT REJECT\n"
		"-A INPUT -s 192.168.0.0/16 -p tcp -j ACCEPT\n"));
	s = sa4("192.168.1.1", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* Same source but udp: the tcp rule does not match -> default REJECT. */
	assert(in(a, &s, 0, GWP_ACL_PROTO_UDP) == GWP_ACL_REJECT);
	s = sa4("8.8.8.8", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
}

static void test_domain(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain example.com -j REJECT\n"));
	assert(out(a, NULL, "example.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "EXAMPLE.COM", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "other.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* A literal-IP target (no domain) does not match a domain rule. */
	assert(out(a, NULL, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/*
	 * A rule WITHOUT a domain match, evaluated against a query that DOES
	 * carry a domain, must not deref the rule's NULL domain (regression:
	 * crit_ok evaluates its matched argument eagerly).
	 */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT --dports 80 -j REJECT\n-P OUTPUT ACCEPT\n"));
	s = sa4("1.2.3.4", 80);
	assert(out(a, &s, "example.com", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &s, "example.com", 81, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

static void test_domain_regexp(void)
{
#ifdef CONFIG_PCRE
	struct gwp_acl *a = NULL;

	/* Raw/unanchored, case-insensitive PCRE against the requested host. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp \\.example\\.com$ -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out(a, NULL, "a.example.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "A.EXAMPLE.COM", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	/* Unanchored on the left, anchored on the right by the pattern. */
	assert(out(a, NULL, "example.com.evil.net", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(out(a, NULL, "other.org", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* A literal-IP target (no hostname) never matches a domain regexp. */
	assert(out(a, NULL, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
#endif
}

static void test_user(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s = sa4("1.2.3.4", 80);

	/* Exact, case-sensitive username; unauthenticated never matches. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user alice -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "alice", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "ALICE", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, "bob", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, NULL, 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Negated: everyone but alice, including an absent (NULL) username. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user ! --user alice -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "bob", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "alice", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, NULL, 80) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

#ifdef CONFIG_PCRE
	/* --user-regexp is case-sensitive (no PCRE2_CASELESS for usernames). */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user-regexp ^team- -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "team-a", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "user001", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, "TEAM-a", 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
#endif
}

static void test_mark(void)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 80);
	struct gwp_acl *a = NULL;
	struct gwp_acl_req req;

	/* MARK is a composable modifier: it records the fwmark (hex accepted)
	 * and eval keeps matching to reach a terminal rule / the policy. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 0x64\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 100);
	gwp_acl_destroy(a);

	/* A non-matching MARK rule leaves the request unmarked. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 9.9.9.9 -j MARK --set-mark 7\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(!req.mark_set);
	gwp_acl_destroy(a);

	/* Last MARK wins; a later terminal REJECT still decides the verdict. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 1\n"
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 2\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(req.mark_set && req.mark == 2);
	gwp_acl_destroy(a);
}

static void test_bind(void)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 80);
	struct gwp_acl *a = NULL;
	struct gwp_acl_req req;
	char ip[64];

	/* BIND records a source address (with port) and interface, and keeps
	 * matching (composable modifier). */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-source 10.0.0.2:5000 --to-iface wg0\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && req.bind.have_src);
	assert(!strcmp(req.bind.iface, "wg0"));
	assert(req.bind.src.i4.sin_family == AF_INET);
	assert(inet_ntop(AF_INET, &req.bind.src.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "10.0.0.2") && ntohs(req.bind.src.i4.sin_port) == 5000);
	gwp_acl_destroy(a);

	/* Interface-only bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -j BIND --to-iface eth1\n-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && !req.bind.have_src && !strcmp(req.bind.iface, "eth1"));
	gwp_acl_destroy(a);

	/* Bracketed IPv6 source with a port; source-only bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -j BIND --to-source [2001:db8::1]:443\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && req.bind.have_src && req.bind.iface[0] == '\0');
	assert(req.bind.src.i6.sin6_family == AF_INET6);
	assert(ntohs(req.bind.src.i6.sin6_port) == 443);
	gwp_acl_destroy(a);

	/* Composable: BIND then a terminal REJECT still records the bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-iface eth0\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(req.bind.set && !strcmp(req.bind.iface, "eth0"));
	gwp_acl_destroy(a);
}

/* Evaluate one OUTPUT DNAT rule against target @ip:@port; return the req. */
static struct gwp_acl_req dnat_eval(const char *rule, const char *ip,
				    uint16_t port, bool v6)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = v6 ? sa6(ip, port) : sa4(ip, port);
	struct gwp_acl_req req = { .target = &t, .dport = port,
				  .proto = GWP_ACL_PROTO_TCP };

	assert(!gwp_acl_parse_str(&a, rule));
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
	return req;
}

static void test_dnat(void)
{
	struct gwp_acl_req req;
	char ip[64];

	/* Rewrite both address and port. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8:9999\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied && req.dnat.i4.sin_family == AF_INET);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8") && ntohs(req.dnat.i4.sin_port) == 9999);

	/* Address only: port carried over from the target. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8") && ntohs(req.dnat.i4.sin_port) == 80);

	/* Port only: address carried over from the target. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to :4444\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "1.2.3.4") && ntohs(req.dnat.i4.sin_port) == 4444);

	/* Port only on an IPv6 target: address preserved, family stays v6. */
	req = dnat_eval("-A OUTPUT -d 2001:db8::1 -j DNAT --to :4444\n",
			"2001:db8::1", 443, true);
	assert(req.dnat_applied && req.dnat.i6.sin6_family == AF_INET6);
	assert(inet_ntop(AF_INET6, &req.dnat.i6.sin6_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "2001:db8::1") && ntohs(req.dnat.i6.sin6_port) == 4444);

	/* IPv6 address+port rewrite via bracket form. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to [2001:db8::2]:5555\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied && req.dnat.i6.sin6_family == AF_INET6);
	assert(inet_ntop(AF_INET6, &req.dnat.i6.sin6_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "2001:db8::2") && ntohs(req.dnat.i6.sin6_port) == 5555);

	/* A non-matching target is not rewritten. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to :4444\n"
			"-P OUTPUT ACCEPT\n", "9.9.9.9", 80, false);
	assert(!req.dnat_applied);

	/*
	 * DNAT is terminal: a later matching REJECT must not be reached, so the
	 * verdict is ACCEPT and the rewrite still applies.
	 */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8\n"
			"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
			"-P OUTPUT REJECT\n", "1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8"));

	/*
	 * A domain-only request (no resolved IP, as with a socks5h upstream) can
	 * still be DNAT'd to an explicit address; the rewrite yields that IP even
	 * with no base target. The caller then redirects the upstream to it.
	 */
	{
		struct gwp_acl *a = NULL;
		struct gwp_acl_req q;

		assert(!gwp_acl_parse_str(&a,
			"-A OUTPUT -m domain --domain blocked.invalid -j DNAT --to 10.1.2.3:8443\n"
			"-P OUTPUT ACCEPT\n"));
		memset(&q, 0, sizeof(q));
		q.domain = "blocked.invalid";
		q.proto = GWP_ACL_PROTO_TCP;
		assert(gwp_acl_eval_output(a, &q) == GWP_ACL_ACCEPT);
		assert(q.dnat_applied && q.dnat.i4.sin_family == AF_INET);
		assert(inet_ntop(AF_INET, &q.dnat.i4.sin_addr, ip, sizeof(ip)));
		assert(!strcmp(ip, "10.1.2.3") && ntohs(q.dnat.i4.sin_port) == 8443);
		gwp_acl_destroy(a);
	}
}

static void test_comments_and_default_policy(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"# leading comment\n"
		"\n"
		"   \n"
		"-P OUTPUT REJECT   # trailing comment\n"
		"-A OUTPUT -d 8.8.8.8/32 -j ACCEPT\n"));
	s = sa4("8.8.8.8", 53);
	assert(out(a, &s, NULL, 53, GWP_ACL_PROTO_UDP) == GWP_ACL_ACCEPT);
	s = sa4("1.1.1.1", 53);		/* no match -> default REJECT */
	assert(out(a, &s, NULL, 53, GWP_ACL_PROTO_UDP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/* NULL ACL and empty ruleset both allow everything. */
	s = sa4("1.2.3.4", 1);
	assert(out(NULL, &s, NULL, 1, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(in(NULL, &s, 1, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
}

static void test_parse_errors(void)
{
	struct gwp_acl *a;
	static const char *bad[] = {
		"-A INPUT -d 1.2.3.4 -j ACCEPT\n",	    /* -d in INPUT */
		"-A INPUT --dports 80 -j ACCEPT\n",	    /* --dports in INPUT */
		"-A OUTPUT -d 1.2.3.4 -m domain --domain x -j ACCEPT\n", /* d+domain */
		"-A OUTPUT -j BOGUS\n",			    /* bad target */
		"-A OUTPUT -x -j ACCEPT\n",		    /* unknown option */
		"-A OUTPUT -d 1.2.3.4\n",		    /* no -j */
		"-A OUTPUT ! -j REJECT\n",		    /* negate before -j */
		"-P OUTPUT MAYBE\n",			    /* bad policy */
		"-P BOGUS ACCEPT\n",			    /* bad chain */
		"-A OUTPUT -j DNAT\n",			    /* DNAT w/o --to */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to :\n",	    /* empty port */
		"-A OUTPUT -d 1.2.3.4 -j ACCEPT --to :80\n",	    /* --to w/o DNAT */
		"-A OUTPUT -j MARK\n",				    /* MARK w/o --set-mark */
		"-A OUTPUT -j ACCEPT --set-mark 5\n",		    /* --set-mark w/o MARK */
		"-A INPUT -j MARK --set-mark 5\n",		    /* MARK in INPUT */
		"-A OUTPUT -j MARK --set-mark nope\n",		    /* bad mark value */
		"-A OUTPUT -j MARK --set-mark 5 --set-mark 6\n",    /* dup --set-mark */
		"-A OUTPUT -j BIND\n",				    /* BIND w/o src|iface */
		"-A OUTPUT -j ACCEPT --to-source 10.0.0.1\n",	    /* --to-source w/o BIND */
		"-A OUTPUT -j ACCEPT --to-iface eth0\n",	    /* --to-iface w/o BIND */
		"-A INPUT -j BIND --to-iface eth0\n",		    /* BIND in INPUT */
		"-A OUTPUT -j BIND --to-source notanip\n",	    /* bad source */
		"-A OUTPUT -j BIND --to-source 1.1.1.1 --to-source 2.2.2.2\n", /* dup src */
		"-A OUTPUT -j BIND --to-iface toolonginterfacename0\n", /* iface >= 16 */
		"-A INPUT -s 1.2.3.4 -j DNAT --to-destination 5.6.7.8\n", /* DNAT in INPUT */
		"-A OUTPUT -d 999.0.0.1 -j REJECT\n",	    /* bad CIDR */
		"-A OUTPUT -d 1.2.3.4/33 -j REJECT\n",	    /* bad prefix */
		"-A OUTPUT --dports 70000 -j REJECT\n",	    /* port range */
		"-A WEIRD -d 1.2.3.4 -j REJECT\n",	    /* bad chain */
		"garbage line\n",			    /* not -P/-A */
	};
	size_t i;
	int saved, devnull;

	/*
	 * These cases are meant to fail parsing, and the parser logs each bad
	 * line to stderr. Silence stderr for the loop so the expected
	 * diagnostics do not look like test failures in "make test" output.
	 */
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	devnull = open("/dev/null", O_WRONLY);
	if (saved >= 0 && devnull >= 0)
		dup2(devnull, STDERR_FILENO);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		a = (void *)0x1;
		assert(gwp_acl_parse_str(&a, bad[i]) < 0);
	}

	/* --domain-regexp still needs the -m domain module loaded first. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT --domain-regexp x -j REJECT\n") < 0);

	/* -m user is OUTPUT-only; --user needs the module and rejects dupes. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT --user alice -j REJECT\n") < 0);		/* no -m user */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A INPUT -m user --user alice -j REJECT\n") < 0);	/* INPUT */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user a --user b -j REJECT\n") < 0);	/* dup */
#ifndef CONFIG_PCRE
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user-regexp x -j REJECT\n") < 0);	/* no pcre */
#endif
#ifdef CONFIG_PCRE
	/* A malformed pattern, and mixing exact + regexp for one field, fail. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp ( -j REJECT\n") < 0);
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain a --domain-regexp b -j REJECT\n") < 0);
#else
	/* Without --use-pcre the regexp option is rejected outright. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp x -j REJECT\n") < 0);
#endif

	fflush(stderr);
	if (saved >= 0)
		dup2(saved, STDERR_FILENO);
	if (devnull >= 0)
		close(devnull);
	if (saved >= 0)
		close(saved);
}

static void run_tests(void)
{
	size_t i;

	/* Negative cases print the offending line to stderr; run them once. */
	test_parse_errors();

	for (i = 0; i < 200; i++) {
		test_default_ruleset();
		test_ports_and_negation();
		test_input_and_proto();
		test_domain();
		test_domain_regexp();
		test_user();
		test_mark();
		test_bind();
		test_dnat();
		test_comments_and_default_policy();
	}
	printf("All tests passed!\n");
}

int main(void)
{
	run_tests();
	return 0;
}
