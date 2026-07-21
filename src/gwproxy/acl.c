// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * iptables-style ACL: parser, in-memory rule model, and matcher. See acl.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/acl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#ifdef CONFIG_PCRE
#include <pcre2.h>
#endif

enum gwp_acl_action {
	GWP_ACL_ACT_ACCEPT	= 0,
	GWP_ACL_ACT_REJECT	= 1,
	GWP_ACL_ACT_DNAT	= 2,
	/*
	 * Composable modifiers: they record connection state (fwmark, source
	 * bind) and eval keeps matching. Only ACCEPT/REJECT/DNAT terminate.
	 */
	GWP_ACL_ACT_MARK	= 3,
	GWP_ACL_ACT_BIND	= 4,
};

enum gwp_acl_chain {
	GWP_ACL_INPUT		= 0,
	GWP_ACL_OUTPUT		= 1,
};

/* A canonicalised address prefix. IPv4 and v4-mapped IPv6 collapse to is_v4. */
struct gwp_acl_cidr {
	bool		is_v4 : 1;
	uint8_t		bits;
	uint8_t		addr[16];
};

struct gwp_acl_prange {
	uint16_t	lo;
	uint16_t	hi;
};

struct gwp_acl_ports {
	struct gwp_acl_prange	*v;
	size_t			nr;
};

/*
 * A -j DNAT rewrite. The address and port are independent: "--to 1.2.3.4:80"
 * sets both, "--to 1.2.3.4" only the address, and "--to :4444" only the port
 * (leaving the matched target's address untouched).
 */
struct gwp_acl_dnat {
	bool		set_addr : 1;
	bool		set_port : 1;
	uint8_t		family;		/* AF_INET/AF_INET6 when set_addr */
	uint16_t	port;		/* host byte order when set_port */
	uint8_t		addr[16];	/* network bytes when set_addr */
};

/*
 * Ordered to minimise padding: the pointer-aligned members lead, then the
 * address prefixes, then the action payload, then a single bit-field block.
 * Three sets of mutually exclusive fields share unions to keep the struct
 * compact as criteria grow:
 *   - the -m domain value is either an exact string or (on a PCRE build) a
 *     compiled regex, selected by @domain_is_re; likewise -m user / @user_is_re;
 *   - a rule carries exactly one -j action payload -- a DNAT rewrite, a MARK
 *     value, or a BIND spec -- selected by @action (ACCEPT/REJECT carry none).
 * The per-criterion present/negated flags and the small proto/action selectors
 * live in one bit-field block. proto/action use uint8_t so their values
 * round-trip safely (a signed 1-bit field would turn value 1 into -1).
 */
struct gwp_acl_rule {
	struct gwp_acl_rule	*next;
	/* -m domain: exact .str, or compiled .re when @domain_is_re (PCRE). */
	union {
		char		*str;
#ifdef CONFIG_PCRE
		pcre2_code	*re;
#endif
	} domain;
	/* -m user: exact .str, or compiled .re when @user_is_re (PCRE). */
	union {
		char		*str;
#ifdef CONFIG_PCRE
		pcre2_code	*re;
#endif
	} user;
	struct gwp_acl_ports	sports, dports;
	struct gwp_acl_cidr	src, dst;
	/* -j action payload; the live member is selected by @action. */
	union {
		struct gwp_acl_dnat	dnat;	 /* GWP_ACL_ACT_DNAT (--to) */
		uint32_t		setmark; /* GWP_ACL_ACT_MARK (--set-mark) */
		struct gwp_acl_bind	bind;	 /* GWP_ACL_ACT_BIND (--to-*) */
	} act;

	bool			has_src : 1, has_dst : 1, has_domain : 1,
				has_proto : 1, has_sports : 1, has_dports : 1;
	bool			neg_src : 1, neg_dst : 1, neg_domain : 1,
				neg_proto : 1, neg_sports : 1, neg_dports : 1;
	bool			has_user : 1, neg_user : 1;
	bool			domain_is_re : 1;	/* --domain-regexp */
	bool			user_is_re : 1;		/* --user-regexp */
	uint8_t			proto : 1;	/* enum gwp_acl_proto */
	uint8_t			action : 3;	/* enum gwp_acl_action */
};

struct gwp_acl_ruleset {
	struct gwp_acl_rule	*in_head, **in_tail;
	struct gwp_acl_rule	*out_head, **out_tail;
	enum gwp_acl_verdict	in_policy, out_policy;
};

struct gwp_acl {
	struct gwp_acl_ruleset	rs;
	char			*path;
	pthread_rwlock_t	lock;
};

#define ACL_MAX_TOKENS	32

#ifdef CONFIG_PCRE
/*
 * ------------------------------------------------------------------------
 * PCRE2 regexp helpers (--domain-regexp / --user-regexp)
 * ------------------------------------------------------------------------
 *
 * Patterns are matched raw/unanchored -- the user writes ^...$ if they want a
 * full-string match. Matching runs against attacker-influenced hostnames and
 * usernames, so a shared match context caps the work (match + backtracking
 * depth limits) to keep a pathological pattern from becoming a ReDoS.
 */
static pthread_once_t g_regex_once = PTHREAD_ONCE_INIT;
static pcre2_match_context *g_regex_mctx;

static void regex_ctx_init(void)
{
	g_regex_mctx = pcre2_match_context_create(NULL);
	if (g_regex_mctx) {
		pcre2_set_match_limit(g_regex_mctx, 100000);
		pcre2_set_depth_limit(g_regex_mctx, 1000);
	}
}

/* Compile @pat, JIT-compiling it when supported. Returns NULL on error. */
static pcre2_code *regex_compile(const char *pat, bool caseless)
{
	uint32_t opts = caseless ? PCRE2_CASELESS : 0;
	PCRE2_SIZE erroff;
	pcre2_code *re;
	int errcode;

	pthread_once(&g_regex_once, regex_ctx_init);
	re = pcre2_compile((PCRE2_SPTR)pat, PCRE2_ZERO_TERMINATED, opts,
			   &errcode, &erroff, NULL);
	if (!re)
		return NULL;
	pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);	/* best effort */
	return re;
}

/*
 * True if @re matches @subj. Fails closed (no match) on OOM or if the match hits
 * the configured limits (a would-be ReDoS is treated as a non-match, not an
 * accept).
 */
static bool regex_match(const pcre2_code *re, const char *subj)
{
	pcre2_match_data *md;
	int rc;

	if (!subj)
		return false;
	md = pcre2_match_data_create(1, NULL);
	if (!md)
		return false;
	rc = pcre2_match(re, (PCRE2_SPTR)subj, PCRE2_ZERO_TERMINATED, 0, 0,
			 md, g_regex_mctx);
	pcre2_match_data_free(md);
	return rc >= 0;
}
#endif /* CONFIG_PCRE */

/*
 * ------------------------------------------------------------------------
 * Address / port helpers
 * ------------------------------------------------------------------------
 */

/* Canonicalise a sockaddr to (is_v4, pointer to its 4- or 16-byte IP). */
static void canon_ip(const struct gwp_sockaddr *a, bool *is_v4,
		     const uint8_t **ip)
{
	if (a->sa.sa_family == AF_INET) {
		*is_v4 = true;
		*ip = (const uint8_t *)&a->i4.sin_addr;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&a->i6.sin6_addr)) {
		*is_v4 = true;
		*ip = &a->i6.sin6_addr.s6_addr[12];
		return;
	}
	*is_v4 = false;
	*ip = a->i6.sin6_addr.s6_addr;
}

/* Does @ip match the first @bits bits of network prefix @net? */
static bool prefix_match(const uint8_t *ip, const uint8_t *net, uint8_t bits)
{
	uint8_t full = bits / 8, rem = bits % 8;

	if (full && memcmp(ip, net, full))
		return false;
	if (rem) {
		uint8_t mask = (uint8_t)(0xffu << (8 - rem));
		if ((ip[full] & mask) != (net[full] & mask))
			return false;
	}
	return true;
}

/* Zero every bit of @addr beyond the first @bits, over @len bytes. */
static void mask_addr(uint8_t *addr, uint8_t bits, size_t len)
{
	size_t full = bits / 8, i;
	uint8_t rem = bits % 8;

	if (rem)
		addr[full++] &= (uint8_t)(0xffu << (8 - rem));
	for (i = full; i < len; i++)
		addr[i] = 0;
}

/* Parse "IP" or "IP/prefixlen" into a canonicalised prefix. */
static int parse_cidr(const char *s, struct gwp_acl_cidr *c)
{
	char buf[INET6_ADDRSTRLEN + 8];
	unsigned long bits;
	char *slash;
	uint8_t v4[4], v6[16];

	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	slash = strchr(buf, '/');
	if (slash)
		*slash = '\0';

	memset(c, 0, sizeof(*c));
	if (inet_pton(AF_INET, buf, v4) == 1) {
		c->is_v4 = true;
		memcpy(c->addr, v4, 4);
		bits = 32;
	} else if (inet_pton(AF_INET6, buf, v6) == 1) {
		c->is_v4 = false;
		memcpy(c->addr, v6, 16);
		bits = 128;
	} else {
		return -EINVAL;
	}

	if (slash) {
		char *end;

		errno = 0;
		bits = strtoul(slash + 1, &end, 10);
		if (errno || *end || slash[1] == '\0')
			return -EINVAL;
		if (bits > (c->is_v4 ? 32u : 128u))
			return -EINVAL;
	}

	c->bits = (uint8_t)bits;
	mask_addr(c->addr, c->bits, c->is_v4 ? 4 : 16);
	return 0;
}

static bool cidr_match(const struct gwp_acl_cidr *c,
		       const struct gwp_sockaddr *addr)
{
	const uint8_t *ip;
	bool is_v4;

	canon_ip(addr, &is_v4, &ip);
	if (is_v4 != c->is_v4)
		return false;
	return prefix_match(ip, c->addr, c->bits);
}

/* Parse a port set: "80" | "1000-2000" | "80,443,1000-2000". */
static int parse_ports(const char *s, struct gwp_acl_ports *p)
{
	char buf[256];
	char *save = NULL, *tok;
	size_t cap = 0;

	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	p->v = NULL;
	p->nr = 0;
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		unsigned long lo, hi;
		char *dash, *end;

		dash = strchr(tok, '-');
		if (dash)
			*dash = '\0';

		errno = 0;
		lo = strtoul(tok, &end, 10);
		if (errno || *end || tok[0] == '\0' || lo > 65535)
			goto einval;
		if (dash) {
			errno = 0;
			hi = strtoul(dash + 1, &end, 10);
			if (errno || *end || dash[1] == '\0' || hi > 65535 ||
			    hi < lo)
				goto einval;
		} else {
			hi = lo;
		}

		if (p->nr == cap) {
			struct gwp_acl_prange *nv;

			cap = cap ? cap * 2 : 4;
			nv = realloc(p->v, cap * sizeof(*nv));
			if (!nv)
				goto enomem;
			p->v = nv;
		}
		p->v[p->nr].lo = (uint16_t)lo;
		p->v[p->nr].hi = (uint16_t)hi;
		p->nr++;
	}

	if (!p->nr)
		goto einval;
	return 0;

einval:
	free(p->v);
	p->v = NULL;
	p->nr = 0;
	return -EINVAL;
enomem:
	free(p->v);
	p->v = NULL;
	p->nr = 0;
	return -ENOMEM;
}

static bool ports_match(const struct gwp_acl_ports *p, uint16_t port)
{
	size_t i;

	for (i = 0; i < p->nr; i++)
		if (port >= p->v[i].lo && port <= p->v[i].hi)
			return true;
	return false;
}

/*
 * Parse a -j DNAT target. The address is optional, so all of these are valid:
 *   "1.2.3.4"        rewrite the address, keep the port
 *   "1.2.3.4:5678"   rewrite both
 *   ":4444"          rewrite only the port, keep the address
 *   "[2001:db8::1]:5678" / "2001:db8::1"   IPv6 forms (brackets to add a port)
 */
static int parse_dnat(const char *s, struct gwp_acl_dnat *d)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *colon = NULL, *host = buf;
	bool have_port = false;

	memset(d, 0, sizeof(*d));
	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	if (buf[0] == '[') {			/* [v6] or [v6]:port */
		char *rb = strchr(buf, ']');

		if (!rb)
			return -EINVAL;
		*rb = '\0';
		host = buf + 1;
		if (rb[1] == ':') {
			colon = rb + 1;
			have_port = true;
		} else if (rb[1] != '\0') {
			return -EINVAL;
		}
	} else {
		colon = strrchr(buf, ':');
		/*
		 * A single ':' is a "host:port" (or ":port") separator; a bare
		 * IPv6 literal has several colons and needs brackets for a port,
		 * so treat multiple colons as part of the address.
		 */
		if (colon && strchr(buf, ':') == colon)
			have_port = true;
		else
			colon = NULL;
	}

	if (have_port) {
		unsigned long port;
		char *end;

		*colon = '\0';
		errno = 0;
		port = strtoul(colon + 1, &end, 10);
		if (errno || *end || colon[1] == '\0' || port > 65535)
			return -EINVAL;
		d->port = (uint16_t)port;
		d->set_port = true;
	}

	if (host[0] == '\0')		/* port-only rewrite: address unchanged */
		return d->set_port ? 0 : -EINVAL;

	if (inet_pton(AF_INET, host, d->addr) == 1)
		d->family = AF_INET;
	else if (inet_pton(AF_INET6, host, d->addr) == 1)
		d->family = AF_INET6;
	else
		return -EINVAL;
	d->set_addr = true;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Parser
 * ------------------------------------------------------------------------
 */

static void free_rule(struct gwp_acl_rule *r)
{
#ifdef CONFIG_PCRE
	if (r->domain_is_re)
		pcre2_code_free(r->domain.re);
	else
		free(r->domain.str);
	if (r->user_is_re)
		pcre2_code_free(r->user.re);
	else
		free(r->user.str);
#else
	free(r->domain.str);
	free(r->user.str);
#endif
	free(r->sports.v);
	free(r->dports.v);
	free(r);
}

static void free_rule_list(struct gwp_acl_rule *r)
{
	while (r) {
		struct gwp_acl_rule *next = r->next;

		free_rule(r);
		r = next;
	}
}

static void ruleset_init(struct gwp_acl_ruleset *rs)
{
	rs->in_head = NULL;
	rs->in_tail = &rs->in_head;
	rs->out_head = NULL;
	rs->out_tail = &rs->out_head;
	rs->in_policy = GWP_ACL_ACCEPT;
	rs->out_policy = GWP_ACL_ACCEPT;
}

static void ruleset_free(struct gwp_acl_ruleset *rs)
{
	free_rule_list(rs->in_head);
	free_rule_list(rs->out_head);
	ruleset_init(rs);
}

static bool eq(const char *a, const char *b1, const char *b2)
{
	return !strcmp(a, b1) || (b2 && !strcmp(a, b2));
}

/* Parse a 32-bit unsigned value (decimal, or 0x hex) into @out; -1 on error. */
static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long v;
	char *end;

	if (!*s)
		return -1;
	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || *end || v > 0xffffffffUL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

/* Parse a decimal port (1..65535, or 0 for "ephemeral") into @out; -1 bad. */
static int parse_port_num(const char *s, uint16_t *out)
{
	unsigned long v;
	char *end;

	if (!*s)
		return -1;
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || *end || v > 65535)
		return -1;
	*out = (uint16_t)v;
	return 0;
}

/*
 * Parse a -j BIND --to-source argument (a literal source address, optionally
 * with a port) into @out: "ip", "ip:port", "[v6]:port", or a bare IPv6 literal.
 * No DNS -- acl.c is self-contained. Returns 0 on success, -1 on error.
 */
static int parse_source(const char *s, struct gwp_sockaddr *out)
{
	char host[64];
	const char *colon;
	uint16_t port = 0;
	struct in6_addr a6;
	struct in_addr a4;

	memset(out, 0, sizeof(*out));

	if (*s == '[') {			/* [v6] or [v6]:port */
		const char *end = strchr(s, ']');
		size_t n;

		if (!end)
			return -1;
		n = (size_t)(end - s - 1);
		if (n >= sizeof(host))
			return -1;
		memcpy(host, s + 1, n);
		host[n] = '\0';
		if (inet_pton(AF_INET6, host, &a6) != 1)
			return -1;
		s = end + 1;
		if (*s == ':') {
			if (parse_port_num(s + 1, &port))
				return -1;
		} else if (*s) {
			return -1;
		}
		out->i6.sin6_family = AF_INET6;
		out->i6.sin6_addr = a6;
		out->i6.sin6_port = htons(port);
		return 0;
	}

	if (inet_pton(AF_INET6, s, &a6) == 1) {	/* bare IPv6 literal, no port */
		out->i6.sin6_family = AF_INET6;
		out->i6.sin6_addr = a6;
		return 0;
	}

	colon = strchr(s, ':');			/* IPv4, optional :port */
	if (colon) {
		size_t n = (size_t)(colon - s);

		if (n >= sizeof(host))
			return -1;
		memcpy(host, s, n);
		host[n] = '\0';
		if (parse_port_num(colon + 1, &port))
			return -1;
	} else {
		if (strlen(s) >= sizeof(host))
			return -1;
		strcpy(host, s);
	}
	if (inet_pton(AF_INET, host, &a4) != 1)
		return -1;
	out->i4.sin_family = AF_INET;
	out->i4.sin_addr = a4;
	out->i4.sin_port = htons(port);
	return 0;
}

/* Tokenise @line in place on whitespace into @tok; returns token count or -1. */
static int tokenise(char *line, char **tok)
{
	char *save = NULL, *t;
	int n = 0;

	for (t = strtok_r(line, " \t\r", &save); t;
	     t = strtok_r(NULL, " \t\r", &save)) {
		if (n == ACL_MAX_TOKENS)
			return -1;
		tok[n++] = t;
	}
	return n;
}

static int parse_policy(struct gwp_acl_ruleset *rs, char **tok, int n)
{
	enum gwp_acl_verdict v;

	if (n != 3)
		return -EINVAL;
	if (!strcmp(tok[2], "ACCEPT"))
		v = GWP_ACL_ACCEPT;
	else if (!strcmp(tok[2], "REJECT"))
		v = GWP_ACL_REJECT;
	else
		return -EINVAL;

	if (!strcmp(tok[1], "INPUT"))
		rs->in_policy = v;
	else if (!strcmp(tok[1], "OUTPUT"))
		rs->out_policy = v;
	else
		return -EINVAL;
	return 0;
}

/* Consume the value token following an option; advances *i. */
static const char *next_val(char **tok, int n, int *i)
{
	if (*i + 1 >= n)
		return NULL;
	*i += 1;
	return tok[*i];
}

static int parse_rule(struct gwp_acl_ruleset *rs, char **tok, int n)
{
	struct gwp_acl_rule *r;
	enum gwp_acl_chain chain;
	bool neg = false, m_domain = false, m_user = false, have_jump = false;
	/* At most one -j action payload group may be present (they share a union). */
	bool have_to = false, have_setmark = false;
	bool have_src = false, have_iface = false;
	const char *v;
	int i, ret = -EINVAL;

	if (n < 2)
		return -EINVAL;
	if (!strcmp(tok[1], "INPUT"))
		chain = GWP_ACL_INPUT;
	else if (!strcmp(tok[1], "OUTPUT"))
		chain = GWP_ACL_OUTPUT;
	else
		return -EINVAL;

	r = calloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;

	for (i = 2; i < n; i++) {
		const char *o = tok[i];

		if (!strcmp(o, "!")) {
			if (neg)
				goto out;
			neg = true;
			continue;
		}

		if (eq(o, "-s", "--source")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_src || parse_cidr(v, &r->src))
				goto out;
			r->has_src = true;
			r->neg_src = neg;
		} else if (eq(o, "-d", "--destination")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !v || r->has_dst ||
			    r->has_domain || parse_cidr(v, &r->dst))
				goto out;
			r->has_dst = true;
			r->neg_dst = neg;
		} else if (!strcmp(o, "-m")) {
			v = next_val(tok, n, &i);
			if (!v || neg)
				goto out;
			if (!strcmp(v, "domain")) {
				m_domain = true;
			} else if (!strcmp(v, "user")) {
				if (chain != GWP_ACL_OUTPUT)
					goto out;	/* -m user is OUTPUT-only */
				m_user = true;
			} else {
				goto out;
			}
			continue;	/* -m is not itself negatable */
		} else if (!strcmp(o, "--domain")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_domain || !v ||
			    r->has_domain || r->has_dst)
				goto out;
			r->domain.str = strdup(v);
			if (!r->domain.str) {
				ret = -ENOMEM;
				goto out;
			}
			r->has_domain = true;
			r->neg_domain = neg;
		} else if (!strcmp(o, "--domain-regexp")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_domain || !v ||
			    r->has_domain || r->has_dst)
				goto out;
#ifdef CONFIG_PCRE
			r->domain.re = regex_compile(v, /*caseless=*/true);
			if (!r->domain.re)
				goto out;
			r->domain_is_re = true;
			r->has_domain = true;
			r->neg_domain = neg;
#else
			/* --domain-regexp requires a --use-pcre build. */
			ret = -ENOSYS;
			goto out;
#endif
		} else if (!strcmp(o, "--user")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_user || !v ||
			    r->has_user)
				goto out;
			r->user.str = strdup(v);
			if (!r->user.str) {
				ret = -ENOMEM;
				goto out;
			}
			r->has_user = true;
			r->neg_user = neg;
		} else if (!strcmp(o, "--user-regexp")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_user || !v ||
			    r->has_user)
				goto out;
#ifdef CONFIG_PCRE
			/* Usernames are case-sensitive, unlike hostnames. */
			r->user.re = regex_compile(v, /*caseless=*/false);
			if (!r->user.re)
				goto out;
			r->user_is_re = true;
			r->has_user = true;
			r->neg_user = neg;
#else
			/* --user-regexp requires a --use-pcre build. */
			ret = -ENOSYS;
			goto out;
#endif
		} else if (eq(o, "-p", "--protocol")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_proto)
				goto out;
			if (!strcmp(v, "tcp"))
				r->proto = GWP_ACL_PROTO_TCP;
			else if (!strcmp(v, "udp"))
				r->proto = GWP_ACL_PROTO_UDP;
			else
				goto out;
			r->has_proto = true;
			r->neg_proto = neg;
		} else if (!strcmp(o, "--sports")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_sports || parse_ports(v, &r->sports))
				goto out;
			r->has_sports = true;
			r->neg_sports = neg;
		} else if (!strcmp(o, "--dports")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !v || r->has_dports ||
			    parse_ports(v, &r->dports))
				goto out;
			r->has_dports = true;
			r->neg_dports = neg;
		} else if (eq(o, "-j", "--jump")) {
			if (neg || have_jump)
				goto out;
			v = next_val(tok, n, &i);
			if (!v)
				goto out;
			if (!strcmp(v, "ACCEPT")) {
				r->action = GWP_ACL_ACT_ACCEPT;
			} else if (!strcmp(v, "REJECT")) {
				r->action = GWP_ACL_ACT_REJECT;
			} else if (!strcmp(v, "DNAT")) {
				r->action = GWP_ACL_ACT_DNAT;
			} else if (!strcmp(v, "MARK")) {
				if (chain != GWP_ACL_OUTPUT)  /* egress sockets */
					goto out;
				r->action = GWP_ACL_ACT_MARK;
			} else if (!strcmp(v, "BIND")) {
				if (chain != GWP_ACL_OUTPUT)  /* egress sockets */
					goto out;
				r->action = GWP_ACL_ACT_BIND;
			} else {
				goto out;
			}
			have_jump = true;
		} else if (eq(o, "--to-destination", "--to")) {
			/* DNAT payload: no other action group may share the union. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    have_iface || parse_dnat(v, &r->act.dnat))
				goto out;
			have_to = true;
		} else if (!strcmp(o, "--set-mark")) {
			/* MARK payload: mutually exclusive with DNAT/BIND. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    have_iface || parse_u32(v, &r->act.setmark))
				goto out;
			have_setmark = true;
		} else if (!strcmp(o, "--to-source")) {
			/* BIND payload: may pair with --to-iface, not DNAT/MARK. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    parse_source(v, &r->act.bind.src))
				goto out;
			r->act.bind.have_src = true;
			have_src = true;
		} else if (!strcmp(o, "--to-iface")) {
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_iface ||
			    strlen(v) >= sizeof(r->act.bind.iface))
				goto out;
			memcpy(r->act.bind.iface, v, strlen(v) + 1);
			have_iface = true;
		} else {
			goto out;		/* unknown option */
		}

		neg = false;
	}

	if (neg || !have_jump)
		goto out;

	/*
	 * Exactly the action's own payload group may be present. The cross-group
	 * guards above already reject mixing DNAT/MARK/BIND options, so here we
	 * only require the matching group and forbid a stray one on an action
	 * that takes no payload (ACCEPT/REJECT).
	 */
	switch (r->action) {
	case GWP_ACL_ACT_DNAT:
		if (chain != GWP_ACL_OUTPUT)	/* DNAT rewrites targets */
			goto out;
		if (!have_to)			/* DNAT needs --to */
			goto out;
		break;
	case GWP_ACL_ACT_MARK:
		if (!have_setmark)		/* MARK needs --set-mark */
			goto out;
		break;
	case GWP_ACL_ACT_BIND:
		if (!have_src && !have_iface)	/* BIND needs a source or iface */
			goto out;
		r->act.bind.set = true;
		break;
	default:				/* ACCEPT / REJECT: no payload */
		if (have_to || have_setmark || have_src || have_iface)
			goto out;
		break;
	}

	if (chain == GWP_ACL_INPUT) {
		*rs->in_tail = r;
		rs->in_tail = &r->next;
	} else {
		*rs->out_tail = r;
		rs->out_tail = &r->next;
	}
	return 0;

out:
	free_rule(r);
	return ret;
}

static int parse_line(struct gwp_acl_ruleset *rs, char *line)
{
	char *tok[ACL_MAX_TOKENS];
	char *hash;
	int n;

	hash = strchr(line, '#');
	if (hash)
		*hash = '\0';

	n = tokenise(line, tok);
	if (n < 0)
		return -EINVAL;
	if (n == 0)
		return 0;		/* blank / comment-only */

	if (!strcmp(tok[0], "-P"))
		return parse_policy(rs, tok, n);
	if (!strcmp(tok[0], "-A"))
		return parse_rule(rs, tok, n);
	return -EINVAL;
}

static int parse_text(struct gwp_acl_ruleset *rs, const char *text)
{
	char *copy, *cursor, *line;
	unsigned lineno = 0;
	int r = 0;

	ruleset_init(rs);

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	cursor = copy;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		lineno++;
		r = parse_line(rs, line);
		if (r) {
			fprintf(stderr, "acl: parse error on line %u: %s\n",
				lineno, strerror(-r));
			ruleset_free(rs);
			break;
		}
	}

	free(copy);
	return r;
}

static int read_file(const char *path, char **out)
{
	long sz;
	char *buf;
	size_t rd;
	FILE *fp;

	fp = fopen(path, "rb");
	if (!fp)
		return -errno;

	if (fseek(fp, 0, SEEK_END) || (sz = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET)) {
		fclose(fp);
		return -EIO;
	}

	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return -ENOMEM;
	}

	rd = fread(buf, 1, (size_t)sz, fp);
	buf[rd] = '\0';
	fclose(fp);
	*out = buf;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------
 */

int gwp_acl_parse_str(struct gwp_acl **out, const char *text)
{
	struct gwp_acl *acl;
	int r;

	acl = calloc(1, sizeof(*acl));
	if (!acl)
		return -ENOMEM;

	r = pthread_rwlock_init(&acl->lock, NULL);
	if (r) {
		free(acl);
		return -r;
	}

	r = parse_text(&acl->rs, text);
	if (r) {
		pthread_rwlock_destroy(&acl->lock);
		free(acl);
		return r;
	}

	*out = acl;
	return 0;
}

int gwp_acl_create(struct gwp_acl **out, const char *path)
{
	struct gwp_acl *acl;
	char *text;
	int r;

	if (!path || !path[0]) {
		*out = NULL;
		return 0;
	}

	r = read_file(path, &text);
	if (r)
		return r;

	r = gwp_acl_parse_str(&acl, text);
	free(text);
	if (r)
		return r;

	acl->path = strdup(path);
	if (!acl->path) {
		gwp_acl_destroy(acl);
		return -ENOMEM;
	}

	*out = acl;
	return 0;
}

int gwp_acl_reload(struct gwp_acl *acl)
{
	struct gwp_acl_ruleset rs;
	char *text;
	int r;

	if (!acl || !acl->path)
		return -EINVAL;

	r = read_file(acl->path, &text);
	if (r)
		return r;

	r = parse_text(&rs, text);
	free(text);
	if (r)
		return r;			/* keep the old rules */

	pthread_rwlock_wrlock(&acl->lock);
	ruleset_free(&acl->rs);
	acl->rs = rs;
	/* The tail pointers in @rs point at @rs's stack head slots when a chain
	 * is empty; re-anchor them to the live struct. */
	if (!acl->rs.in_head)
		acl->rs.in_tail = &acl->rs.in_head;
	if (!acl->rs.out_head)
		acl->rs.out_tail = &acl->rs.out_head;
	pthread_rwlock_unlock(&acl->lock);
	return 0;
}

void gwp_acl_destroy(struct gwp_acl *acl)
{
	if (!acl)
		return;
	ruleset_free(&acl->rs);
	pthread_rwlock_destroy(&acl->lock);
	free(acl->path);
	free(acl);
}

/*
 * ------------------------------------------------------------------------
 * Matcher
 * ------------------------------------------------------------------------
 */

/*
 * A single match criterion. @present is the rule's has_* flag; @matched is
 * whether the value matched; @negate is the rule's neg_* flag. The criterion is
 * satisfied when it is absent, or present with (matched XOR negated). Adding a
 * new criterion to rule_matches() is then a one-liner.
 *
 * @matched is computed by the caller and so is evaluated even when @present is
 * false: it must be side-effect-free and safe to compute for a rule that does
 * not set the criterion (e.g. guard a pointer deref on the rule field, not just
 * the query field).
 */
static bool crit_ok(bool present, bool matched, bool negate)
{
	return !present || (matched != negate);
}

/*
 * True if rule @r's -m domain criterion matches the requested hostname @dom
 * (exact, case-insensitive; or PCRE when --domain-regexp was used). Returns
 * false for a NULL @dom so a literal-IP request never matches a domain rule.
 */
static bool domain_match(const struct gwp_acl_rule *r, const char *dom)
{
	if (!dom)
		return false;
#ifdef CONFIG_PCRE
	if (r->domain_is_re)
		return r->domain.re && regex_match(r->domain.re, dom);
#endif
	return r->domain.str && !strcasecmp(dom, r->domain.str);
}

/*
 * True if rule @r's -m user criterion matches the authenticated username @user
 * (exact, case-sensitive; or PCRE when --user-regexp was used). Returns false
 * for a NULL @user so an unauthenticated connection never matches a user rule.
 */
static bool user_match(const struct gwp_acl_rule *r, const char *user)
{
	if (!user)
		return false;
#ifdef CONFIG_PCRE
	if (r->user_is_re)
		return r->user.re && regex_match(r->user.re, user);
#endif
	return r->user.str && !strcmp(user, r->user.str);
}

static bool rule_matches(const struct gwp_acl_rule *r,
			 const struct gwp_acl_req *q)
{
	/*
	 * Target-dependent criteria (-d, --dports) cannot be evaluated for a
	 * domain-only request (socks5h remote-DNS: no resolved IP, @dport unset).
	 * Such a rule matches NEITHER polarity -- otherwise crit_ok would let a
	 * negated "! -d"/"! --dports" flip the unknown into a match and fail open
	 * (e.g. an allow-by-exclusion rule bypassing an internal-range REJECT).
	 * -m domain / -m user still evaluate here (domain/user are known).
	 */
	if (!q->target && (r->has_dst || r->has_dports))
		return false;

	return crit_ok(r->has_src,
		       q->client && cidr_match(&r->src, q->client), r->neg_src) &&
	       crit_ok(r->has_dst,
		       q->target && cidr_match(&r->dst, q->target), r->neg_dst) &&
	       crit_ok(r->has_domain, domain_match(r, q->domain),
		       r->neg_domain) &&
	       crit_ok(r->has_user, user_match(r, q->user), r->neg_user) &&
	       crit_ok(r->has_proto, q->proto == r->proto, r->neg_proto) &&
	       crit_ok(r->has_sports, ports_match(&r->sports, q->sport),
		       r->neg_sports) &&
	       crit_ok(r->has_dports, ports_match(&r->dports, q->dport),
		       r->neg_dports);
}

/* Read a sockaddr's port (host byte order) regardless of family. */
static uint16_t sa_port(const struct gwp_sockaddr *sa)
{
	return ntohs(sa->sa.sa_family == AF_INET ? sa->i4.sin_port
						 : sa->i6.sin6_port);
}

/*
 * Compute the effective rewritten destination for a matched DNAT rule into
 * @req->dnat. The address and port are taken from the rule where set, otherwise
 * carried over from the matched target (@req->target); a port-only rewrite thus
 * keeps the original address. If neither the rule nor the request supplies an
 * address, @req->dnat is left with family 0 (no usable rewrite -- the caller,
 * which only DNATs concrete targets, ignores it).
 */
static void apply_dnat(struct gwp_acl_req *req, const struct gwp_acl_dnat *d)
{
	const struct gwp_sockaddr *base = req->target;
	struct gwp_sockaddr out;
	uint16_t port;
	int fam;

	memset(&out, 0, sizeof(out));
	fam = d->set_addr ? d->family : (base ? base->sa.sa_family : 0);
	if (d->set_port)
		port = d->port;
	else
		port = base ? sa_port(base) : 0;

	if (fam == AF_INET) {
		out.i4.sin_family = AF_INET;
		if (d->set_addr)
			memcpy(&out.i4.sin_addr, d->addr, 4);
		else
			out.i4.sin_addr = base->i4.sin_addr;
		out.i4.sin_port = htons(port);
	} else if (fam == AF_INET6) {
		out.i6.sin6_family = AF_INET6;
		if (d->set_addr)
			memcpy(&out.i6.sin6_addr, d->addr, 16);
		else
			out.i6.sin6_addr = base->i6.sin6_addr;
		out.i6.sin6_port = htons(port);
	}

	req->dnat = out;
	req->dnat_applied = true;
}

/*
 * Walk @head, returning the first terminal verdict. DNAT rewrites @req->dnat;
 * MARK is a composable modifier that records @req->mark and keeps matching.
 */
static enum gwp_acl_verdict eval_chain(const struct gwp_acl_rule *head,
				       enum gwp_acl_verdict policy,
				       struct gwp_acl_req *req)
{
	const struct gwp_acl_rule *r;

	for (r = head; r; r = r->next) {
		if (!rule_matches(r, req))
			continue;

		switch (r->action) {
		case GWP_ACL_ACT_MARK:
			/*
			 * Modifier: record the fwmark and keep matching. A later
			 * MARK overrides it; a terminal rule (or the policy) then
			 * decides the verdict.
			 */
			req->mark = r->act.setmark;
			req->mark_set = true;
			continue;
		case GWP_ACL_ACT_BIND:
			/* Modifier: record the source/iface bind, keep matching. */
			req->bind = r->act.bind;
			continue;
		case GWP_ACL_ACT_DNAT:
			/*
			 * DNAT is terminal (like iptables' nat table): record
			 * the rewrite and accept, so later rules cannot re-match
			 * or override it.
			 */
			apply_dnat(req, &r->act.dnat);
			return GWP_ACL_ACCEPT;
		case GWP_ACL_ACT_REJECT:
			return GWP_ACL_REJECT;
		default: /* GWP_ACL_ACT_ACCEPT */
			return GWP_ACL_ACCEPT;
		}
	}
	return policy;
}

enum gwp_acl_verdict gwp_acl_eval_output(struct gwp_acl *acl,
					 struct gwp_acl_req *req)
{
	enum gwp_acl_verdict verdict;

	req->dnat_applied = false;
	req->mark_set = false;
	req->bind.set = false;
	if (!acl)
		return GWP_ACL_ACCEPT;

	pthread_rwlock_rdlock(&acl->lock);
	verdict = eval_chain(acl->rs.out_head, acl->rs.out_policy, req);
	pthread_rwlock_unlock(&acl->lock);
	return verdict;
}

enum gwp_acl_verdict gwp_acl_eval_input(struct gwp_acl *acl,
					struct gwp_acl_req *req)
{
	enum gwp_acl_verdict verdict;

	if (!acl)
		return GWP_ACL_ACCEPT;

	pthread_rwlock_rdlock(&acl->lock);
	verdict = eval_chain(acl->rs.in_head, acl->rs.in_policy, req);
	pthread_rwlock_unlock(&acl->lock);
	return verdict;
}
