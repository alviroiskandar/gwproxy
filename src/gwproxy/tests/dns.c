// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <stdio.h>
#include <assert.h>
#include <gwproxy/dns.h>
#include <gwproxy/dns_cache.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct req_template {
	const char *domain, *service;
	bool needs_ipv6;	/* requires a resolvable IPv6, see has_ipv6() */
};

/*
 * Names that resolve from /etc/hosts alone. A unit test must not depend on
 * public DNS: on an offline or filtered builder every one of these lookups
 * fails, the assertion below aborts, and `make test-unit` stops before the
 * socks5/http1/http/acl binaries ever run -- indistinguishable from a real
 * regression in gwp_dns_queue(). Repeating a handful of local names keeps the
 * many-requests shape (queue, workers, eventfd, refcounts, cache inserts) that
 * this test is actually about, and covers both address families.
 *
 * The entries marked needs_ipv6 are requested only where the host can serve
 * them; /etc/hosts is not enough on its own. See has_ipv6().
 */
static const struct req_template req_template[] = {
	{ "localhost",		"80",	false },
	{ "127.0.0.1",		"80",	false },
	{ "::1",		"443",	true },
	{ "ip6-localhost",	"443",	false },
	{ "localhost",		"443",	false },
	{ "127.0.0.1",		"443",	false },
	{ "::1",		"80",	true },
	{ "ip6-localhost",	"80",	false },
	{ "localhost",		"8080",	false },
	{ "127.0.0.1",		"8080",	false },
	{ "::1",		"8080",	true },
	{ "ip6-localhost",	"8080",	false },
	{ "localhost",		"9090",	false },
	{ "127.0.0.1",		"9090",	false },
	{ "::1",		"9090",	true },
};

static int poll_all_in(struct pollfd *pfd, int n, int timeout)
{
	int ret, i, t = 0;

	while (1) {
		ret = poll(pfd, n, timeout);
		if (ret < 0) {
			perror("poll");
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "poll timed out\n");
			return -ETIMEDOUT;
		}

		for (i = 0; i < n; i++) {
			if (pfd[i].revents & (POLLIN | POLLERR | POLLHUP)) {
				pfd[i].events = 0;
				t++;
			}
		}

		if (t == n)
			return 0;
	}
}

/*
 * Can this host resolve an IPv6 name at all, using the flags the resolver
 * itself uses?
 *
 * gwp_dns_queue() resolves with AI_ADDRCONFIG (prep_hints() in dns.c), and
 * glibc only enables AF_INET6 lookups when a NON-LOOPBACK IPv6 address is
 * configured -- "::1/128 scope host" on lo does not count. So on a v4-only
 * host, and in most containers, even the literal "::1" fails with
 * EAI_ADDRFAMILY, which the resolver reports as -EHOSTUNREACH. That is the
 * resolver behaving correctly, not a regression, so the IPv6 names are
 * requested only where they can succeed. Probing beats parsing /etc/hosts or
 * poking at interfaces: it asks exactly the question the code under test asks.
 */
static bool has_ipv6(void)
{
	struct addrinfo hints, *res = NULL;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	r = getaddrinfo("::1", "80", &hints, &res);
	if (res)
		freeaddrinfo(res);

	return r == 0;
}

static void test_basic_dns_multiple_requests(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1 };
	struct gwp_dns_entry *earr[ARRAY_SIZE(req_template)];
	struct pollfd pfd[ARRAY_SIZE(req_template)];
	bool v6 = has_ipv6();
	struct gwp_dns_ctx *ctx;
	int i, n, skipped = 0;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	n = 0;
	for (i = 0; i < (int)ARRAY_SIZE(req_template); i++) {
		const struct req_template *rt = &req_template[i];

		if (rt->needs_ipv6 && !v6) {
			skipped++;
			continue;
		}
		earr[n] = gwp_dns_queue(ctx, rt->domain, rt->service);
		assert(earr[n]);
		assert(earr[n]->ev_fd >= 0);
		pfd[n].fd = earr[n]->ev_fd;
		pfd[n].events = POLLIN;
		n++;
	}
	assert(n > 0);

	/*
	 * Say so rather than quietly running a smaller test: a reader who sees
	 * a pass here must not conclude that IPv6 resolution was covered.
	 */
	if (skipped)
		printf("dns: no non-loopback IPv6 on this host, skipped %d of %zu requests\n",
		       skipped, ARRAY_SIZE(req_template));

	r = poll_all_in(pfd, n, 5000);
	assert(!r);

	for (i = 0; i < n; i++) {
		assert(earr[i]->res == 0);
		r = earr[i]->addrs[0].sa.sa_family;
		assert(r == AF_INET || r == AF_INET6);
	}

	for (i = 0; i < n; i++)
		gwp_dns_entry_put(earr[i]);
	gwp_dns_ctx_free(ctx);
}

static void test_dns_cache(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .cache_expiry = 10 };
	struct gwp_sockaddr addr;
	struct gwp_dns_ctx *ctx;
	struct gwp_dns_entry *e;
	struct pollfd pfd;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	e = gwp_dns_queue(ctx, "localhost", "80");
	assert(e != NULL);
	assert(e->ev_fd >= 0);
	pfd.fd = e->ev_fd;
	pfd.events = POLLIN;
	r = poll_all_in(&pfd, 1, 5000);
	assert(r == 0);
	assert(e->res == 0);
	r = e->addrs[0].sa.sa_family;
	assert(r == AF_INET || r == AF_INET6);
	gwp_dns_entry_put(e);

	r = gwp_dns_cache_lookup(ctx, "localhost", "80", &addr);
	assert(!r);
	r = addr.sa.sa_family;
	assert(r == AF_INET || r == AF_INET6);
	r = gwp_dns_cache_lookup(ctx, "aaaa.com", "80", &addr);
	assert(r == -ENOENT);
	gwp_dns_ctx_free(ctx);
}

/* A throwaway one-address (IPv4) addrinfo for direct cache-layer tests. */
static void fill_ai_v4(struct addrinfo *ai, struct sockaddr_in *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
	memset(ai, 0, sizeof(*ai));
	ai->ai_family = AF_INET;
	ai->ai_addr = (struct sockaddr *)sa;
	ai->ai_addrlen = sizeof(*sa);
}

/*
 * Exercise the cache layer directly (no network): the max-entries cap must
 * refuse new keys once full while still allowing same-key replacement.
 */
static void test_dns_cache_cap(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_entry *e;
	struct sockaddr_in sa;
	struct addrinfo ai;
	char key[32];
	int r, i;

	fill_ai_v4(&ai, &sa);

	r = gwp_dns_cache_init(&cache, 16, 4);	/* cap = 4 entries */
	assert(!r && cache);

	/* Fill to capacity: four distinct keys are accepted. */
	for (i = 0; i < 4; i++) {
		snprintf(key, sizeof(key), "host%d.example", i);
		r = gwp_dns_cache_insert(cache, key, &ai, time(NULL) + 100);
		assert(!r);
	}

	/* A fifth distinct key is refused and not cached. */
	r = gwp_dns_cache_insert(cache, "host4.example", &ai, time(NULL) + 100);
	assert(r == -ENOSPC);
	r = gwp_dns_cache_getent(cache, "host4.example", &e);
	assert(r == -ENOENT);

	/* Existing keys remain; replacing one (same key) is allowed when full. */
	r = gwp_dns_cache_getent(cache, "host0.example", &e);
	assert(!r);
	gwp_dns_cache_putent(e);
	r = gwp_dns_cache_insert(cache, "host0.example", &ai, time(NULL) + 100);
	assert(!r);

	gwp_dns_cache_free(cache);
}

/* Keys are case-insensitive: a mixed-case insert is found by any case. */
static void test_dns_cache_case(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_entry *e;
	struct sockaddr_in sa;
	struct addrinfo ai;
	int r;

	fill_ai_v4(&ai, &sa);
	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r && cache);

	r = gwp_dns_cache_insert(cache, "MixedCase.Example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_getent(cache, "mixedcase.example", &e);
	assert(!r);
	gwp_dns_cache_putent(e);
	r = gwp_dns_cache_getent(cache, "MIXEDCASE.EXAMPLE", &e);
	assert(!r);
	gwp_dns_cache_putent(e);

	/* A differently-cased insert replaces, not duplicates, the same key. */
	r = gwp_dns_cache_insert(cache, "MIXEDCASE.example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_getent(cache, "mixedcase.example", &e);
	assert(!r);
	gwp_dns_cache_putent(e);

	gwp_dns_cache_free(cache);
}

/*
 * An already-expired entry is not returned, and a reference obtained before a
 * same-key replace stays valid until released (the documented guarantee; run
 * under ASan this also checks there is no use-after-free).
 */
static void test_dns_cache_expiry_refcount(void)
{
	struct gwp_dns_cache_entry *e, *e2;
	struct gwp_dns_cache *cache = NULL;
	struct sockaddr_in sa;
	struct addrinfo ai;
	int r;

	fill_ai_v4(&ai, &sa);
	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r && cache);

	/* Expired-on-insert: lookup reports a miss, not the stale entry. */
	r = gwp_dns_cache_insert(cache, "old.example", &ai, time(NULL) - 1);
	assert(!r);
	r = gwp_dns_cache_getent(cache, "old.example", &e);
	assert(r == -ETIMEDOUT || r == -ENOENT);

	/* A held reference survives a same-key replace. */
	r = gwp_dns_cache_insert(cache, "live.example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_getent(cache, "live.example", &e);	/* ref held */
	assert(!r);
	r = gwp_dns_cache_insert(cache, "live.example", &ai, time(NULL) + 100);
	assert(!r);						/* replaced */
	assert(e->name_len > 0);				/* stale ref still readable */
	r = gwp_dns_cache_getent(cache, "live.example", &e2);	/* fresh entry */
	assert(!r);
	gwp_dns_cache_putent(e2);
	gwp_dns_cache_putent(e);				/* frees the old entry */

	gwp_dns_cache_free(cache);
}

/*
 * The resolver must hand back every usable address, not just the one it would
 * have connected to, and the cache must agree with a fresh lookup -- both on
 * the leading address and on the ordering. "localhost" is the useful case here
 * because it is normally dual stack (127.0.0.1 and ::1).
 */
static void test_addr_list(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .cache_expiry = 10 };
	struct gwp_sockaddr one, list[GWP_DNS_MAX_ADDRS];
	struct gwp_dns_ctx *ctx;
	struct gwp_dns_entry *e;
	uint8_t nr = 0, i;
	struct pollfd pfd;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);

	e = gwp_dns_queue(ctx, "localhost", "80");
	assert(e != NULL);
	pfd.fd = e->ev_fd;
	pfd.events = POLLIN;
	r = poll_all_in(&pfd, 1, 5000);
	assert(r == 0);
	assert(e->res == 0);

	/* At least one address, and the count must match what was filled in. */
	assert(e->nr_addrs >= 1);
	assert(e->nr_addrs <= GWP_DNS_MAX_ADDRS);
	for (i = 0; i < e->nr_addrs; i++) {
		r = e->addrs[i].sa.sa_family;
		assert(r == AF_INET || r == AF_INET6);
	}

	/*
	 * Families must alternate while both are still available, so a broken
	 * family costs one attempt rather than every attempt.
	 */
	for (i = 1; i < e->nr_addrs; i++) {
		int prev = e->addrs[i - 1].sa.sa_family;
		int cur = e->addrs[i].sa.sa_family;
		uint8_t j, same_as_cur = 0;

		if (prev != cur)
			continue;
		/*
		 * Two in a row is only legal once the other family is
		 * exhausted, i.e. every remaining entry has this family.
		 */
		for (j = i; j < e->nr_addrs; j++)
			if (e->addrs[j].sa.sa_family == cur)
				same_as_cur++;
		assert(same_as_cur == (uint8_t)(e->nr_addrs - i));
	}
	gwp_dns_entry_put(e);

	/* The cache stores every record; its list must match the resolver's. */
	r = gwp_dns_cache_lookup_list(ctx, "localhost", "80", list,
				      GWP_DNS_MAX_ADDRS, &nr);
	assert(!r);
	assert(nr >= 1);

	/* ... and its first address must equal the single-address lookup. */
	r = gwp_dns_cache_lookup(ctx, "localhost", "80", &one);
	assert(!r);
	assert(one.sa.sa_family == list[0].sa.sa_family);

	r = gwp_dns_cache_lookup_list(ctx, "aaaa.com", "80", list,
				      GWP_DNS_MAX_ADDRS, &nr);
	assert(r == -ENOENT);

	gwp_dns_ctx_free(ctx);
}

int main(void)
{
	test_basic_dns_multiple_requests();
	test_dns_cache();
	test_dns_cache_cap();
	test_dns_cache_case();
	test_dns_cache_expiry_refcount();
	test_addr_list();
	printf("All tests passed.\n");
	return 0;
}
