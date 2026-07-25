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
#include <poll.h>
#include <errno.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct req_template {
	const char *domain, *service;
};

/*
 * Names that resolve from /etc/hosts alone. A unit test must not depend on
 * public DNS: on an offline or filtered builder every one of these lookups
 * fails, the assertion below aborts, and `make test-unit` stops before the
 * socks5/http1/http/acl binaries ever run -- indistinguishable from a real
 * regression in gwp_dns_queue(). Repeating a handful of local names keeps the
 * many-requests shape (queue, workers, eventfd, refcounts, cache inserts) that
 * this test is actually about, and covers both address families.
 */
static const struct req_template req_template[] = {
	{ "localhost",		"80" },
	{ "127.0.0.1",		"80" },
	{ "::1",		"443" },
	{ "ip6-localhost",	"443" },
	{ "localhost",		"443" },
	{ "127.0.0.1",		"443" },
	{ "::1",		"80" },
	{ "ip6-localhost",	"80" },
	{ "localhost",		"8080" },
	{ "127.0.0.1",		"8080" },
	{ "::1",		"8080" },
	{ "ip6-localhost",	"8080" },
	{ "localhost",		"9090" },
	{ "127.0.0.1",		"9090" },
	{ "::1",		"9090" },
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

static void test_basic_dns_multiple_requests(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1 };
	struct gwp_dns_entry *earr[ARRAY_SIZE(req_template)];
	struct pollfd pfd[ARRAY_SIZE(req_template)];
	struct gwp_dns_ctx *ctx;
	int i, n;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	n = (int)ARRAY_SIZE(req_template);
	for (i = 0; i < n; i++) {
		const struct req_template *rt = &req_template[i];
		earr[i] = gwp_dns_queue(ctx, rt->domain, rt->service);
		assert(earr[i]);
		assert(earr[i]->ev_fd >= 0);
		pfd[i].fd = earr[i]->ev_fd;
		pfd[i].events = POLLIN;
	}

	r = poll_all_in(pfd, n, 5000);
	assert(!r);

	for (i = 0; i < n; i++) {
		assert(earr[i]->res == 0);
		r = earr[i]->addr.sa.sa_family;
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
	r = e->addr.sa.sa_family;
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

int main(void)
{
	test_basic_dns_multiple_requests();
	test_dns_cache();
	printf("All tests passed.\n");
	return 0;
}
