// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns.h"
#include "dns_cache.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

#include <pthread.h>
#include <sys/eventfd.h>

/*
 * The resolver threads. @nr_workers of them (--nr-dns-workers) are started
 * with the context and stay; more are started when lookups queue up with no
 * thread free to take them, up to GWP_DNS_MAX_THREADS, and those exit again
 * after GWP_DNS_IDLE_SECS without work.
 *
 * Each thread runs one blocking getaddrinfo() at a time and hands its result
 * to the waiting client as soon as it returns, so how many lookups are in
 * flight follows the load, and a slow name delays nobody but its own client.
 */
#define GWP_DNS_MAX_THREADS	64u
#define GWP_DNS_IDLE_SECS	10

enum {
	GWP_DNS_THR_FREE	= 0,	/* slot unused */
	GWP_DNS_THR_RUNNING	= 1,
	GWP_DNS_THR_EXITED	= 2,	/* exited on idle, not joined yet */
};

struct gwp_dns_ctx;

struct gwp_dns_thr {
	struct gwp_dns_ctx	*ctx;
	pthread_t		thread;
	uint32_t		id;
	uint8_t			state;
	bool			join;	/* free_threads() only */
};

struct gwp_dns_ctx {
	bool			should_stop;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	uint32_t		nr_sleeping;
	uint32_t		nr_entries;
	uint32_t		nr_threads;	/* RUNNING slots */
	uint32_t		max_threads;
	struct gwp_dns_entry	*head;
	struct gwp_dns_entry	*tail;
	struct gwp_dns_thr	*threads;	/* @max_threads slots */
	struct gwp_dns_cache	*cache;
	time_t			last_scan;
	struct gwp_dns_cfg	cfg;
};

static void put_all_entries(struct gwp_dns_entry *head)
{
	struct gwp_dns_entry *e, *next;

	for (e = head; e; e = next) {
		next = e->next;
		gwp_dns_entry_put(e);
	}
}

static void copy_ai_addr(struct gwp_sockaddr *gs, const struct addrinfo *ai,
			 uint16_t port)
{
	if (ai->ai_family == AF_INET) {
		gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
		gs->i4.sin_port = htons(port);
	} else {
		gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
		gs->i6.sin6_port = htons(port);
	}
}

/*
 * Collect up to @cap addresses from @res into @out, ordered the way the connect
 * path wants to try them: the preferred family first, then the two families
 * alternating. Alternating matters -- when a family is broken end to end (a
 * black-holed IPv6 route is the usual case), interleaving costs one failed
 * attempt instead of one per address before the working family is reached.
 *
 * Within a family the resolver's own order is preserved; glibc already sorts
 * that per RFC 6724, and the previous code discarded that ordering by scanning
 * for a family.
 *
 * @out[0] is the address the old single-shot selection would have returned, so
 * callers that only look at the first entry keep their existing behaviour.
 *
 * The names are resolved without a service, so @port is filled in here.
 *
 * Returns the number of addresses written.
 */
static uint8_t collect_addr_list(struct addrinfo *res, struct gwp_sockaddr *out,
				 uint8_t cap, uint32_t rt, uint16_t port)
{
	const struct addrinfo *v4[GWP_DNS_MAX_ADDRS];
	const struct addrinfo *v6[GWP_DNS_MAX_ADDRS];
	uint8_t nr_v4 = 0, nr_v6 = 0, n = 0, i;
	const struct addrinfo *ai;
	bool v6_first;

	if (!res || !cap)
		return 0;

	if (cap > GWP_DNS_MAX_ADDRS)
		cap = GWP_DNS_MAX_ADDRS;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			if (rt != GWP_DNS_RESTYP_IPV6_ONLY && nr_v4 < cap)
				v4[nr_v4++] = ai;
		} else if (ai->ai_family == AF_INET6) {
			if (rt != GWP_DNS_RESTYP_IPV4_ONLY && nr_v6 < cap)
				v6[nr_v6++] = ai;
		}
	}

	/*
	 * DEFAULT leads with IPv4 to match fetch_addr()'s DEFAULT handling, so
	 * a cache hit and a cache miss agree on the first address.
	 */
	v6_first = (rt == GWP_DNS_RESTYP_PREFER_IPV6);

	for (i = 0; n < cap && (i < nr_v4 || i < nr_v6); i++) {
		const struct addrinfo *a, *b;

		a = v6_first ? (i < nr_v6 ? v6[i] : NULL)
			     : (i < nr_v4 ? v4[i] : NULL);
		b = v6_first ? (i < nr_v4 ? v4[i] : NULL)
			     : (i < nr_v6 ? v6[i] : NULL);

		if (a)
			copy_ai_addr(&out[n++], a, port);
		if (b && n < cap)
			copy_ai_addr(&out[n++], b, port);
	}

	return n;
}

static void prep_hints(struct addrinfo *hints, uint32_t restyp)
{
	memset(hints, 0, sizeof(*hints));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_ADDRCONFIG;

	if (restyp == GWP_DNS_RESTYP_IPV4_ONLY)
		hints->ai_family = AF_INET;
	else if (restyp == GWP_DNS_RESTYP_IPV6_ONLY)
		hints->ai_family = AF_INET6;
}

static void try_pass_result_to_cache(struct gwp_dns_ctx *ctx, const char *name,
				     const struct addrinfo *ai)
{
	int x;

	if (!ctx->cache)
		return;

	x = ctx->cfg.cache_expiry;
	gwp_dns_cache_insert(ctx->cache, name, ai, time(NULL) + x);
}

/*
 * Resolve @name into @addrs/@nr_addrs. On success *@res_p holds the
 * getaddrinfo() result, which the caller passes to the cache and frees.
 */
static int resolve(const char *name, uint16_t port, struct gwp_sockaddr *addrs,
		   uint8_t cap, uint8_t *nr_addrs, uint32_t restyp,
		   struct addrinfo **res_p)
{
	struct addrinfo *res = NULL, hints;
	uint8_t n;
	int r;

	*res_p = NULL;
	*nr_addrs = 0;
	prep_hints(&hints, restyp);
	r = getaddrinfo(name, NULL, &hints, &res);
	if (r)
		return -EHOSTUNREACH;

	n = collect_addr_list(res, addrs, cap, restyp, port);
	if (!n) {
		freeaddrinfo(res);
		return -EHOSTUNREACH;
	}

	*res_p = res;
	*nr_addrs = n;
	return 0;
}

int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    uint16_t port, struct gwp_sockaddr *addrs,
		    uint8_t cap, uint8_t *nr_addrs, uint32_t restyp)
{
	struct addrinfo *res;
	int r;

	r = resolve(name, port, addrs, cap, nr_addrs, restyp, &res);
	if (r)
		return r;

	try_pass_result_to_cache(ctx, name, res);
	freeaddrinfo(res);
	return 0;
}

static void gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	if (!e)
		return;

	assert(e->ev_fd >= 0);
	__sys_close(e->ev_fd);
	free(e->name);
	free(e);
}

/*
 * Must be called with ctx->lock held. May release the lock, but it
 * will reacquire it before returning.
 *
 * If the DNS cache is enabled, do:
 *   - Compare the last scan time with the current time.
 *   - If it's more than ctx->cfg.cache_expiry seconds ago, scan the
 *     cache to find expired entries and delete them.
 *   - Save the current time as the last scan time.
 */
static void cond_scan_cache(struct gwp_dns_ctx *ctx)
{
	if (!ctx->cache)
		return;

	if (time(NULL) - ctx->last_scan < ctx->cfg.cache_expiry)
		return;

	/* Claim this round, so no other thread starts one meanwhile. */
	ctx->last_scan = time(NULL);
	pthread_mutex_unlock(&ctx->lock);
	gwp_dns_cache_housekeep(ctx->cache);
	pthread_mutex_lock(&ctx->lock);

	/*
	 * Call time(NULL) again because the scan might have taken
	 * several seconds if the number of entries is large or
	 * it got contended by other threads.
	 */
	ctx->last_scan = time(NULL);
}

static bool is_persistent(const struct gwp_dns_thr *t)
{
	return t->id < t->ctx->cfg.nr_workers;
}

/*
 * Must be called with ctx->lock held. Sleep until there is work or a stop.
 * Returns false when the calling thread should exit because it was idle for
 * too long; only the threads started on demand do.
 *
 * With the cache on, the persistent threads also wake on their own to sweep
 * it (cond_scan_cache()), so expired entries are reclaimed without traffic.
 */
static bool wait_for_queue_entry(struct gwp_dns_thr *t)
{
	struct gwp_dns_ctx *ctx = t->ctx;
	bool persistent = is_persistent(t);
	struct timespec ts;
	int r = 0;

	ctx->nr_sleeping++;
	if (persistent && !ctx->cache) {
		pthread_cond_wait(&ctx->cond, &ctx->lock);
	} else {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec += persistent ? ctx->cfg.cache_expiry : GWP_DNS_IDLE_SECS;
		r = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
	}
	ctx->nr_sleeping--;

	if (r == ETIMEDOUT && !persistent && !ctx->head)
		return false;

	cond_scan_cache(ctx);
	return true;
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *e = ctx->head;
	struct addrinfo *res;

	ctx->head = e->next;
	if (!ctx->head) {
		ctx->tail = NULL;
		assert(ctx->nr_entries == 1);
	}

	ctx->nr_entries--;
	pthread_mutex_unlock(&ctx->lock);

	if (atomic_load(&e->refcnt) == 1) {
		/*
		 * If the refcnt is 1, it means we are the last reference
		 * to this entry. The client no longer cares about the
		 * result. We can free it immediately. No need to resolve
		 * the query nor to signal the eventfd.
		 */
		gwp_dns_entry_free(e);
		goto out;
	}

	e->res = resolve(e->name, e->port, e->addrs, GWP_DNS_MAX_ADDRS,
			 &e->nr_addrs, ctx->cfg.restyp, &res);

	/*
	 * Wake the client first: the cache insert takes the write lock and
	 * allocates, and the client has no reason to wait for either.
	 */
	eventfd_write(e->ev_fd, 1);
	if (!e->res) {
		try_pass_result_to_cache(ctx, e->name, res);
		freeaddrinfo(res);
	}
	gwp_dns_entry_put(e);
out:
	pthread_mutex_lock(&ctx->lock);
}

static void *gwp_dns_thread_entry(void *arg)
{
	struct gwp_dns_thr *t = arg;
	struct gwp_dns_ctx *ctx = t->ctx;

	pthread_mutex_lock(&ctx->lock);
	while (!ctx->should_stop) {
		if (ctx->head) {
			process_queue_entry(ctx);
			continue;
		}

		if (!wait_for_queue_entry(t)) {
			t->state = GWP_DNS_THR_EXITED;
			break;
		}
	}
	ctx->nr_threads--;
	pthread_mutex_unlock(&ctx->lock);

	return NULL;
}

/*
 * Must be called with ctx->lock held. Start a thread in slot @t, reaping the
 * one that exited there before.
 */
static int start_thread(struct gwp_dns_ctx *ctx, struct gwp_dns_thr *t)
{
	int r;

	/*
	 * It marked itself EXITED under the lock and only has to return,
	 * which needs no lock, so this does not wait for long.
	 */
	if (t->state == GWP_DNS_THR_EXITED) {
		pthread_join(t->thread, NULL);
		t->state = GWP_DNS_THR_FREE;
	}

	t->ctx = ctx;
	r = pthread_create(&t->thread, NULL, gwp_dns_thread_entry, t);
	if (r)
		return -r;

	t->state = GWP_DNS_THR_RUNNING;
	ctx->nr_threads++;
	return 0;
}

/*
 * Must be called with ctx->lock held. More lookups are queued than threads
 * are free to take them: start one more thread, unless all are running. A
 * failure is not fatal; the threads already running serve the queue.
 */
static void maybe_grow(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (ctx->nr_entries <= ctx->nr_sleeping)
		return;
	if (ctx->nr_threads >= ctx->max_threads)
		return;

	for (i = ctx->cfg.nr_workers; i < ctx->max_threads; i++) {
		struct gwp_dns_thr *t = &ctx->threads[i];

		if (t->state != GWP_DNS_THR_RUNNING) {
			start_thread(ctx, t);
			return;
		}
	}
}

static void free_threads(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (!ctx->threads)
		return;

	/*
	 * Nothing queues lookups any more, so no slot leaves FREE from here
	 * on; a RUNNING one may still turn EXITED, which needs joining too.
	 */
	pthread_mutex_lock(&ctx->lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->cond);
	for (i = 0; i < ctx->max_threads; i++)
		ctx->threads[i].join = ctx->threads[i].state != GWP_DNS_THR_FREE;
	pthread_mutex_unlock(&ctx->lock);

	for (i = 0; i < ctx->max_threads; i++) {
		if (ctx->threads[i].join)
			pthread_join(ctx->threads[i].thread, NULL);
	}

	free(ctx->threads);
	ctx->threads = NULL;
}

static int init_threads(struct gwp_dns_ctx *ctx)
{
	uint32_t i;
	int r = 0;

	if (ctx->cfg.nr_workers == 0)
		return -EINVAL;

	ctx->max_threads = ctx->cfg.nr_workers;
	if (ctx->max_threads < GWP_DNS_MAX_THREADS)
		ctx->max_threads = GWP_DNS_MAX_THREADS;

	ctx->threads = calloc(ctx->max_threads, sizeof(*ctx->threads));
	if (!ctx->threads)
		return -ENOMEM;

	for (i = 0; i < ctx->max_threads; i++)
		ctx->threads[i].id = i;

	pthread_mutex_lock(&ctx->lock);
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		r = start_thread(ctx, &ctx->threads[i]);
		if (r)
			break;
	}
	pthread_mutex_unlock(&ctx->lock);

	if (r)
		free_threads(ctx);

	return r;
}

int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 uint16_t port, struct gwp_sockaddr *addr)
{
	uint8_t nr;

	return gwp_dns_cache_lookup_list(ctx, name, port, addr, 1, &nr);
}

/* Size the bucket array from the entry cap for a ~1.0 load factor, clamped to
 * a sane range; fall back to a fixed size when the cap is unlimited (0). */
static uint32_t cache_bucket_count(uint32_t max_entries)
{
	uint32_t n = max_entries ? max_entries : 65536;

	if (n < 1024)
		n = 1024;
	else if (n > (1u << 20))
		n = (1u << 20);
	return n;
}

/* A hit must be able to fill a whole list from one family. */
_Static_assert(GWP_DNS_CACHE_MAX_ADDRS >= GWP_DNS_MAX_ADDRS,
	       "the cache hands back fewer addresses than a lookup returns");

static void fill_i4(struct gwp_sockaddr *addr, const struct in_addr *a,
		    uint16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->i4.sin_family = AF_INET;
	addr->i4.sin_port = htons(port);
	addr->i4.sin_addr = *a;
}

static void fill_i6(struct gwp_sockaddr *addr, const struct in6_addr *a,
		    uint16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->i6.sin6_family = AF_INET6;
	addr->i6.sin6_port = htons(port);
	addr->i6.sin6_addr = *a;
}

int gwp_dns_cache_lookup_list(struct gwp_dns_ctx *ctx, const char *name,
			      uint16_t port, struct gwp_sockaddr *addrs,
			      uint8_t cap, uint8_t *nr_addrs)
{
	struct gwp_dns_cache_addrs ca;
	uint8_t nr_v4, nr_v6, n = 0, i;
	uint32_t rt = ctx->cfg.restyp;
	bool v6_first;
	int r;

	if (!ctx->cache)
		return -ENOSYS;
	if (!cap)
		return -EINVAL;
	if (cap > GWP_DNS_MAX_ADDRS)
		cap = GWP_DNS_MAX_ADDRS;

	r = gwp_dns_cache_lookup_addrs(ctx->cache, name, &ca);
	if (r)
		return r;

	nr_v4 = (rt == GWP_DNS_RESTYP_IPV6_ONLY) ? 0 : ca.nr_i4;
	nr_v6 = (rt == GWP_DNS_RESTYP_IPV4_ONLY) ? 0 : ca.nr_i6;

	/* Same interleave and the same leading family as collect_addr_list(). */
	v6_first = (rt == GWP_DNS_RESTYP_PREFER_IPV6);

	for (i = 0; n < cap && (i < nr_v4 || i < nr_v6); i++) {
		if (v6_first) {
			if (i < nr_v6)
				fill_i6(&addrs[n++], &ca.i6[i], port);
			if (i < nr_v4 && n < cap)
				fill_i4(&addrs[n++], &ca.i4[i], port);
		} else {
			if (i < nr_v4)
				fill_i4(&addrs[n++], &ca.i4[i], port);
			if (i < nr_v6 && n < cap)
				fill_i6(&addrs[n++], &ca.i6[i], port);
		}
	}

	*nr_addrs = n;
	return n ? 0 : -EHOSTUNREACH;
}

static int init_cache(struct gwp_dns_ctx *ctx)
{
	uint32_t max = ctx->cfg.max_entries;
	struct gwp_dns_cache *cache;
	int r;

	if (ctx->cfg.cache_expiry <= 0) {
		/*
		 * Cache is disabled.
		 */
		ctx->cache = NULL;
		return 0;
	}

	r = gwp_dns_cache_init(&cache, cache_bucket_count(max), max);
	if (r)
		return r;

	ctx->cache = cache;
	return 0;
}

static void free_cache(struct gwp_dns_cache *cache)
{
	if (!cache)
		return;

	gwp_dns_cache_free(cache);
}

static inline bool validate_restyp(int restyp)
{
	switch (restyp) {
	case GWP_DNS_RESTYP_DEFAULT:
	case GWP_DNS_RESTYP_IPV4_ONLY:
	case GWP_DNS_RESTYP_IPV6_ONLY:
	case GWP_DNS_RESTYP_PREFER_IPV4:
	case GWP_DNS_RESTYP_PREFER_IPV6:
		return true;
	default:
		return false;
	}
}

/* The idle timeouts are intervals, so measure them on the monotonic clock. */
static int init_cond(pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	int r;

	r = pthread_condattr_init(&attr);
	if (r)
		return -r;

	r = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (!r)
		r = pthread_cond_init(cond, &attr);

	pthread_condattr_destroy(&attr);
	return -r;
}

int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg)
{
	struct gwp_dns_ctx *ctx;
	int r;

	if (!validate_restyp(cfg->restyp))
		return -EINVAL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ctx->cfg = *cfg;
	r = pthread_mutex_init(&ctx->lock, NULL);
	if (r) {
		r = -r;
		goto out_free_ctx;
	}

	r = init_cond(&ctx->cond);
	if (r)
		goto out_destroy_mutex;

	r = init_cache(ctx);
	if (r)
		goto out_destroy_cond;

	ctx->nr_sleeping = 0;
	ctx->nr_entries = 0;
	ctx->nr_threads = 0;
	ctx->threads = NULL;
	ctx->head = NULL;
	ctx->tail = NULL;
	ctx->should_stop = false;
	ctx->last_scan = time(NULL);
	r = init_threads(ctx);
	if (r)
		goto out_free_cache;

	*ctx_p = ctx;
	return 0;
out_free_cache:
	free_cache(ctx->cache);
out_destroy_cond:
	pthread_cond_destroy(&ctx->cond);
out_destroy_mutex:
	pthread_mutex_destroy(&ctx->lock);
out_free_ctx:
	free(ctx);
	*ctx_p = NULL;
	return r;
}

static void put_all_queued_entries(struct gwp_dns_ctx *ctx)
{
	put_all_entries(ctx->head);
	ctx->head = ctx->tail = NULL;
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	free_threads(ctx);
	pthread_mutex_destroy(&ctx->lock);
	pthread_cond_destroy(&ctx->cond);
	put_all_queued_entries(ctx);
	free_cache(ctx->cache);
	free(ctx);
}

static void push_queue(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e)
{
	pthread_mutex_lock(&ctx->lock);
	if (ctx->tail)
		ctx->tail->next = e;
	else
		ctx->head = e;
	ctx->tail = e;
	e->next = NULL;

	ctx->nr_entries++;
	if (ctx->nr_sleeping)
		pthread_cond_signal(&ctx->cond);
	maybe_grow(ctx);
	pthread_mutex_unlock(&ctx->lock);
}

struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, uint16_t port)
{
	struct gwp_dns_entry *e;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;

	e->ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (e->ev_fd < 0)
		goto out_free_e;

	e->name = strdup(name);
	if (!e->name)
		goto out_close_ev_fd;

	e->port = port;

	atomic_init(&e->refcnt, 2);
	e->res = 0;
	push_queue(ctx, e);
	return e;

out_close_ev_fd:
	__sys_close(e->ev_fd);
out_free_e:
	free(e);
	return NULL;
}

bool gwp_dns_entry_put(struct gwp_dns_entry *e)
{
	int x;

	if (!e)
		return false;

	x = atomic_fetch_sub(&e->refcnt, 1);
	assert(x > 0);
	if (x == 1) {
		gwp_dns_entry_free(e);
		return true;
	}

	return false;
}
