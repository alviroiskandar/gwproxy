// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWP_DNS_H
#define GWP_DNS_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <gwproxy/net.h>
#include <gwproxy/syscall.h>

struct gwp_dns_wrk;

/*
 * How many addresses a single name may contribute. A resolver can return far
 * more; the connect path only ever tries a handful before giving up, so the
 * rest are dropped rather than carried around per connection.
 */
#define GWP_DNS_MAX_ADDRS	8u

struct gwp_dns_entry {
	char			*name;
	char			*service;
	_Atomic(int)		refcnt;
	int			res;
	int			ev_fd;
	/*
	 * Every usable address for @name, ordered the way they should be
	 * tried: preferred family first, then families alternating, so a
	 * family that is broken end to end costs one attempt rather than all
	 * of them. @addrs[0] is the address a single-shot selection would have
	 * picked.
	 */
	struct gwp_sockaddr	addrs[GWP_DNS_MAX_ADDRS];
	uint8_t			nr_addrs;
	struct gwp_dns_entry	*next;
};

enum {
	GWP_DNS_RESTYP_DEFAULT		= 0,
	GWP_DNS_RESTYP_IPV4_ONLY	= 1,
	GWP_DNS_RESTYP_IPV6_ONLY	= 2,
	GWP_DNS_RESTYP_PREFER_IPV4	= 3,
	GWP_DNS_RESTYP_PREFER_IPV6	= 4,
};

struct gwp_dns_cfg {
	int		cache_expiry;	/* In seconds. <= 0 to disable cache. */
	uint32_t	nr_workers;
	uint32_t	restyp;
};

struct gwp_dns_ctx;

/**
 * Initialize the DNS context. Stores the context in `*ctx_p`. When
 * the context is no longer needed, it should be freed using
 * gwp_dns_ctx_free().
 *
 * @param ctx_p	Pointer to a pointer where the context will be stored.
 * @param cfg	Pointer to the configuration structure.
 * @return	0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOMEM: Memory allocation failed.
 * -EINVAL: Invalid configuration parameters.
 */
int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg);

/**
 * Free the DNS context.
 *
 * @param ctx	Pointer to the context to be freed.
 */
void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx);

/**
 * Queue a DNS resolution request. It returns a pointer to a gwp_dns_entry
 * with eventfd set to a valid file descriptor that can be used to wait for
 * the resolution result. The caller's responsible to call gwp_dns_entry_put()
 * to release the entry when it is no longer needed.
 *
 * The returned eventfd file descriptor is non-blocking.
 *
 * @param ctx		Pointer to the DNS context.
 * @param name		Name to resolve.
 * @param service 	Service to resolve in port number ascii format.
 * @return		Pointer to a gwp_dns_entry on success, NULL on failure.
 */
struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, const char *service);

/**
 * Release a DNS entry. This function decrements the reference count of the
 * entry. If the reference count reaches zero, the entry is freed.
 *
 * @param entry		Pointer to the DNS entry to release. If the entry is
 *			NULL, this function does nothing.
 * @return		True if the entry was freed, false otherwise.
 */
bool gwp_dns_entry_put(struct gwp_dns_entry *entry);

/**
 * Lookup a DNS entry in the cache. If the entry is found, it fills the
 * `addr` structure with the resolved address and returns 0. If the entry is
 * not found, it returns -ENOENT.
 *
 * @param ctx		Pointer to the DNS context.
 * @param name		Pointer to the name to look up.
 * @param service	Pointer to the service to look up.
 * @param addr		Pointer to the sockaddr structure to fill in.
 * @return		0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOSYS: Cache is disabled.
 * -ENOENT: Entry not found in the cache.
 * -EINVAL: Invalid parameters.
 */
int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 const char *service, struct gwp_sockaddr *addr);

/*
 * As gwp_dns_cache_lookup(), but returns up to @cap addresses in the order they
 * should be tried, matching what a cache miss would have produced. *@nr_addrs
 * receives the count. The cache already stores every A and AAAA record, so this
 * reads the same entry -- no extra lookup cost.
 */
int gwp_dns_cache_lookup_list(struct gwp_dns_ctx *ctx, const char *name,
			      const char *service, struct gwp_sockaddr *addrs,
			      uint8_t cap, uint8_t *nr_addrs);


/*
 * Resolve @name/@service into up to @cap addresses, written to @addrs in the
 * order they should be tried (see struct gwp_dns_entry). *@nr_addrs receives
 * the count. Returns 0 on success, or -EHOSTUNREACH when nothing resolved.
 */
int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    const char *service, struct gwp_sockaddr *addrs,
		    uint8_t cap, uint8_t *nr_addrs, uint32_t restyp);

#endif /* #ifndef GWP_DNS_H */
