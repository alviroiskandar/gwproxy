// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_DNS_CACHE_H
#define GWPROXY_DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct gwp_dns_cache_entry {
	/**
	 * Super compact domain name and IP address list.
	 *
	 * - name_len: length of the domain name (including null terminator).
	 * - nr_i4: number of IPv4 addresses.
	 * - nr_i6: number of IPv6 addresses.
	 * - block: flexible array member that contains:
	 *     - The first name_len octets are the domain name.
	 *     - The next nr_i4 * 4 octets are IPv4 addresses.
	 *     - The next nr_i6 * 16 octets are IPv6 addresses.
	 */
	uint8_t		name_len;
	uint8_t		nr_i4;
	uint8_t		nr_i6;
	uint8_t		block[];
};

static inline uint8_t *gwp_dns_cache_entget_i4(struct gwp_dns_cache_entry *e)
{
	if (!e->nr_i4)
		return NULL;

	return e->block + e->name_len;
}

static inline uint8_t *gwp_dns_cache_entget_i6(struct gwp_dns_cache_entry *e)
{
	if (!e->nr_i6)
		return NULL;

	return e->block + e->name_len + (e->nr_i4 * 4);
}

struct gwp_dns_cache;

/**
 * Initialize a DNS cache and fills the provided pointer with a new cache
 * instance. When the cache is no longer needed, it should be freed using
 * `gwp_dns_cache_free()`.
 *
 * @param cache_p	Pointer to the cache pointer that will be initialized.
 * @param nr_buckets	Number of buckets for the hash map.
 * @param max_entries	Maximum number of entries to hold; once reached, inserts
 *			of new keys are refused (returning -ENOSPC) to bound
 *			memory. 0 means unlimited.
 * @return int		0 on success, negative error code on failure.
 */
int gwp_dns_cache_init(struct gwp_dns_cache **cache_p, uint32_t nr_buckets,
		       uint32_t max_entries);

/**
 * Free the DNS cache and all its resources.
 *
 * @param cache	The DNS cache to free.
 */
void gwp_dns_cache_free(struct gwp_dns_cache *cache);

/**
 * Scan and remove expired entries from the DNS cache. Expected to
 * be called periodically to reclaim memory from expired entries.
 *
 * @param cache	The DNS cache to perform housekeeping on.
 */
void gwp_dns_cache_housekeep(struct gwp_dns_cache *cache);

/**
 * Look up a DNS entry by its key and retrieve the corresponding
 * entry if it exists. It increments the reference count of the
 * entry, so it can be safely used even after the cache is freed
 * using `gwp_dns_cache_free()`.
 *
 * `gwp_dns_cache_putent()` MUST be called to release the reference
 * count when the entry is no longer needed.
 *
 * @param cache	The DNS cache to look up the entry in.
 * @param key 	The key to look up, typically a domain name.
 * @param ep	Pointer to a pointer that will be filled with the found entry.
 * @return int	0 on success, negative error code on failure.
 *
 * Error codes:
 * -ENOENT:    Entry not found.
 * -ETIMEDOUT: Entry found but expired (treated as a miss).
 * -EINVAL:    Invalid key (empty or too long).
 */
int gwp_dns_cache_getent(struct gwp_dns_cache *cache, const char *key,
			 struct gwp_dns_cache_entry **ep);

/**
 * Decrement the reference count of a DNS cache entry. If the
 * reference count reaches zero, the entry is freed. This function
 * should be called when the entry is no longer needed.
 *
 * @param e	The DNS cache entry to put.
 */
void gwp_dns_cache_putent(struct gwp_dns_cache_entry *e);

/**
 * Insert a new DNS entry into the cache. If an entry with the same key
 * already exists, it will be replaced.
 *
 * If the entry to be replaced is currently being used (referenced),
 * it's safe for that reference to continue to exist until the user
 * calls `gwp_dns_cache_putent()` on it.
 *
 * @param cache		The DNS cache to insert the entry into.
 * @param key		The key for the entry, typically a domain name.
 * @param ai		The address information to insert.
 * @param expired_at	The time when the entry expires.
 * @return int		0 on success, negative error code on failure.
 */
struct addrinfo;
int gwp_dns_cache_insert(struct gwp_dns_cache *cache, const char *key,
			 const struct addrinfo *ai, time_t expired_at);

#endif /* #ifndef GWPROXY_DNS_CACHE_H */
