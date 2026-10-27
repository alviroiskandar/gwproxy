// SPDX-License-Identifier: GPL-2.0-only
/*
 * White-box tests for the DNS cache: the hash table itself, which the public
 * API does not expose.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "../dns_cache.c"

#include <stdio.h>
#include <arpa/inet.h>

static size_t longest_chain(const struct gwp_dns_cache *cache)
{
	const struct dns_hash_map *map = &cache->map;
	size_t i, n, max = 0;

	for (i = 0; i < map->nr_buckets; i++) {
		const struct dns_cache_entry *e;

		n = 0;
		for (e = map->table[i]; e; e = e->next)
			n++;
		if (n > max)
			max = n;
	}

	return max;
}

static uint64_t djb2(uint64_t h, const char *s)
{
	while (*s)
		h = h * 33 + (unsigned char)*s++;
	return h;
}

/*
 * "ax" and "c6" add the same amount to a DJB2 hash (97 * 33 + 120 == 99 * 33 +
 * 54), so @k such two-character blocks give 2^k names that collide whatever
 * the starting value. With a seeded DJB2 every one of them landed in one
 * bucket, and each insert walked the whole chain under the write lock. A keyed
 * hash must spread them like any other names.
 */
static void test_hash_flood(void)
{
	enum { K = 12, NR = 1 << K };
	struct gwp_dns_cache *cache = NULL;
	struct sockaddr_in sa;
	struct addrinfo ai;
	char name[2 * K + sizeof(".evil.test")];
	size_t chain;
	int i, j, r;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(0x7f000001);
	memset(&ai, 0, sizeof(ai));
	ai.ai_family = AF_INET;
	ai.ai_addr = (struct sockaddr *)&sa;
	ai.ai_addrlen = sizeof(sa);

	r = gwp_dns_cache_init(&cache, NR, 0);
	assert(!r && cache);

	for (i = 0; i < NR; i++) {
		for (j = 0; j < K; j++)
			memcpy(&name[2 * j], (i >> j) & 1 ? "c6" : "ax", 2);
		strcpy(&name[2 * K], ".evil.test");

		/* The names really do collide under DJB2, for any seed. */
		assert(djb2(5381, name) == djb2(5381, "axaxaxaxaxaxaxaxaxaxaxax.evil.test"));
		assert(djb2(12345, name) == djb2(12345, "axaxaxaxaxaxaxaxaxaxaxax.evil.test"));

		r = gwp_dns_cache_insert(cache, name, &ai, time(NULL) + 100);
		assert(!r);
	}

	/*
	 * 4096 random keys in 4096 buckets: the longest chain is about 7.
	 * Allow plenty of slack; a predictable hash puts all 4096 in one.
	 */
	chain = longest_chain(cache);
	printf("dns_cache: %d colliding names, longest chain %zu\n", NR, chain);
	assert(chain <= 16);

	gwp_dns_cache_free(cache);
}

int main(void)
{
	test_hash_flood();
	printf("All tests passed.\n");
	return 0;
}
