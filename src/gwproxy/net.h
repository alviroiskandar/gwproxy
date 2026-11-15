/*
 * utility for network-related stuff
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef GWP_NET_H
#define GWP_NET_H

#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

struct gwp_sockaddr {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	i4;
		struct sockaddr_in6	i6;
	};
};

/*
 * The length of @a for bind(), connect() and sendmsg(). The caller holds an
 * AF_INET or AF_INET6 address; any other family gets the IPv6 length.
 */
static inline socklen_t gwp_sockaddr_len(const struct gwp_sockaddr *a)
{
	return a->sa.sa_family == AF_INET ? sizeof(a->i4) : sizeof(a->i6);
}

/*
 * Canonicalise @a to (*@is_v4, *@ip pointing at its 4- or 16-byte address):
 * an IPv4-mapped IPv6 address counts as the IPv4 address it maps.
 */
static inline void gwp_sockaddr_canon_ip(const struct gwp_sockaddr *a,
					 bool *is_v4, const uint8_t **ip)
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

/* The port of @a in network byte order, for AF_INET or AF_INET6. */
static inline uint16_t gwp_sockaddr_port(const struct gwp_sockaddr *a)
{
	return a->sa.sa_family == AF_INET ? a->i4.sin_port : a->i6.sin6_port;
}

/* The port of @a in host byte order, for AF_INET or AF_INET6. */
static inline uint16_t gwp_sockaddr_port_h(const struct gwp_sockaddr *a)
{
	return ntohs(gwp_sockaddr_port(a));
}

/*
 * Convert address string to network address
 *
 * @param str source
 * @param gs destination
 * @param default_port fill it with zero if unspecified
 * @return zero on success and a negative integer on failure.
 */
int convert_str_to_ssaddr(const char *str,
				struct gwp_sockaddr *gs, uint16_t default_port);

/*
 * Convert network address to string format
 *
 * @param buf destination
 * @param gs source
 * @return zero on success and a negative integer on failure.
 */
int convert_ssaddr_to_str(char buf[FULL_ADDRSTRLEN],
			const struct gwp_sockaddr *gs);

#endif /* #ifndef GWP_NET_H */