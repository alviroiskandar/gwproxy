// SPDX-License-Identifier: GPL-2.0-only
/*
 * getrandom() for the seeds and keys that want it, on libcs with and
 * without it.
 */
#ifndef GWPROXY_RAND_H
#define GWPROXY_RAND_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#ifdef CONFIG_HAVE_GETRANDOM
#include <sys/random.h>
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK	0x0001
#endif

/*
 * Fill @buf with @len bytes from getrandom(@buf, @len, @flags). True only
 * when all @len came; false on a failure, a short read, or a libc that does
 * not provide getrandom() at all (Termux on Android, say), where calling it
 * would not even compile, hence the configure probe. Each caller keeps its
 * own fallback for false.
 */
static inline bool gwp_getrandom(void *buf, size_t len, unsigned int flags)
{
#ifdef CONFIG_HAVE_GETRANDOM
	return getrandom(buf, len, flags) == (ssize_t)len;
#else
	(void)buf;
	(void)len;
	(void)flags;
	return false;
#endif
}

#endif /* #ifndef GWPROXY_RAND_H */
