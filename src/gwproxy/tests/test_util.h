// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fixtures shared by the unit tests: temporary files, addresses and the
 * pass line. Everything is static inline, so a test that includes this
 * header links only what it calls.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef GWPROXY__TESTS__TEST_UTIL_H
#define GWPROXY__TESTS__TEST_UTIL_H

/* The helpers check with assert(); a test that drops them checks nothing. */
#ifdef NDEBUG
#error "include test_util.h after #undef NDEBUG"
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gwproxy/auth.h>
#include <gwproxy/net.h>

/*
 * Print a test function's pass line, the first time it gets there only. A
 * macro, as it needs the caller's __func__ and a flag of its own per test.
 */
#define PRTEST_OK()					\
do {							\
	static int __printed;				\
	if (!__printed) {				\
		printf("Test passed: %s\n", __func__);	\
		__printed = 1;				\
	}						\
} while (0)

/*
 * The socket address of @ip, an IPv4 or IPv6 literal, and @port, with every
 * other byte zero; an IPv6 literal is told by its ':'.
 */
static inline struct gwp_sockaddr gwp_test_addr(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	if (strchr(ip, ':')) {
		s.i6.sin6_family = AF_INET6;
		s.i6.sin6_port = htons(port);
		assert(inet_pton(AF_INET6, ip, &s.i6.sin6_addr) == 1);
	} else {
		s.i4.sin_family = AF_INET;
		s.i4.sin_port = htons(port);
		assert(inet_pton(AF_INET, ip, &s.i4.sin_addr) == 1);
	}
	return s;
}

/* The directory for temporary files: $TMPDIR, or /tmp when it is not set. */
static inline const char *gwp_test_tmpdir(void)
{
	const char *dir = getenv("TMPDIR");

	return (dir && *dir) ? dir : "/tmp";
}

/*
 * Create a unique temporary file named @prefix.XXXXXX in gwp_test_tmpdir()
 * and write @len bytes of @data to it; *@path gets its malloc'd name. Using
 * mkstemp() rather than opening a fixed path keeps each run's file unique and
 * owned by the current user; that matters under fs.protected_regular, where
 * (re)opening another user's file for writing in the sticky, world-writable
 * /tmp is denied even for root. Returns write()'s result, or -1 when the file
 * cannot be created. The caller unlink()s and free()s *@path.
 */
static inline ssize_t gwp_test_write_tmp(char **path, const char *prefix,
					 const void *data, size_t len)
{
	ssize_t w;
	int fd;

	assert(asprintf(path, "%s/%s.XXXXXX", gwp_test_tmpdir(), prefix) > 0);
	fd = mkstemp(*path);
	if (fd < 0)
		return -1;

	w = write(fd, data, len);
	close(fd);
	return w;
}

/*
 * Replace the contents of the existing file at @path with the @len bytes at
 * @buf. There is no O_CREAT: a test that rewrites a file it never made
 * fails here rather than quietly creating one.
 */
static inline void gwp_test_rewrite_file(const char *path, const void *buf,
					 size_t len)
{
	int fd;

	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, buf, len) == (ssize_t)len);
	close(fd);
}

/*
 * A credential store loaded from a new temporary file of the @len bytes at
 * @data, named as gwp_test_write_tmp() names it; *@path gets the file's
 * malloc'd name. Give both back with gwp_test_auth_put().
 */
static inline struct gwp_auth *gwp_test_auth_from_buf(const char *prefix,
						      const void *data,
						      size_t len, char **path)
{
	struct gwp_auth *auth = NULL;

	assert(gwp_test_write_tmp(path, prefix, data, len) == (ssize_t)len);
	assert(!gwp_auth_create(&auth, *path));
	assert(auth);
	return auth;
}

static inline void gwp_test_auth_put(struct gwp_auth *auth, char *path)
{
	gwp_auth_destroy(auth);
	unlink(path);
	free(path);
}

#endif /* #ifndef GWPROXY__TESTS__TEST_UTIL_H */
