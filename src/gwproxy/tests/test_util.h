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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

#endif /* #ifndef GWPROXY__TESTS__TEST_UTIL_H */
