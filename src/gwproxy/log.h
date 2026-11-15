// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY__LOG_H
#define GWPROXY__LOG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef GWP_STATIC_LOG_LEVEL
#define GWP_STATIC_LOG_LEVEL 4
#endif

__attribute__((__format__(printf, 3, 4)))
void __pr_log(FILE *handle, int level, const char *fmt, ...);

/*
 * The room gwp_log_escape() needs for @len bytes: each may become "\xHH",
 * and the terminating NUL.
 */
#define GWP_LOG_ESC_SIZE(len) ((len) * 4 + 1)

/*
 * Copy the @len bytes at @src, which may be any bytes NUL included, into @dst
 * as a NUL-terminated string fit to quote in a log message: every byte outside
 * printable ASCII, and '"' and '\', is written as "\xHH", so the value reads
 * back unambiguously between double quotes. @dst must hold
 * GWP_LOG_ESC_SIZE(@len) bytes. Returns @dst.
 */
char *gwp_log_escape(char *dst, const void *src, size_t len);

struct log_handle {
	FILE *handle;
	int level;
};

#define pr_log(HANDLE, LEVEL, FMT, ...)				\
do {								\
	struct log_handle *__hd = (HANDLE);			\
	int __level = (LEVEL);					\
	if (__level > GWP_STATIC_LOG_LEVEL)			\
		break;						\
	if (!__hd)						\
		break;						\
	if (__level > __hd->level)				\
		break;						\
	if (!__hd->handle)					\
		break;						\
	__pr_log(__hd->handle, __level, FMT, ##__VA_ARGS__);	\
} while (0)

#define pr_err(HANDLE, FMT, ...) pr_log(HANDLE, 1, FMT, ##__VA_ARGS__)
#define pr_warn(HANDLE, FMT, ...) pr_log(HANDLE, 2, FMT, ##__VA_ARGS__)
#define pr_info(HANDLE, FMT, ...) pr_log(HANDLE, 3, FMT, ##__VA_ARGS__)
#define pr_dbg(HANDLE, FMT, ...) pr_log(HANDLE, 4, FMT, ##__VA_ARGS__)

/*
 * A log line a client can trigger at will, written at most once a second: the
 * next is due from @next on, and @quiet counts the ones left out since the
 * last (gwp_log_limit_take()).
 */
struct gwp_log_limit {
	uint32_t	next;
	uint32_t	quiet;
};

/*
 * Whether a line limited by @l may be logged at second @now. When it may,
 * *@quiet (unless @quiet is NULL) is set to the number left out since the
 * last one, for the line to say; when not, this one is counted among them.
 *
 * A signed difference, not "@now == the second last logged": a limit the
 * workers share (iplimit.c) sees their coarse clocks, each its own, so @now
 * may come from one that is still a second behind the worker that logged. It
 * also stays right as the seconds wrap.
 */
static inline bool gwp_log_limit_take(struct gwp_log_limit *l, uint32_t now,
				      uint32_t *quiet)
{
	if ((int32_t)(now - l->next) < 0) {
		l->quiet++;
		return false;
	}

	if (quiet)
		*quiet = l->quiet;
	l->quiet = 0;
	l->next = now + 1;
	return true;
}

#endif /* #ifndef GWPROXY__LOG_H */
