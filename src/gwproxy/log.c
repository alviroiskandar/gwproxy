#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/syscall.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

/*
 * Per-thread state, so a log line costs no syscall but its write(2): the
 * thread id never changes, and the timestamp only has to be formatted again
 * when the second changes (localtime_r() takes glibc's global timezone lock).
 */
static __thread pid_t log_tid;
static __thread time_t log_sec = (time_t)-1;
static __thread char log_time[32];

static const char *log_time_str(void)
{
	time_t now = time(NULL);
	struct tm tm;

	if (now != log_sec) {
		log_sec = now;
		if (likely(localtime_r(&now, &tm)))
			strftime(log_time, sizeof(log_time),
				 "%Y-%m-%d %H:%M:%S", &tm);
		else
			log_time[0] = '\0';
	}
	return log_time;
}

static void log_write(int fd, const char *buf, size_t len)
{
	ssize_t r;

	while (len) {
		r = __sys_write(fd, buf, len);
		if (r < 0) {
			if (r == -EINTR)
				continue;
			return;
		}
		buf += r;
		len -= (size_t)r;
	}
}

/*
 * The whole line is formatted once into one buffer and handed to the kernel
 * with a single write(2), bypassing stdio: no FILE lock for the workers to
 * serialise on, no second formatting pass, and no flush. A regular log file
 * is opened with O_APPEND (fopen "a"), so lines from different workers never
 * interleave.
 */
__attribute__((__format__(printf, 3, 4)))
void __pr_log(FILE *handle, int level, const char *fmt, ...)
{
	char loc_buf[4096], *pb = loc_buf;
	size_t hlen, room;
	va_list ap, ap2;
	const char *ls;
	int r;

	if (!handle)
		return;

	switch (level) {
	case 1:  ls = "error "; break;
	case 2:  ls = "warn  "; break;
	case 3:  ls = "info  "; break;
	case 4:  ls = "debug "; break;
	default: ls = "????? "; break;
	}

	if (unlikely(!log_tid))
		log_tid = __sys_gettid();

	r = snprintf(loc_buf, sizeof(loc_buf), "[%s][%s][%08d]: ",
		     log_time_str(), ls, log_tid);
	if (unlikely(r < 0 || (size_t)r >= sizeof(loc_buf)))
		return;
	hlen = (size_t)r;
	/* Keep one byte for the '\n' that replaces the terminator. */
	room = sizeof(loc_buf) - hlen - 1;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	r = vsnprintf(loc_buf + hlen, room, fmt, ap);
	if (unlikely(r < 0))
		goto out;	/* bad format or conversion: nothing to print */
	if (unlikely((size_t)r >= room)) {
		pb = malloc(hlen + (size_t)r + 2);
		if (!pb)
			goto out;

		memcpy(pb, loc_buf, hlen);
		vsnprintf(pb + hlen, (size_t)r + 1, fmt, ap2);
	}

	pb[hlen + (size_t)r] = '\n';
	log_write(fileno(handle), pb, hlen + (size_t)r + 1);
	if (unlikely(pb != loc_buf))
		free(pb);
out:
	va_end(ap2);
	va_end(ap);
}
