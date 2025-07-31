#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/syscall.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

__attribute__((__format__(printf, 3, 4)))
void __pr_log(FILE *handle, int level, const char *fmt, ...)
{
	char loc_buf[4096], *tmp, *pb, time_buf[64];
	va_list ap, ap2;
	const char *ls;
	struct tm tm;
	time_t now;
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

	va_start(ap, fmt);
	va_copy(ap2, ap);
	r = vsnprintf(loc_buf, sizeof(loc_buf), fmt, ap);
	if (unlikely((size_t)r >= sizeof(loc_buf))) {
		tmp = malloc(r + 1);
		if (!tmp)
			goto out;

		vsnprintf(tmp, r + 1, fmt, ap2);
		pb = tmp;
	} else {
		pb = loc_buf;
	}

	now = time(NULL);
	if (likely(localtime_r(&now, &tm)))
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	else
		time_buf[0] = '\0';

	fprintf(handle, "[%s][%s][%08d]: %s\n", time_buf, ls, __sys_gettid(), pb);
	if (unlikely(pb != loc_buf))
		free(pb);
out:
	va_end(ap2);
	va_end(ap);
}
