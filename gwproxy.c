// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 * -- (( Year: 2025 ))
 *
 * Simple TCP proxy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

struct gwp_sock_pair {
	int		tfd;
	int		cfd;
	uint32_t	tfb_len;
	uint32_t	cfb_len;
	char		*tbuf;
	char		*cbuf;
};

struct gwp;

struct gwp_thread {
	int			epl_fd;
	int			evp_fd;
	struct gwp_sock_pair	**sock_pairs;
};

struct gwp_cfg {
	char		bind_addr[256];
	char		target_addr[256];
	uint16_t	nr_threads;
};

struct gwp_ctx {
	int			tcp_fd;
	struct gwp_thread	*threads;
	struct gwp_cfg		cfg;
};

static const struct option long_opts[] = {
	{ "bind",	required_argument,	NULL, 'b' },
	{ "target",	required_argument,	NULL, 't' },
	{ "threads",	required_argument,	NULL, 'n' },
	{ "help",	no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};
static const char short_opts[] = "b:t:n:h";

static void show_usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b, --bind=ADDR       Bind to the specified address\n");
	fprintf(stderr, "  -t, --target=ADDR     Connect to the target address\n");
	fprintf(stderr, "  -n, --threads=NUM     Number of threads to use\n");
	fprintf(stderr, "  -h, --help            Show this help message\n");
	exit(EXIT_FAILURE);
}

static int process_option(const char *progname, int c, struct gwp_cfg *cfg)
{
	size_t len;

	switch (c) {
	case 'b':
		len = sizeof(cfg->bind_addr) - 1;
		strncpy(cfg->bind_addr, optarg, len);
		cfg->bind_addr[len] = '\0';
		break;
	case 't':
		len = sizeof(cfg->target_addr) - 1;
		strncpy(cfg->target_addr, optarg, len);
		cfg->target_addr[len] = '\0';
		break;
	case 'n':
		c = atoi(optarg);
		if (c <= 0) {
			fprintf(stderr, "Invalid number of threads: %s\n", optarg);
			return -EINVAL;
		}
		cfg->nr_threads = c;
		break;
	case 'h':
	default:
		show_usage(progname);
	}
	return 0;
}

static int prepare_gwp_ctx_from_argv(int argc, char *argv[], struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->tcp_fd = -1;
	while (1) {
		ret = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (ret == -1)
			break;

		ret = process_option(argv[0], ret, cfg);
		if (ret)
			return ret;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct gwp_ctx ctx;
	int ret;

	ret = prepare_gwp_ctx_from_argv(argc, argv, &ctx);
	if (ret)
		return -ret;

	return 0;
}
