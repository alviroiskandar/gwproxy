// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 * Link: https://t.me/GNUWeeb/1174779
 *
 * Simple TCP proxy.
 *
 * ./gwproxy --target 127.0.0.1:1111 --bind [::]:8080 -m 16
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include <stdatomic.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/resource.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <linux/limits.h>

enum {
	EV_BIT_ACCEPT		= (0x0001ULL << 48ULL),
	EV_BIT_EVFD		= (0x0002ULL << 48ULL),
	EV_BIT_TARGET_DATA	= (0x0003ULL << 48ULL),
	EV_BIT_CLIENT_DATA	= (0x0004ULL << 48ULL),
	EV_BIT_TIMER		= (0x0005ULL << 48ULL),
	EV_BIT_INOTIFY		= (0x0006ULL << 48ULL),
};

enum {
	SP_STATE_INIT			= 0x00,

	SP_STATE_FWD			= 0x10,

	SP_STATE_SOCKS5_AUTH		= 0x20,
	SP_STATE_SOCKS5_AUTH_USER_PASS	= 0x21,

	SP_STATE_SOCKS5_CMD		= 0x30,
	SP_STATE_SOCKS5_CMD_CONNECT	= 0x31,

	SP_STATE_SOCKS5_ERR		= 0xff,
};

#define ALL_EV_BITS	(EV_BIT_ACCEPT | EV_BIT_EVFD | \
			 EV_BIT_TARGET_DATA | EV_BIT_CLIENT_DATA | \
			 EV_BIT_TIMER | EV_BIT_INOTIFY)
#define GET_EV_BIT(X)	((X) & ALL_EV_BITS)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BITS)
#define NR_EPL_EVENTS	512

#define CFG_DEF_CONNECT_TIMEOUT	5
#define CFG_DEF_NR_THREADS	4
#define CFG_DEF_SEND_BUF_SIZE	4096
#define CFG_DEF_RECV_BUF_SIZE	4096
#define CFG_DEF_NR_ACCEPT_SPIN	32
#define CFG_DEF_SOCKS5_TIMEOUT	10

struct gwp_sock {
	int		fd;
	uint32_t	ep_msk;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
};

struct gwp_sock_pair {
	bool		is_target_alive;
	bool		is_setup_done;
	uint8_t		state;
	uint32_t	idx;
	struct gwp_sock	client;
	struct gwp_sock	target;
	int		tmfd;
	uint32_t	tfb_len;
	uint32_t	cfb_len;
	struct sockaddr_storage addr;
};

struct gwp_sock_bucket {
	struct gwp_sock_pair	**pairs;
	uint32_t		nr_pairs;
	uint32_t		cap_pairs;
};

struct gwp_ctx;

struct gwp_thread {
	int			tcp_fd;
	int			epl_fd;
	int			evp_fd;
	struct gwp_sock_bucket	gsb;
	struct gwp_ctx		*ctx;
	bool			need_reload;
	uint16_t		idx;
	pthread_t		thread;
	struct epoll_event	events[NR_EPL_EVENTS];
};

struct gwp_cfg {
	char		bind_addr[256];
	char		target_addr[256];
	uint32_t	client_buf;
	uint32_t	target_buf;
	uint16_t	nr_threads;
	uint16_t	nr_accept_spin;
	int		connect_timeout;	/* In seconds. */
	bool		socks5;			/* Enable SOCKS5 proxy mode. */
	char		auth_file[256];	/* Authentication file for SOCKS5. */
	int		socks5_timeout;	/* SOCKS5 auth and command timeout in seconds. */
};

struct gwp_socks5_auth_user {
	char	*username;
	char	*password;
};

struct gwp_socks5_auth {
	FILE				*handle;
	int				ino_fd;
	pthread_mutex_t			lock;
	struct gwp_socks5_auth_user	*users;
	size_t				nr_users;
};

struct gwp_ctx {
	volatile bool			stop;
	uint32_t			rr_counter;
	socklen_t			bind_addr_len;
	struct sockaddr_storage		target_addr;
	socklen_t			target_addr_len;
	struct gwp_thread		*threads;
	struct gwp_cfg			cfg;
	struct gwp_socks5_auth		*socks5_auth;
};

static const struct option long_opts[] = {
	{ "bind",		required_argument,	NULL, 'b' },
	{ "target",		required_argument,	NULL, 't' },
	{ "target-buf-size",	required_argument,	NULL, 'w' },
	{ "client-buf-size",	required_argument,	NULL, 'x' },
	{ "threads",		required_argument,	NULL, 'm' },
	{ "nr-accept-spin",	required_argument,	NULL, 'A' },
	{ "connect-timeout",	required_argument,	NULL, 'T' },
	{ "socks5",		no_argument,		NULL, 'S' },
	{ "auth-file",		required_argument,	NULL, 'a' },
	{ "socks5-timeout",	required_argument,	NULL, 'P' },
	{ "help",		no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};
static const char short_opts[] = "b:t:w:x:m:A:T:Sa:P:h";

static int prepare_rlimit(void)
{
	struct rlimit rl;
	int r;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		r = -errno;
		fprintf(stderr, "Failed to get RLIMIT_NOFILE: %s\n", strerror(-r));
		return r;
	}

	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set RLIMIT_NOFILE: %s\n", strerror(-r));
		return r;
	}

	printf("RLIMIT_NOFILE set to %lu\n", (unsigned long)rl.rlim_cur);

	return 0;
}

static void show_usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -b, --bind=ADDR:PORT       Bind to the specified address\n");
	fprintf(stderr, "  -t, --target=ADDR:PORT     Connect to the target address\n");
	fprintf(stderr, "  -w, --target-buf-size=SIZE Set target buffer size (default: %d)\n", CFG_DEF_SEND_BUF_SIZE);
	fprintf(stderr, "  -x, --client-buf-size=SIZE Set client buffer size (default: %d)\n", CFG_DEF_RECV_BUF_SIZE);
	fprintf(stderr, "  -m, --threads=NUM          Number of threads to use (default: %d)\n", CFG_DEF_NR_THREADS);
	fprintf(stderr, "  -A, --nr-accept-spin=NUM   Number of accept spins per event (default: %d)\n", CFG_DEF_NR_ACCEPT_SPIN);
	fprintf(stderr, "  -T, --connect-timeout=SEC  Connection timeout in seconds (default: %d)\n", CFG_DEF_CONNECT_TIMEOUT);
	fprintf(stderr, "  -S, --socks5               Enable SOCKS5 proxy mode\n");
	fprintf(stderr, "  -a, --auth-file=FILE       Specify authentication file for SOCKS5 proxy\n");
	fprintf(stderr, "  -P, --socks5-timeout=SEC   SOCKS5 auth and command timeout in seconds (default: %d)\n", CFG_DEF_SOCKS5_TIMEOUT);
	fprintf(stderr, "  -h, --help                 Show this help message\n");
	exit(EXIT_FAILURE);
}

static int process_option(const char *progname, int c, struct gwp_cfg *cfg)
{
	size_t l;

	switch (c) {
	case 'b':
		l = sizeof(cfg->bind_addr) - 1;
		strncpy(cfg->bind_addr, optarg, l);
		cfg->bind_addr[l] = '\0';
		break;
	case 't':
		l = sizeof(cfg->target_addr) - 1;
		strncpy(cfg->target_addr, optarg, l);
		cfg->target_addr[l] = '\0';
		break;
	case 'w':
		c = atoi(optarg);
		if (c <= 0) {
			fprintf(stderr, "Invalid target buffer size: %s\n", optarg);
			return -EINVAL;
		}
		cfg->target_buf = (uint32_t)c;
		break;
	case 'x':
		c = atoi(optarg);
		if (c <= 0) {
			fprintf(stderr, "Invalid client buffer size: %s\n", optarg);
			return -EINVAL;
		}
		cfg->client_buf = (uint32_t)c;
		break;
	case 'm':
		c = atoi(optarg);
		if (c <= 0) {
			fprintf(stderr, "Invalid number of threads: %s\n", optarg);
			return -EINVAL;
		}
		cfg->nr_threads = (uint16_t)c;
		break;
	case 'A':
		c = atoi(optarg);
		if (c <= 0) {
			fprintf(stderr, "Invalid number of accept spins: %s\n", optarg);
			return -EINVAL;
		}
		cfg->nr_accept_spin = (uint16_t)c;
		break;
	case 'T':
		c = atoi(optarg);
		if (c < 0) {
			fprintf(stderr, "Invalid connect timeout: %s\n", optarg);
			return -EINVAL;
		}
		cfg->connect_timeout = c;
		break;
	case 'S':
		cfg->socks5 = true;
		break;
	case 'a':
		l = sizeof(cfg->auth_file) - 1;
		strncpy(cfg->auth_file, optarg, l);
		cfg->auth_file[l] = '\0';
		if (cfg->socks5 && !*cfg->auth_file) {
			fprintf(stderr, "Authentication file is required for SOCKS5 proxy mode\n");
			return -EINVAL;
		}
		break;
	case 'P':
		c = atoi(optarg);
		if (c < 0) {
			fprintf(stderr, "Invalid SOCKS5 timeout: %s\n", optarg);
			return -EINVAL;
		}
		cfg->socks5_timeout = c;
		break;
	default:
	case 'h':
		show_usage(progname);
		break;
	}
	return 0;
}

static int prepare_gwp_ctx_from_argv(int argc, char *argv[],
				     struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	cfg->nr_threads = CFG_DEF_NR_THREADS;
	cfg->connect_timeout = CFG_DEF_CONNECT_TIMEOUT;
	cfg->client_buf = CFG_DEF_RECV_BUF_SIZE;
	cfg->target_buf = CFG_DEF_SEND_BUF_SIZE;
	cfg->nr_accept_spin = CFG_DEF_NR_ACCEPT_SPIN;
	cfg->socks5_timeout = CFG_DEF_SOCKS5_TIMEOUT;
	ctx->stop = false;
	while (1) {
		ret = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (ret == -1)
			break;

		ret = process_option(argv[0], ret, cfg);
		if (ret)
			return ret;
	}

	if (cfg->socks5) {
		if (cfg->target_buf < 512) {
			fprintf(stderr, "Target buffer size must be at least 512 bytes for SOCKS5 proxy mode\n");
			return -EINVAL;
		}

		if (cfg->client_buf < 512) {
			fprintf(stderr, "Client buffer size must be at least 512 bytes for SOCKS5 proxy mode\n");
			return -EINVAL;
		}
	}

	return 0;
}

static void sock_set_options(int fd)
{
	static const int flg = 1;
	socklen_t l = sizeof(flg);

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flg, l);
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flg, l);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flg, l);
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flg, l);
}

static int create_sock_target(const struct sockaddr_storage *addr_ss,
			      socklen_t addr_len)
{
	static const int flg = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	int fd, err;

	fd = socket(addr_ss->ss_family, flg, 0);
	if (fd < 0)
		return -errno;

	sock_set_options(fd);
	err = connect(fd, (struct sockaddr *)addr_ss, addr_len);
	if (err < 0) {
		err = -errno;
		if (err != -EINPROGRESS) {
			close(fd);
			return err;
		}
	}

	return fd;
}

static void close_sock(struct gwp_sock *s)
{
	if (s->fd >= 0) {
		close(s->fd);
		s->fd = -1;
	}
	s->ep_msk = 0;
	s->len = 0;
}

static void gwp_free_thread_sock_pair(struct gwp_sock_pair *sp)
{
	if (!sp)
		return;

	if (sp->tmfd >= 0)
		close(sp->tmfd);

	free(sp->client.buf);
	free(sp->target.buf);
	close_sock(&sp->client);
	close_sock(&sp->target);
	free(sp);
}

static int del_sock_pair(struct gwp_thread *t, struct gwp_sock_pair *sp)
{
	struct gwp_sock_bucket *gsb = &t->gsb;
	struct gwp_sock_pair *sq;
	uint32_t i = sp->idx;

	sq = gsb->pairs[i];
	assert(sq == sp);
	if (sq != sp)
		return -EINVAL;

	gsb->pairs[i] = gsb->pairs[gsb->nr_pairs - 1];
	gsb->pairs[i]->idx = i;
	gsb->pairs[gsb->nr_pairs - 1] = NULL;
	gsb->nr_pairs--;
	gwp_free_thread_sock_pair(sp);

	if ((gsb->cap_pairs - gsb->nr_pairs) >= 64) {
		/*
		 * Shirk the capacity if many sock pairs have been freed.
		 */
		uint32_t new_cap = gsb->nr_pairs + 2;
		struct gwp_sock_pair **new_pairs;

		new_pairs = realloc(gsb->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return -ENOMEM;

		gsb->pairs = new_pairs;
		gsb->cap_pairs = new_cap;
	}

	return 0;
}

static int add_sock_pair(struct gwp_thread *t, struct gwp_sock_pair *sp)
{
	struct gwp_sock_bucket *gsb = &t->gsb;

	if (gsb->nr_pairs >= gsb->cap_pairs) {
		uint32_t new_cap = (gsb->cap_pairs + 1) * 2;
		struct gwp_sock_pair **new_pairs;

		new_pairs = realloc(gsb->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return -ENOMEM;

		gsb->pairs = new_pairs;
		gsb->cap_pairs = new_cap;
	}

	sp->idx = gsb->nr_pairs;
	gsb->pairs[gsb->nr_pairs++] = sp;
	return 0;
}

static int gwp_send_signal_thread(struct gwp_thread *t)
{
	uint64_t val = 1;

	assert(t->evp_fd >= 0);
	if (write(t->evp_fd, &val, sizeof(val)) != (ssize_t)sizeof(val))
		return -EIO;

	return 0;
}

static int alloc_sock_pair(struct gwp_thread *t, int cfd, int tg_fd,
			   int tm_fd, const struct sockaddr_storage *addr)
{
	struct gwp_cfg *cfg = &t->ctx->cfg;
	struct gwp_sock_pair *sp;
	struct epoll_event ev;
	int r;

	sp = calloc(1, sizeof(*sp));
	if (!sp)
		return -ENOMEM;

	sp->client.fd = cfd;
	sp->client.ep_msk = EPOLLIN | EPOLLRDHUP;
	sp->client.len = 0;
	sp->client.cap = cfg->client_buf;
	sp->client.buf = malloc(cfg->client_buf);
	if (!sp->client.buf) {
		free(sp);
		return -ENOMEM;
	}

	sp->target.fd = tg_fd;
	sp->target.ep_msk = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
	sp->target.len = 0;
	sp->target.cap = cfg->target_buf;
	sp->target.buf = malloc(cfg->target_buf);
	if (!sp->target.buf) {
		free(sp->client.buf);
		free(sp);
		return -ENOMEM;
	}

	sp->tmfd = tm_fd;
	sp->addr = *addr;
	sp->is_target_alive = false;
	r = add_sock_pair(t, sp);
	if (r < 0) {
		free(sp->client.buf);
		free(sp->target.buf);
		free(sp);
		return r;
	}

	/*
	 * At this state, the target host only exists if we are not
	 * running as a socks5 proxy.
	 *
	 * Socks5 proxy mode will handle the target connection
	 * later after the client has sent the SOCKS5 authentication
	 * and command.
	 */
	if (!t->ctx->cfg.socks5) {
		assert(tg_fd >= 0);
		ev.events = sp->target.ep_msk;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_TARGET_DATA;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, tg_fd, &ev);
		if (r < 0) {
			r = -errno;
			goto out_del_pair;
		}
		sp->state = SP_STATE_FWD;
	} else {
		sp->state = SP_STATE_SOCKS5_AUTH;
	}

	ev.events = sp->client.ep_msk;
	ev.data.u64 = 0;
	ev.data.ptr = sp;
	ev.data.u64 |= EV_BIT_CLIENT_DATA;
	r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, cfd, &ev);
	if (r < 0) {
		r = -errno;
		goto out_del_pair;
	}

	if (tm_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, tm_fd, &ev);
		if (r < 0) {
			r = -errno;
			goto out_del_pair;
		}
	}

	sp->is_setup_done = true;
	return r;

out_del_pair:
	sp->client.fd = sp->target.fd = sp->tmfd = -1;
	del_sock_pair(t, sp);
	return r;
}

static int create_timerfd(time_t itv_sec, time_t itv_nsec, time_t iti_sec,
			  time_t iti_nsec)
{
	static const int flg = TFD_CLOEXEC | TFD_NONBLOCK;
	const struct itimerspec ts = {
		.it_value = {
			.tv_sec = itv_sec,
			.tv_nsec = itv_nsec
		},
		.it_interval = {
			.tv_sec = iti_sec,
			.tv_nsec = iti_nsec
		}
	};
	int tm_fd, ret;

	tm_fd = timerfd_create(CLOCK_MONOTONIC, flg);
	if (tm_fd < 0)
		return -errno;

	ret = timerfd_settime(tm_fd, 0, &ts, NULL);
	if (ret < 0) {
		ret = -errno;
		close(tm_fd);
		return ret;
	}

	return tm_fd;
}

static int create_initial_timer(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int timeout = cfg->socks5 ? cfg->socks5_timeout : cfg->connect_timeout;

	if (timeout <= 0)
		return -ENOSYS;

	return create_timerfd(timeout, 0, 0, 0);
}

static int __process_event_accept(struct gwp_thread *t)
{
	static const int flg = SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct gwp_ctx *ctx = t->ctx;
	socklen_t addr_len = ctx->bind_addr_len;
	struct sockaddr_storage addr;
	int cfd, ret, tg_fd = -1, tm_fd;

	cfd = accept4(t->tcp_fd, (struct sockaddr *)&addr, &addr_len, flg);
	if (cfd < 0)
		return -errno;

	sock_set_options(cfd);

	if (!ctx->cfg.socks5) {
		ret = tg_fd = create_sock_target(&ctx->target_addr,
						 ctx->target_addr_len);
		if (tg_fd < 0)
			goto close_cfd;
	}

	ret = tm_fd = create_initial_timer(ctx);
	if (tm_fd < 0 && tm_fd != -ENOSYS)
		goto close_tg_fd;

	ret = alloc_sock_pair(t, cfd, tg_fd, tm_fd, &addr);
	if (!ret)
		return 0;

	if (tm_fd >= 0)
		close(tm_fd);
close_tg_fd:
	close(tg_fd);
close_cfd:
	close(cfd);
	return ret;
}

static int process_event_accept(struct gwp_thread *t)
{
	uint32_t n = t->ctx->cfg.nr_accept_spin;
	int r = 0;

	assert(n);
	while (n--) {
		r = __process_event_accept(t);
		if (r)
			break;
	}

	return (r == -EAGAIN || r == -EINTR) ? 0 : r;
}

static int gwp_recv_signal_thread(struct gwp_thread *t)
{
	uint64_t val;
	ssize_t ret;

	ret = read(t->evp_fd, &val, sizeof(val));
	if (ret < 0) {
		ret = -errno;
		return (ret == -EAGAIN || ret == -EINTR) ? 0 : ret;
	}

	if (ret != (ssize_t)sizeof(val))
		return -EIO;

	return 0;
}

static int do_forward(struct gwp_sock *src, struct gwp_sock *dst,
		      bool do_recv, bool do_send)
{
	ssize_t recv_ret, send_ret;
	uint32_t len, uret;
	char *buf;
	int err;

	buf = src->buf + src->len;
	len = src->cap - src->len;
	if (len > 0 && do_recv) {
		recv_ret = recv(src->fd, buf, len, MSG_NOSIGNAL);
		if (recv_ret < 0) {
			err = -errno;
			if (err != -EAGAIN && err != -EINTR)
				return err;
			recv_ret = 0;
		} else if (!recv_ret) {
			return -ECONNRESET;
		}

		src->len += (uint32_t)recv_ret;
	}

	buf = src->buf;
	len = src->len;
	if (len > 0 && do_send) {
		send_ret = send(dst->fd, buf, len, MSG_NOSIGNAL);
		if (send_ret < 0) {
			err = -errno;
			if (err != -EAGAIN && err != -EINTR)
				return err;
			send_ret = 0;
		} else if (!send_ret) {
			return -ECONNRESET;
		}

		uret = (uint32_t)send_ret;
		assert(uret <= len);
		src->len -= uret;
		if (src->len > 0)
			memmove(buf, &buf[uret], src->len);
	}

	return 0;
}

static void adjust_epoll_out(struct gwp_sock *a, struct gwp_sock *b,
			     int *changed)
{
	if (b->fd < 0)
		return;

	if (a->len > 0) {
		if (!(b->ep_msk & EPOLLOUT)) {
			b->ep_msk |= EPOLLOUT;
			*changed |= 1;
		}
	} else {
		if (b->ep_msk & EPOLLOUT) {
			b->ep_msk &= ~EPOLLOUT;
			*changed |= 1;
		}
	}
}

static void adjust_epoll_in(struct gwp_sock *s, int *changed)
{
	if (s->fd < 0)
		return;

	if (s->cap != s->len) {
		if (!(s->ep_msk & EPOLLIN)) {
			s->ep_msk |= EPOLLIN;
			*changed |= 1;
		}
	} else {
		if (s->ep_msk & EPOLLIN) {
			s->ep_msk &= ~EPOLLIN;
			*changed |= 1;
		}
	}
}

static int adjust_epoll_events(struct gwp_thread *t,
			       struct gwp_sock_pair *sp)
{
	int client_need_ctl = 0;
	int target_need_ctl = 0;
	struct epoll_event ev;
	int r;

	adjust_epoll_out(&sp->target, &sp->client, &client_need_ctl);
	adjust_epoll_in(&sp->client, &client_need_ctl);
	if (sp->is_target_alive) {
		/*
		 * Only adjust the target epoll events if the target
		 * connection is alive, otherwise the target socket
		 * will not be used for forwarding data.
		 */
		adjust_epoll_in(&sp->target, &target_need_ctl);
		adjust_epoll_out(&sp->client, &sp->target, &target_need_ctl);
	}

	if (client_need_ctl) {
		ev.events = sp->client.ep_msk;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_CLIENT_DATA;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_MOD, sp->client.fd, &ev);
		if (r < 0)
			return -errno;
	}

	if (target_need_ctl) {
		ev.events = sp->target.ep_msk;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_TARGET_DATA;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_MOD, sp->target.fd, &ev);
		if (r < 0)
			return -errno;
	}

	return 0;
}

static int handle_socks5_connect_reply(struct gwp_sock_pair *sp, int err);

static int process_event_target_conn(struct gwp_thread *t,
				     struct gwp_sock_pair *sp)
{
	int err = 0, r;
	socklen_t len = sizeof(err);

	if (!sp->is_setup_done)
		return 0;

	r = getsockopt(sp->target.fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (r < 0) {
		r = -errno;
		goto out_del_pair;
	}

	if (sp->state == SP_STATE_SOCKS5_CMD_CONNECT) {
		r = handle_socks5_connect_reply(sp, err);
		if (r < 0)
			goto out_del_pair;
	}

	if (err) {
		r = -err;
		goto out_del_pair;
	}

	if (sp->client.len) {
		r = do_forward(&sp->client, &sp->target, false, true);
		if (r < 0)
			return r;
	}

	if (sp->tmfd >= 0) {
		close(sp->tmfd);
		sp->tmfd = -1;
	}

	sp->is_target_alive = true;
	return adjust_epoll_events(t, sp);

out_del_pair:
	t->need_reload = true;
	return del_sock_pair(t, sp);
}

static int process_event_target_data(struct gwp_thread *t,
				     struct gwp_sock_pair *sp, uint32_t events)
{
	int r;

	if (!sp->is_target_alive)
		return process_event_target_conn(t, sp);

	if (events & EPOLLIN) {
		r = do_forward(&sp->target, &sp->client, true, true);
		if (r)
			return r;
	}

	if (events & EPOLLOUT) {
		r = do_forward(&sp->client, &sp->target, true, true);
		if (r)
			return r;
	}

	if (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
		return -ECONNRESET;

	return adjust_epoll_events(t, sp);
}

static int handle_socks5_state(struct gwp_thread *t,
			       struct gwp_sock_pair *sp);

static int process_event_client_data(struct gwp_thread *t,
				     struct gwp_sock_pair *sp, uint32_t events)
{
	int r;

	if (events & EPOLLIN) {
		r = do_forward(&sp->client, &sp->target, true, sp->is_target_alive);
		if (r)
			return r;
	}

	if (events & EPOLLOUT) {
		r = do_forward(&sp->target, &sp->client, sp->is_target_alive, true);
		if (r)
			return r;
	}

	if (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
		return -ECONNRESET;

	if (sp->state != SP_STATE_FWD) {
		assert(t->ctx->cfg.socks5);
		r = handle_socks5_state(t, sp);
		if (r < 0)
			return r;
	}

	return adjust_epoll_events(t, sp);
}

/*
 * RFC 1928, section 3:
 *
 *    The client connects to the server, and sends a version
 *    identifier/method selection message:
 *
 *                    +----+----------+----------+
 *                    |VER | NMETHODS | METHODS  |
 *                    +----+----------+----------+
 *                    | 1  |    1     | 1 to 255 |
 *                    +----+----------+----------+
 *
 *    The VER field is set to X'05' for this version of the protocol.  The
 *    NMETHODS field contains the number of method identifier octets that
 *    appear in the METHODS field.
 *
 *    The server selects from one of the methods given in METHODS, and
 *    sends a METHOD selection message:
 *
 *                          +----+--------+
 *                          |VER | METHOD |
 *                          +----+--------+
 *                          | 1  |   1    |
 *                          +----+--------+
 *
 *    If the selected METHOD is X'FF', none of the methods listed by the
 *    client are acceptable, and the client MUST close the connection.
 *
 *    The values currently defined for METHOD are:
 *
 *           o  X'00' NO AUTHENTICATION REQUIRED
 *           o  X'01' GSSAPI
 *           o  X'02' USERNAME/PASSWORD
 *           o  X'03' to X'7F' IANA ASSIGNED
 *           o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 *           o  X'FF' NO ACCEPTABLE METHODS
 *
 *    The client and server then enter a method-specific sub-negotiation.
 */
static int handle_socks5_state_auth(struct gwp_thread *t,
				    struct gwp_sock_pair *sp)
{
	struct gwp_cfg *cfg = &t->ctx->cfg;
	struct gwp_sock *s = &sp->client;
	uint8_t nr_methods, *buf = (uint8_t *)s->buf;
	uint32_t len = s->len;
	uint8_t *methods;
	bool found = false;
	int expected_method;

	/*
	 * Must have at least 2 bytes for the version and number of methods.
	 */
	if (len < 2)
		return -EAGAIN;

	if (buf[0] != 0x05)
		return -EINVAL;

	/*
	 * Must have at least 2 + nr_methods bytes for the version, number of
	 * methods, and the methods themselves.
	 */
	nr_methods = buf[1];
	if (len < (2u + nr_methods))
		return -EAGAIN;

	methods = &buf[2];
	if (*cfg->auth_file)
		expected_method = 0x02; /* USERNAME/PASSWORD */
	else
		expected_method = 0x00; /* NO AUTHENTICATION REQUIRED */

	found = !!memchr(methods, expected_method, nr_methods);
	buf = (uint8_t *)sp->target.buf;
	sp->target.len = 2; /* VER, METHOD */
	buf[0] = 0x05; /* VER */
	buf[1] = found ? expected_method : 0xFF; /* METHOD */
	sp->client.len -= (2u + nr_methods);

	if (buf[1] == 0xFF)
		sp->state = SP_STATE_SOCKS5_ERR;
	else
		sp->state = *cfg->auth_file ? SP_STATE_SOCKS5_AUTH_USER_PASS
					    : SP_STATE_SOCKS5_CMD;

	return 0;
}

static bool gwp_auth_check(struct gwp_socks5_auth *gsa, const char *username,
			   const char *password);

static bool gwp_auth_checkl(struct gwp_socks5_auth *gsa, const char *username,
			    uint8_t ulen, const char *password, uint8_t plen)
{
	char u[256], p[256];

	memcpy(u, username, ulen);
	u[ulen] = '\0';

	if (password) {
		memcpy(p, password, plen);
		p[plen] = '\0';
	}

	return gwp_auth_check(gsa, u, password ? p : NULL);
}

/*
 * RFC 1929, section 2:
 *
 *    Once the SOCKS V5 server has started, and the client has selected the
 *    Username/Password Authentication protocol, the Username/Password
 *    subnegotiation begins.  This begins with the client producing a
 *    Username/Password request:
 *
 *            +----+------+----------+------+----------+
 *            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *            +----+------+----------+------+----------+
 *            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *            +----+------+----------+------+----------+
 *
 *    The VER field contains the current version of the subnegotiation,
 *    which is X'01'. The ULEN field contains the length of the UNAME field
 *    that follows. The UNAME field contains the username as known to the
 *    source operating system. The PLEN field contains the length of the
 *    PASSWD field that follows. The PASSWD field contains the password
 *    association with the given UNAME.
 *
 *    The server verifies the supplied UNAME and PASSWD, and sends the
 *    following response:
 *
 *                         +----+--------+
 *                         |VER | STATUS |
 *                         +----+--------+
 *                         | 1  |   1    |
 *                         +----+--------+
 * 
 *    A STATUS field of X'00' indicates success. If the server returns a
 *    `failure' (STATUS value other than X'00') status, it MUST close the
 *    connection.
 */
static int handle_socks5_state_auth_user_pass(struct gwp_thread *t,
					      struct gwp_sock_pair *sp)
{
	struct gwp_sock *s = &sp->client;
	uint32_t len = s->len, needed_len;
	uint8_t *buf = (uint8_t *)s->buf;
	uint8_t ulen, plen;
	char *user, *pass;
	bool auth_ok;

	needed_len = 1;
	if (len < needed_len)
		return -EAGAIN;

	if (buf[0] != 0x01) /* VER */
		return -EINVAL;

	needed_len += 1; /* ULEN */
	if (len < needed_len)
		return -EAGAIN;

	ulen = buf[1];
	if (!ulen)
		return -EINVAL;

	needed_len += ulen + 1; /* UNAME + PLEN */
	if (len < needed_len)
		return -EAGAIN;

	user = (char *)&buf[2];
	plen = buf[2 + ulen];
	needed_len += plen; /* PASSWD */
	if (len < needed_len)
		return -EAGAIN;

	pass = plen ? (char *)&buf[3 + ulen] : NULL;
	s->len -= needed_len;
	auth_ok = gwp_auth_checkl(t->ctx->socks5_auth, user, ulen, pass, plen);

	sp->target.len = 2; /* VER, STATUS */
	buf = (uint8_t *)sp->target.buf;
	buf[0] = 0x01; /* VER */
	if (auth_ok) {
		buf[1] = 0x00; /* STATUS: success */
		sp->state = SP_STATE_SOCKS5_CMD;
	} else {
		buf[1] = 0x01; /* STATUS: failure */
		sp->state = SP_STATE_SOCKS5_ERR;
	}

	return 0;
}

/*
 * RFC 1928, section 6:
 *
 *    The SOCKS request information is sent by the client as soon as it has
 *    established a connection to the SOCKS server, and completed the
 *    authentication negotiations.  The server evaluates the request, and
 *    returns a reply formed as follows:
 *
 *         +----+-----+-------+------+----------+----------+
 *         |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *         +----+-----+-------+------+----------+----------+
 *         | 1  |  1  | X'00' |  1   | Variable |    2     |
 *         +----+-----+-------+------+----------+----------+
 *
 *      Where:
 *
 *           o  VER    protocol version: X'05'
 *           o  REP    Reply field:
 *              o  X'00' succeeded
 *              o  X'01' general SOCKS server failure
 *              o  X'02' connection not allowed by ruleset
 *              o  X'03' Network unreachable
 *              o  X'04' Host unreachable
 *              o  X'05' Connection refused
 *              o  X'06' TTL expired
 *              o  X'07' Command not supported
 *              o  X'08' Address type not supported
 *              o  X'09' to X'FF' unassigned
 *           o  RSV    RESERVED
 *           o  ATYP   address type of following address
 *         o  IP V4 address: X'01'
 *              o  DOMAINNAME: X'03'
 *              o  IP V6 address: X'04'
 *           o  BND.ADDR       server bound address
 *           o  BND.PORT       server bound port in network octet order
 *              o  IP V4 address: X'01'
 *              o  DOMAINNAME: X'03'
 *              o  IP V6 address: X'04'
 *           o  BND.ADDR       server bound address
 *           o  BND.PORT       server bound port in network octet order
 *
 *    Fields marked RESERVED (RSV) must be set to X'00'.
 *
 *    If the chosen method includes encapsulation for purposes of
 *    authentication, integrity and/or confidentiality, the replies are
 *    encapsulated in the method-dependent encapsulation.
 */
static int handle_socks5_connect_reply(struct gwp_sock_pair *sp, int err)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *in = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	socklen_t addr_len = sizeof(addr);
	uint8_t *buf;
	int r;

	if (sp->target.len != 0)
		return -EINVAL;

	if (sp->target.fd >= 0) {
		r = getsockname(sp->target.fd, (struct sockaddr *)&addr, &addr_len);
		if (r < 0)
			return -errno;
	} else {
		memset(&addr, 0, sizeof(addr));
		addr.ss_family = AF_INET;
	}

	assert(sp->target.cap >= (4 + 16 + 2));
	buf = (uint8_t *)sp->target.buf;

	sp->target.len = 4; /* VER, REP, RSV, ATYP */

	buf[0] = 0x05; /* VER */
	switch (err) {
	case 0:
		buf[1] = 0x00; /* Succeeded */
		break;
	case ECONNREFUSED:
		buf[1] = 0x05; /* Connection refused */
		break;
	case ENETUNREACH:
		buf[1] = 0x03; /* Network unreachable */
		break;
	case EHOSTUNREACH:
		buf[1] = 0x04; /* Host unreachable */
		break;
	case EPERM:
	case EACCES:
		buf[1] = 0x02; /* Connection not allowed by ruleset */
		break;
	default:
		buf[1] = 0x01; /* General SOCKS server failure */
		break;
	}
	buf[2] = 0x00; /* RSV */

	if (addr.ss_family == AF_INET) {
		buf[3] = 0x01; /* ATYP: IPv4 */
		memcpy(&buf[4], &in->sin_addr, 4); /* BND.ADDR */
		memcpy(&buf[8], &in->sin_port, 2); /* BND.PORT */
		sp->target.len += 4 + 2;
	} else if (addr.ss_family == AF_INET6) {
		buf[3] = 0x04; /* ATYP: IPv6 */
		memcpy(&buf[4], &in6->sin6_addr, 16); /* BND.ADDR */
		memcpy(&buf[20], &in6->sin6_port, 2); /* BND.PORT */
		sp->target.len += 16 + 2;
	} else {
		return -EINVAL;
	}

	if (sp->tmfd >= 0) {
		close(sp->tmfd);
		sp->tmfd = -1;
	}

	sp->state = err ? SP_STATE_SOCKS5_ERR : SP_STATE_FWD;
	return do_forward(&sp->target, &sp->client, false, true);
}

static int do_connect_socks5_cmd(struct gwp_thread *t,
				 struct gwp_sock_pair *sp,
				 const struct sockaddr_storage *addr_ss)
{
	struct gwp_cfg *cfg = &t->ctx->cfg;
	socklen_t addr_len = 0;
	struct epoll_event ev;
	int r;

	if (sp->tmfd >= 0) {
		close(sp->tmfd);
		sp->tmfd = -1;
	}

	if (addr_ss->ss_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else if (addr_ss->ss_family == AF_INET6)
		addr_len = sizeof(struct sockaddr_in6);
	else
		return -EINVAL;

	sp->target.fd = r = create_sock_target(addr_ss, addr_len);
	if (r < 0) {
		close(sp->tmfd);
		sp->tmfd = -1;
		return r;
	}

	sp->tmfd = r = create_timerfd(cfg->connect_timeout, 0, 0, 0);
	if (r < 0 && r != -ENOSYS)
		goto out_close_target;

	ev.events = EPOLLOUT | EPOLLRDHUP;
	ev.data.u64 = 0;
	ev.data.ptr = sp;
	ev.data.u64 |= EV_BIT_TARGET_DATA;
	r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, sp->target.fd, &ev);
	if (r < 0) {
		r = -errno;
		goto out_close_tmfd;
	}

	if (sp->tmfd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, sp->tmfd, &ev);
		if (r < 0) {
			r = -errno;
			goto out_close_tmfd;
		}
	}

	sp->state = SP_STATE_SOCKS5_CMD_CONNECT;
	return 0;

out_close_tmfd:
	if (sp->tmfd >= 0) {
		close(sp->tmfd);
		sp->tmfd = -1;
	}
out_close_target:
	close(sp->target.fd);
	sp->target.fd = -1;
	return handle_socks5_connect_reply(sp, -r);
}

static int resolve_domain_name(const char *name, uint16_t port,
			       struct sockaddr_storage *addr_ss)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr_ss;
	struct sockaddr_in *in = (struct sockaddr_in *)addr_ss;
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_CANONNAME | AI_ADDRCONFIG
	};
	struct addrinfo *res, *ai;
	bool found = false;
	char port_str[6];
	int r;

	snprintf(port_str, sizeof(port_str), "%hu", port);
	r = getaddrinfo(name, port_str, &hints, &res);
	if (r || !res)
		return -EHOSTUNREACH;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			*in = *(struct sockaddr_in *)ai->ai_addr;
			found = true;
			break;
		} else if (ai->ai_family == AF_INET6) {
			*in6 = *(struct sockaddr_in6 *)ai->ai_addr;
			found = true;
			break;
		}
	}

	freeaddrinfo(res);
	return found ? 0 : -EAFNOSUPPORT;
}

/*
 * RFC 1928, section 4:
 *
 *    Once the method-dependent subnegotiation has completed, the client
 *    sends the request details.  If the negotiated method includes
 *    encapsulation for purposes of integrity checking and/or
 *    confidentiality, these requests MUST be encapsulated in the method-
 *    dependent encapsulation.
 *
 *    The SOCKS request is formed as follows:
 *
 *         +----+-----+-------+------+----------+----------+
 *         |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *         +----+-----+-------+------+----------+----------+
 *         | 1  |  1  | X'00' |  1   | Variable |    2     |
 *         +----+-----+-------+------+----------+----------+
 *
 *      Where:
 *
 *           o  VER    protocol version: X'05'
 *           o  CMD
 *              o  CONNECT X'01'
 *              o  BIND X'02'
 *              o  UDP ASSOCIATE X'03'
 *           o  RSV    RESERVED
 *           o  ATYP   address type of following address
 *              o  IP V4 address: X'01'
 *              o  DOMAINNAME: X'03'
 *              o  IP V6 address: X'04'
 *           o  DST.ADDR       desired destination address
 *           o  DST.PORT desired destination port in network octet
 *              order
 *
 *    The SOCKS server will typically evaluate the request based on source
 *    and destination addresses, and return one or more reply messages, as
 *    appropriate for the request type.
 */
static int handle_socks5_state_cmd(struct gwp_thread *t,
				   struct gwp_sock_pair *sp)
{
	struct sockaddr_storage addr_ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr_ss;
	struct sockaddr_in *in = (struct sockaddr_in *)&addr_ss;
	uint32_t needed_len = 4; /* VER, CMD, RSV, ATYP */
	struct gwp_sock *s = &sp->client;
	uint8_t *buf = (uint8_t *)s->buf;
	uint32_t len = s->len;
	char domain_name[256];
	uint16_t port;
	int r;

	if (len < needed_len)
		return -EAGAIN;

	if (buf[0] != 0x05)
		return -EINVAL;

	/*
	 * Currently, only CONNECT command is supported.
	 */
	if (buf[1] != 0x01)
		return -ENOSYS;

	/*
	 * RSV must be 0x00.
	 */
	if (buf[2] != 0x00)
		return -EINVAL;

	/*
	 * Only IPv4, domain name, and IPv6 are supported
	 */
	if (buf[3] != 0x01 && buf[3] != 0x03 && buf[3] != 0x04)
		return -ENOSYS;

	switch (buf[3]) {
	case 0x01:
		/*
		 * IPv4 address needs 6 bytes (4 bytes for address
		 * and 2 bytes for port).
		 */
		needed_len += 4 + 2;
		break;
	case 0x03:
		/*
		 * Domain name address.
		 * 1 byte for length, followed by the domain name.
		 * The length must be at least 1 and at most 255
		 * bytes. And then 2 bytes for port.
		 */
		if (len < 5)
			return -EAGAIN;

		needed_len += 1 + buf[4] + 2;
		break;
	case 0x04:
		/*
		 * IPv6 address needs 18 bytes (16 bytes for address
		 * and 2 bytes for port).
		 */
		needed_len += 16 + 2;
		break;
	default:
		__builtin_unreachable();
	}

	if (len < needed_len)
		return -EAGAIN;

	sp->client.len -= needed_len;
	memset(&addr_ss, 0, sizeof(addr_ss));
	switch (buf[3]) {
	case 0x01:
		in->sin_family = AF_INET;
		memcpy(&in->sin_addr.s_addr, &buf[4], 4);
		memcpy(&in->sin_port, &buf[8], 2);
		break;
	case 0x03:
		memcpy(domain_name, &buf[5], buf[4]);
		domain_name[buf[4]] = '\0';
		memcpy(&port, &buf[5 + buf[4]], 2);
		port = ntohs(port);
		r = resolve_domain_name(domain_name, port, &addr_ss);
		if (r < 0)
			return handle_socks5_connect_reply(sp, -r);
		break;
	case 0x04:
		in6->sin6_family = AF_INET6;
		memcpy(&in6->sin6_addr, &buf[4], 16);
		memcpy(&in6->sin6_port, &buf[20], 2);
		break;
	}

	return do_connect_socks5_cmd(t, sp, &addr_ss);
}

static int handle_socks5_state(struct gwp_thread *t,
			       struct gwp_sock_pair *sp)
{
	int r;

again:
	switch (sp->state) {
	case SP_STATE_SOCKS5_AUTH:
		r = handle_socks5_state_auth(t, sp);
		break;
	case SP_STATE_SOCKS5_AUTH_USER_PASS:
		r = handle_socks5_state_auth_user_pass(t, sp);
		break;
	case SP_STATE_SOCKS5_CMD:
		r = handle_socks5_state_cmd(t, sp);
		break;
	default:
		assert(0 && "Invalid SOCKS5 state");
		return -EINVAL;
	}

	if (r == -EAGAIN)
		return 0;

	if (sp->target.len) {
		r = do_forward(&sp->target, &sp->client, false, true);
		if (r < 0)
			return r;
	}

	if (sp->state == SP_STATE_SOCKS5_ERR)
		return -ECONNRESET;

	if (sp->client.len > 0)
		goto again;

	return 0;
}

static int gwp_load_auth_file(struct gwp_socks5_auth *gsa);

static int process_event_inotify(struct gwp_thread *t)
{
	static const size_t req_sz = sizeof(struct inotify_event) + NAME_MAX + 1;
	char buf[req_sz * 8];
	struct gwp_socks5_auth *sa;
	struct gwp_ctx *ctx = t->ctx;
	ssize_t ret;

	assert(ctx->cfg.socks5);
	assert(ctx->socks5_auth);

	sa = ctx->socks5_auth;
	ret = read(sa->ino_fd, buf, sizeof(buf));
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;
		return ret;
	}

	printf("Reloading SOCKS5 authentication file: %s\n", ctx->cfg.auth_file);
	return gwp_load_auth_file(sa);
}

static int process_event(struct gwp_thread *t, struct epoll_event *ev)
{
	uint64_t ev_bit = GET_EV_BIT(ev->data.u64);
	void *data;
	int ret = 0;

	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	data = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_ACCEPT:
		ret = process_event_accept(t);
		break;
	case EV_BIT_EVFD:
		ret = gwp_recv_signal_thread(t);
		break;
	case EV_BIT_TARGET_DATA:
		ret = process_event_target_data(t, data, ev->events);
		break;
	case EV_BIT_CLIENT_DATA:
		ret = process_event_client_data(t, data, ev->events);
		break;
	case EV_BIT_TIMER:
		ret = -ETIMEDOUT;
		break;
	case EV_BIT_INOTIFY:
		ret = process_event_inotify(t);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		switch (ev_bit) {
		case EV_BIT_TARGET_DATA:
		case EV_BIT_CLIENT_DATA:
		case EV_BIT_TIMER:
			del_sock_pair(t, data);
			t->need_reload = true;
			ret = 0;
			break;
		}
	}

	return ret;
}

static int process_events(struct gwp_thread *t, int nr_events)
{
	struct gwp_ctx *ctx = t->ctx;
	int i, ret = 0;

	for (i = 0; i < nr_events; i++) {
		ret = process_event(t, &t->events[i]);
		if (ret < 0)
			return ret;

		if (t->need_reload || ctx->stop)
			break;
	}

	return ret;
}

static int grab_events(struct gwp_thread *t)
{
	int ret = epoll_wait(t->epl_fd, t->events, NR_EPL_EVENTS, -1);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			ret = 0;
	}

	return ret;
}

static void *gwp_thread_entry(void *arg)
{
	struct gwp_thread *t = arg;
	struct gwp_ctx *ctx = t->ctx;
	int ret = 0;

	while (!ctx->stop) {
		ret = grab_events(t);
		if (ret < 0)
			break;
		ret = process_events(t, ret);
		if (ret < 0)
			break;
	}

	ctx->stop = true;
	return (void *)(intptr_t)ret;
}

static int parse_str_addr(struct sockaddr_storage *addr,
			  socklen_t *addr_len, const char *str)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *in = (struct sockaddr_in *)addr;
	char tmp[256], *b = tmp, *e;
	int port;

	strncpy(tmp, str, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	if (*b == '[') {
		/*
		 * Parse IPv6 address in square brackets.
		 */
		b++;
		e = strchr(b, ']');
		if (!e)
			return -EINVAL;
		if (e[1] != ':')
			return -EINVAL;
		*e = '\0';
		if (inet_pton(AF_INET6, b, &in6->sin6_addr) <= 0)
			return -EINVAL;
		port = atoi(&e[2]);
		if (port < 0 || port > 65535)
			return -EINVAL;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons((uint16_t)port);
		*addr_len = sizeof(*in6);
	} else {
		/*
		 * Parse IPv4 address.
		 */
		e = strchr(b, ':');
		if (!e)
			return -EINVAL;
		*e = '\0';
		if (inet_pton(AF_INET, b, &in->sin_addr) <= 0)
			return -EINVAL;
		port = atoi(e + 1);
		if (port < 0 || port > 65535)
			return -EINVAL;
		in->sin_family = AF_INET;
		in->sin_port = htons((uint16_t)port);
		*addr_len = sizeof(*in);
	}

	return 0;
}

static int gwp_init_thread_sock(struct gwp_thread *t)
{
	static const int flg = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct gwp_ctx *ctx = t->ctx;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	int fd, err, v;

	if (!ctx->cfg.socks5) {
		err = parse_str_addr(&ctx->target_addr, &ctx->target_addr_len,
				ctx->cfg.target_addr);
		if (err)
			return err;
	}
	err = parse_str_addr(&addr, &addr_len, ctx->cfg.bind_addr);
	if (err)
		return err;
	ctx->bind_addr_len = addr_len;
	fd = socket(addr.ss_family, flg, 0);
	if (fd < 0)
		return -errno;
	v = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));
	err = bind(fd, (struct sockaddr *)&addr, addr_len);
	if (err < 0)
		goto err;
	err = listen(fd, SOMAXCONN);
	if (err < 0)
		goto err;

	t->tcp_fd = fd;
	return 0;

err:
	err = -errno;
	close(fd);
	return err;
}

static void gwp_free_thread_sock(struct gwp_thread *t)
{
	if (t->tcp_fd >= 0) {
		close(t->tcp_fd);
		t->tcp_fd = -1;
	}
}

static int gwp_init_thread_epoll(struct gwp_thread *t)
{
	struct epoll_event ev_ee;
	int err, ep, ev;

	ep = epoll_create1(EPOLL_CLOEXEC);
	if (ep < 0)
		return -errno;
	ev = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev < 0) {
		err = -errno;
		goto err_ep;
	}

	memset(&ev_ee, 0, sizeof(ev_ee));
	ev_ee.events = EPOLLIN;
	ev_ee.data.u64 = EV_BIT_EVFD;
	err = epoll_ctl(ep, EPOLL_CTL_ADD, ev, &ev_ee);
	if (err < 0) {
		err = -errno;
		goto err_ev;
	}

	ev_ee.events = EPOLLIN;
	ev_ee.data.u64 = EV_BIT_ACCEPT;
	err = epoll_ctl(ep, EPOLL_CTL_ADD, t->tcp_fd, &ev_ee);
	if (err < 0) {
		err = -errno;
		goto err_ev;
	}

	t->epl_fd = ep;
	t->evp_fd = ev;
	return 0;

err_ev:
	close(ev);
err_ep:
	close(ep);
	return err;
}

static void gwp_free_thread_epoll(struct gwp_thread *t)
{
	if (t->epl_fd >= 0) {
		close(t->epl_fd);
		t->epl_fd = -1;
	}
	if (t->evp_fd >= 0) {
		close(t->evp_fd);
		t->evp_fd = -1;
	}
}

static int gwp_init_thread_sock_bucket(struct gwp_thread *t)
{
	struct gwp_sock_bucket *gsb = &t->gsb;
	uint32_t cap_pairs = 16;

	gsb->pairs = calloc(cap_pairs, sizeof(*gsb->pairs));
	if (!gsb->pairs)
		return -ENOMEM;

	gsb->nr_pairs = 0;
	gsb->cap_pairs = cap_pairs;
	return 0;
}

static void gwp_free_thread_sock_bucket(struct gwp_thread *t)
{
	struct gwp_sock_bucket *gsb = &t->gsb;
	uint32_t i;

	if (!gsb || !gsb->pairs)
		return;

	for (i = 0; i < gsb->nr_pairs; i++)
		gwp_free_thread_sock_pair(gsb->pairs[i]);

	free(gsb->pairs);
	gsb->pairs = NULL;
	gsb->nr_pairs = 0;
	gsb->cap_pairs = 0;
	memset(gsb, 0, sizeof(*gsb));
}

static int gwp_init_thread_add_inotify_to_epoll(struct gwp_thread *t)
{
	struct gwp_socks5_auth *gsa = t->ctx->socks5_auth;
	struct epoll_event ev;

	if (!gsa)
		return 0;

	assert(t->ctx->cfg.socks5);
	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_INOTIFY;
	return epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, gsa->ino_fd, &ev);
}

static int gwp_init_thread(struct gwp_thread *t)
{
	int ret = gwp_init_thread_sock(t);
	if (ret)
		return ret;
	ret = gwp_init_thread_epoll(t);
	if (ret)
		goto out_free_sock;
	ret = gwp_init_thread_sock_bucket(t);
	if (ret)
		goto out_free_epoll;
	if (t->idx == 0)
		return gwp_init_thread_add_inotify_to_epoll(t);
	ret = pthread_create(&t->thread, NULL, gwp_thread_entry, t);
	if (ret)
		goto out_free_sock_bucket;

	return 0;

out_free_sock_bucket:
	gwp_free_thread_sock_bucket(t);
out_free_epoll:
	gwp_free_thread_epoll(t);
out_free_sock:
	gwp_free_thread_sock(t);
	return ret;
}

static void gwp_free_thread(struct gwp_thread *t)
{
	if (!t)
		return;

	t->ctx->stop = true;
	gwp_send_signal_thread(t);
	pthread_join(t->thread, NULL);
	gwp_free_thread_epoll(t);
	gwp_free_thread_sock_bucket(t);
	gwp_free_thread_sock(t);
}

static int gwp_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_thread *threads;
	uint32_t i;
	int ret;

	if (ctx->cfg.nr_threads == 0)
		return -EINVAL;

	threads = calloc(ctx->cfg.nr_threads, sizeof(*threads));
	if (!threads)
		return -ENOMEM;

	for (i = 0; i < ctx->cfg.nr_threads; i++) {
		threads[i].ctx = ctx;
		threads[i].idx = i;
		ret = gwp_init_thread(&threads[i]);
		if (ret) {
			while (i > 0) {
				i--;
				gwp_free_thread(&threads[i]);
			}
			free(threads);
			return ret;
		}
	}

	ctx->threads = threads;
	return 0;
}

static void gwp_free_auth_users(struct gwp_socks5_auth *gsa)
{
	size_t i;

	if (!gsa || !gsa->users)
		return;

	for (i = 0; i < gsa->nr_users; i++) {
		if (gsa->users[i].username)
			free(gsa->users[i].username);
	}

	free(gsa->users);
	gsa->users = NULL;
	gsa->nr_users = 0;
}

static int gwp_append_auth_user(struct gwp_socks5_auth *gsa, const char *line)
{
	struct gwp_socks5_auth_user *new_users, *cur_user;
	char *colon, *user, *pass;

	if (!gsa || !line)
		return -EINVAL;

	new_users = realloc(gsa->users, (gsa->nr_users + 1) * sizeof(*new_users));
	if (!new_users)
		return -ENOMEM;
	gsa->users = new_users;

	user = strdup(line);
	if (!user) {
		fprintf(stderr, "Failed to allocate memory for auth user: %s\n", line);
		return -ENOMEM;
	}

	colon = strchr(user, ':');
	if (colon)
		*colon = '\0';

	pass = colon ? colon + 1 : NULL;
	if (pass && !*pass)
		pass = NULL;

	cur_user = &gsa->users[gsa->nr_users++];
	cur_user->username = user;
	cur_user->password = pass;
	return 0;
}

static int __gwp_load_auth_file(struct gwp_socks5_auth *gsa)
{
	char buf[256 + 256], *p;
	uint32_t line = 0;
	size_t len;
	int r;

	gwp_free_auth_users(gsa);
	while (1) {
		p = fgets(buf, sizeof(buf), gsa->handle);
		if (!p)
			break;

		line++;
		len = strlen(p);
		if (!len)
			continue;

		if (p[len - 1] == '\n')
			p[--len] = '\0';

		if (!len) {
			/*
			 * Skip empty lines.
			 */
			continue;
		}

		/*
		 * A line is only allowed to have a maximum of 255 + 255 + 1
		 * characters, which is 511 characters in total because the
		 * max possible username and password length is 255 characters
		 * each. Plus one character for the colon between them.
		 */
		if (len > 511) {
			fprintf(stderr,
				"Line too long in auth file: '%s' at line %d\n",
				p, line);
			return -EINVAL;
		}

		r = gwp_append_auth_user(gsa, p);
		if (r < 0) {
			fprintf(stderr, "Failed to add auth user: %s\n",
				strerror(-r));
			return r;
		}
	}

	printf("Loaded %zu users from the auth file.\n", gsa->nr_users);
	rewind(gsa->handle);
	return 0;
}

static int gwp_load_auth_file(struct gwp_socks5_auth *gsa)
{
	int r, fd = fileno(gsa->handle);

	/*
	 * The mutex protects from other threads trying to read the
	 * auth array.
	 *
	 * The flock() call protects from other processes trying to
	 * write to the file while we read it (lock shared / LOCK_SH).
	 *
	 * Other processes SHOULD use flock() to lock the file
	 * before writing to it, so that we can read it safely. 
	 */
	pthread_mutex_lock(&gsa->lock);
	flock(fd, LOCK_SH);
	r = __gwp_load_auth_file(gsa);
	flock(fd, LOCK_UN);
	pthread_mutex_unlock(&gsa->lock);
	return r;
}

static bool __gwp_auth_check(struct gwp_socks5_auth *gsa, const char *username,
			     const char *password)
{
	size_t i;

	for (i = 0; i < gsa->nr_users; i++) {
		const char *u = gsa->users[i].username;
		const char *p = gsa->users[i].password;

		if (strcmp(u, username))
			continue;

		if (!p && (!password || !*password))
			return true;

		if (p && password && !strcmp(p, password))
			return true;
	}

	return false;
}

static bool gwp_auth_check(struct gwp_socks5_auth *gsa, const char *username,
			   const char *password)
{
	bool r;
	pthread_mutex_lock(&gsa->lock);
	r = __gwp_auth_check(gsa, username, password);
	pthread_mutex_unlock(&gsa->lock);
	return r;
}

static int gwp_init_auth_file(struct gwp_ctx *ctx)
{
	struct gwp_socks5_auth *gsa;
	int r;

	if (!*ctx->cfg.auth_file)
		return 0;

	if (!ctx->cfg.socks5) {
		fprintf(stderr, "Auth file is only supported with SOCKS5 mode\n");
		return -EINVAL;
	}

	gsa = malloc(sizeof(*gsa));
	if (!gsa) {
		fprintf(stderr, "Failed to allocate memory for auth file\n");
		return -ENOMEM;
	}

	gsa->handle = fopen(ctx->cfg.auth_file, "rb");
	if (!gsa->handle) {
		r = -errno;
		fprintf(stderr, "Failed to open auth file '%s': %s\n",
			ctx->cfg.auth_file, strerror(-r));
		goto err_free_gsa;
	}

	gsa->ino_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (gsa->ino_fd < 0) {
		r = -errno;
		fprintf(stderr, "Failed to create inotify fd for auth file '%s': %s\n",
			ctx->cfg.auth_file, strerror(-r));
		goto err_fclose_handle;
	}

	r = inotify_add_watch(gsa->ino_fd, ctx->cfg.auth_file,
			      IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to add inotify watch for auth file '%s': %s\n",
			ctx->cfg.auth_file, strerror(-r));
		goto err_close_ino_fd;
	}

	r = pthread_mutex_init(&gsa->lock, NULL);
	if (r) {
		fprintf(stderr, "Failed to initialize mutex for auth file '%s': %s\n",
			ctx->cfg.auth_file, strerror(r));
		goto err_close_ino_fd;
	}

	r = gwp_load_auth_file(gsa);
	if (r < 0) {
		fprintf(stderr, "Failed to load auth file '%s': %s\n",
			ctx->cfg.auth_file, strerror(-r));
		goto err_destroy_lock;
	}

	ctx->socks5_auth = gsa;
	return 0;

err_destroy_lock:
	pthread_mutex_destroy(&gsa->lock);
err_close_ino_fd:
	close(gsa->ino_fd);
err_fclose_handle:
	fclose(gsa->handle);
err_free_gsa:
	free(gsa);
	return r;
}

static void gwp_free_auth_file(struct gwp_ctx *ctx)
{
	struct gwp_socks5_auth *gsa = ctx->socks5_auth;

	if (!gsa)
		return;

	fclose(gsa->handle);
	close(gsa->ino_fd);
	gwp_free_auth_users(gsa);
	pthread_mutex_destroy(&gsa->lock);
	free(gsa);
	ctx->socks5_auth = NULL;
}

static int gwp_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_init_auth_file(ctx);
	if (r)
		return r;

	r = gwp_init_threads(ctx);
	if (r) {
		gwp_free_auth_file(ctx);
		return r;
	}

	return 0;
}

static void gwp_free(struct gwp_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->stop = true;

	if (ctx->threads) {
		uint32_t i;

		for (i = 0; i < ctx->cfg.nr_threads; i++)
			gwp_free_thread(&ctx->threads[i]);
		free(ctx->threads);
		ctx->threads = NULL;
	}
}

static int gwp_run(struct gwp_ctx *ctx)
{
	return (intptr_t)gwp_thread_entry(ctx->threads);
}

int main(int argc, char *argv[])
{
	struct gwp_ctx ctx;
	int ret;

	ret = prepare_rlimit();
	if (ret) {
		fprintf(stderr, "Failed to set resource limits: %s\n",
			strerror(-ret));
		return -ret;
	}

	ret = prepare_gwp_ctx_from_argv(argc, argv, &ctx);
	if (ret)
		return -ret;

	ret = gwp_init(&ctx);
	if (ret) {
		fprintf(stderr, "Failed to initialize gwp ctx: %s\n",
			strerror(-ret));
		return -ret;
	}

	ret = gwp_run(&ctx);
	if (ret)
		fprintf(stderr, "Failed to run gwp: %s\n", strerror(-ret));

	gwp_free(&ctx);
	return -ret;
}
