// SPDX-License-Identifier: GPL-2.0-only
/*
 * Author: Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 * -- (( Year: 2025 )) --
 *
 * Simple TCP proxy.
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

#define DEBUG_LEVEL 3
#define pr_debug(LEVEL, FMT, ...)	\
do {					\
	if (DEBUG_LEVEL >= (LEVEL)) {	\
		fprintf(stderr, FMT "\n", __VA_ARGS__);	\
	}				\
} while (0)

enum {
	EV_BIT_ACCEPT		= (0x0001ULL << 48ULL),
	EV_BIT_EVFD		= (0x0002ULL << 48ULL),
	EV_BIT_TARGET_DATA	= (0x0003ULL << 48ULL),
	EV_BIT_CLIENT_DATA	= (0x0004ULL << 48ULL),
	EV_BIT_TIMER		= (0x0005ULL << 48ULL),
};

#define ALL_EV_BITS	(EV_BIT_ACCEPT | EV_BIT_EVFD | \
				EV_BIT_TARGET_DATA | EV_BIT_CLIENT_DATA | \
				EV_BIT_TIMER)
#define GET_EV_BIT(X)	((X) & ALL_EV_BITS)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BITS)
#define NR_EPL_EVENTS	16

#define CFG_DEF_CONNECT_TIMEOUT	5U
#define CFG_DEF_NR_THREADS	4U
#define CFG_DEF_SEND_BUF_SIZE	4096
#define CFG_DEF_RECV_BUF_SIZE	4096
#define CFG_DEF_NR_ACCEPT_SPIN	32U

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
};

struct gwp_ctx {
	volatile bool			stop;
	uint32_t			rr_counter;
	socklen_t			bind_addr_len;
	struct sockaddr_storage		target_addr;
	socklen_t			target_addr_len;
	struct gwp_thread		*threads;
	struct gwp_cfg			cfg;
};

static const struct option long_opts[] = {
	{ "bind",		required_argument,	NULL, 'b' },
	{ "target",		required_argument,	NULL, 't' },
	{ "target-buf-size",	required_argument,	NULL, 'w' },
	{ "client-buf-size",	required_argument,	NULL, 'x' },
	{ "threads",		required_argument,	NULL, 'm' },
	{ "nr-accept-spin",	required_argument,	NULL, 'A' },
	{ "connect-timeout",	required_argument,	NULL, 'T' },
	{ "help",		no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};
static const char short_opts[] = "b:t:w:x:m:A:T:h";

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
	ctx->stop = false;
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

static void sock_set_options(int fd)
{
	static const int flg = 1;
	socklen_t l = sizeof(flg);

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flg, l);
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flg, l);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flg, l);
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flg, l);
}

static int create_sock_target(struct gwp_ctx *c)
{
	static const int flg = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct sockaddr *addr = (struct sockaddr *)&c->target_addr;
	socklen_t addr_len = c->target_addr_len;
	int fd, err;

	fd = socket(c->target_addr.ss_family, flg, 0);
	if (fd < 0)
		return -errno;

	sock_set_options(fd);
	err = connect(fd, addr, addr_len);
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
		uint32_t new_cap = gsb->nr_pairs;
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
		uint32_t new_cap = gsb->cap_pairs * 2;
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

	ev.events = sp->target.ep_msk;
	ev.data.u64 = 0;
	ev.data.ptr = sp;
	ev.data.u64 |= EV_BIT_TARGET_DATA;
	r = epoll_ctl(t->epl_fd, EPOLL_CTL_ADD, tg_fd, &ev);
	if (r < 0) {
		r = -errno;
		goto out_del_pair;
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

static int create_connect_timer(struct gwp_ctx *ctx)
{
	static const int flg = TFD_CLOEXEC | TFD_NONBLOCK;
	struct gwp_cfg *cfg = &ctx->cfg;
	const struct itimerspec ts = {
		.it_value = {
			.tv_sec = cfg->connect_timeout,
			.tv_nsec = 0
		},
		.it_interval = {
			.tv_sec = 0,
			.tv_nsec = 0
		}
	};
	int tm_fd, ret;

	if (cfg->connect_timeout <= 0)
		return -ENOSYS;

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

static int __process_event_accept(struct gwp_thread *t)
{
	static const int flg = SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct gwp_ctx *ctx = t->ctx;
	socklen_t addr_len = ctx->bind_addr_len;
	struct sockaddr_storage addr;
	int cfd, ret, tg_fd, tm_fd;

	cfd = accept4(t->tcp_fd, (struct sockaddr *)&addr, &addr_len, flg);
	if (cfd < 0)
		return -errno;

	sock_set_options(cfd);

	ret = tg_fd = create_sock_target(ctx);
	if (tg_fd < 0)
		goto close_cfd;

	ret = tm_fd = create_connect_timer(ctx);
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
	adjust_epoll_out(&sp->client, &sp->target, &target_need_ctl);
	adjust_epoll_in(&sp->client, &client_need_ctl);
	adjust_epoll_in(&sp->target, &target_need_ctl);

	if (client_need_ctl) {
		ev.events = sp->client.ep_msk;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_CLIENT_DATA;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_MOD, sp->client.fd, &ev);
		if (r < 0) {
			r = -errno;
			return r;
		}
	}

	if (target_need_ctl) {
		ev.events = sp->target.ep_msk;
		ev.data.u64 = 0;
		ev.data.ptr = sp;
		ev.data.u64 |= EV_BIT_TARGET_DATA;
		r = epoll_ctl(t->epl_fd, EPOLL_CTL_MOD, sp->target.fd, &ev);
		if (r < 0) {
			r = -errno;
			return r;
		}
	}

	return 0;
}

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

	if (err) {
		r = -err;
		goto out_del_pair;
	}

	if (sp->client.len) {
		r = do_forward(&sp->target, &sp->client, false, true);
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
		r = do_forward(&sp->client, &sp->target, true, sp->is_target_alive);
		if (r)
			return r;
	}

	if (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
		return -ECONNRESET;

	return adjust_epoll_events(t, sp);
}

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
		r = do_forward(&sp->target, &sp->client, true, true);
		if (r)
			return r;
	}

	if (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
		return -ECONNRESET;

	return adjust_epoll_events(t, sp);
}

static int process_event(struct gwp_thread *t, struct epoll_event *ev)
{
	uint64_t orig_bit = ev->data.u64;
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
	default:
		fprintf(stderr, "Unknown event bit: %#" PRIx64 "\n", ev_bit);
		fprintf(stderr, "Original event bit: %#" PRIx64 "\n", orig_bit);
		fprintf(stderr, "Thread index: %u\n", t->idx);
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

	err = parse_str_addr(&ctx->target_addr, &ctx->target_addr_len,
			     ctx->cfg.target_addr);
	if (err)
		return err;
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
		return 0;
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

static int gwp_init(struct gwp_ctx *ctx)
{
	return gwp_init_threads(ctx);
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
