// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_H
#define GWPROXY_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <gwproxy/syscall.h>
#include <gwproxy/socks5.h>
#include <gwproxy/auth.h>
#include <gwproxy/http.h>
#include <gwproxy/dns.h>
#include <gwproxy/acl.h>
#include <gwproxy/log.h>
#include <assert.h>
#ifdef CONFIG_IO_URING
#include <liburing.h>
#endif

#ifdef CONFIG_NEW_DNS_RESOLVER
#include <gwproxy/dns_resolver.h>
#endif

#include <gwproxy/http1.h>

/*
 * Forward declarations for the optional TLS module (src/gwproxy/ssl.c, built
 * only under CONFIG_HTTPS). The pointers below are always present but stay NULL
 * and unused unless TLS is compiled in and configured.
 */
struct gwp_ssl_ctx;
struct gwp_ssl;
struct gwp_iou_tls;
struct gwp_iou_udp;
struct gwp_acl;

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	bool		as_http;
	bool		udp_associate;	/* allow SOCKS5 UDP ASSOCIATE (default on) */
	bool		prefer_ipv6;
	bool		use_raw_dns;
	int		protocol_timeout;
	const char	*auth_file;
	const char	*acl_file;
	bool		acl_allow_all;	/* skip the built-in default ACL */
	int		dns_cache_secs;
	int		nr_workers;
	int		nr_dns_workers;
	int		connect_timeout;
	/*
	 * Happy Eyeballs Connection Attempt Delay in milliseconds (RFC 8305
	 * Section 5): how long before the next candidate address joins the
	 * race. 0 disables racing, leaving plain sequential fallback.
	 */
	int		connect_attempt_delay;
	int		target_buf_size;
	int		client_buf_size;
	bool		tcp_nodelay;
	bool		tcp_quickack;
	bool		tcp_keepalive;
	int		tcp_keepidle;
	int		tcp_keepintvl;
	int		tcp_keepcnt;
	int		log_level;
	const char	*log_file;
	const char	*pid_file;
	const char	*dns_servers;
	const char	*upstream_proxy;
	int		mark;
	bool		as_transparent;
	const char	*tls_cert;
	const char	*tls_key;
};

struct gwp_ctx;

enum {
	GWP_UPSTREAM_SOCKS5	= 0,
	GWP_UPSTREAM_HTTP	= 1,
};

/*
 * Parsed form of the --upstream-proxy option. When @enabled, every outgoing
 * connection is routed through this upstream proxy instead of being connected
 * to directly. The URL scheme picks @type (socks5[h]:// vs http[s]://) and, for
 * HTTP, whether the hop to the proxy is TLS (@use_tls, https://). Populated once
 * at startup and shared read-only by all workers.
 */
struct gwp_upstream {
	bool			enabled;
	uint8_t			type;		/* GWP_UPSTREAM_SOCKS5 / HTTP */
	bool			remote_dns;	/* socks5h:// (proxy resolves) */
	bool			use_tls;	/* https:// (TLS to the proxy) */
	bool			has_auth;
	uint8_t			ulen;
	uint8_t			plen;
	struct gwp_sockaddr	addr;		/* proxy endpoint */
	char			user[256];
	char			pass[256];
};

int gwp_parse_upstream(const char *url, struct gwp_upstream *up);

/*
 * How many of a name's addresses one connection may try. The resolver can hand
 * back more (GWP_DNS_MAX_ADDRS); this bounds what is copied per connection,
 * since every candidate costs memory in every conn pair.
 */
#define GWP_MAX_CONN_CAND	4u

enum {
	EV_BIT_ACCEPT			= (1ull << 48ull),
	EV_BIT_EVENTFD			= (2ull << 48ull),
	EV_BIT_TARGET			= (3ull << 48ull),
	EV_BIT_CLIENT			= (4ull << 48ull),
	EV_BIT_TIMER			= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5		= (6ull << 48ull),
	EV_BIT_DNS_QUERY		= (7ull << 48ull),
	EV_BIT_SOCKS5_AUTH_FILE		= (8ull << 48ull),

	/*
	 * Raw DNS resolver socket (--raw-dns), epoll only. Values 9-21 belong
	 * to the io_uring selectors below, so use 26 -- this used to be 19,
	 * which is EV_BIT_IOU_TLS_HS_SEND.
	 */
	EV_BIT_RAW_DNS_QUERY		= (26ull << 48ull),

	/*
	 * Per-connection UDP relay socket for a SOCKS5 UDP ASSOCIATE. Values
	 * 9-21 are reserved by the io_uring aliases below, so use 22.
	 */
	EV_BIT_UDP_RELAY		= (22ull << 48ull),

	/*
	 * inotify watch for the ACL rule file (--acl-file); 23-24 are the
	 * io_uring UDP relay aliases below, so use 25.
	 */
	EV_BIT_ACL_FILE			= (25ull << 48ull),

	/*
	 * This ev_bit is used for user_data masking during protocol
	 * initalization.
	 *
	 * Supported protocols:
	 *   - SOCKS5
	 *   - HTTP
	 *
	 * It means it waits for the data specific protocol before
	 * solely forwarding the received data to the destination host.
	 */
	/*
	 * One in-flight connect attempt of a Happy Eyeballs race, plus N for
	 * the attempt's slot, so the completion can be attributed without
	 * disturbing the conn-pair pointer in the low bits. Values 32..47 are
	 * reserved for this.
	 */
	EV_BIT_TARGET_ATTEMPT		= (32ull << 48ull),

	/* Fires when it is time to start the next attempt in the race. */
	EV_BIT_ATTEMPT_TIMER		= (48ull << 48ull),

	EV_BIT_CLIENT_PROT		= (1000ull << 48ull),

#ifdef CONFIG_IO_URING
	/*
	 * Only used by io_uring.
	 */
	EV_BIT_IOU_DNS_QUERY		= EV_BIT_DNS_QUERY,
	EV_BIT_IOU_SOCKS5_AUTH_FILE	= EV_BIT_SOCKS5_AUTH_FILE,
	EV_BIT_IOU_TIMER		= EV_BIT_TIMER,
	EV_BIT_IOU_ACCEPT		= EV_BIT_ACCEPT,
	EV_BIT_IOU_CLIENT_PROT		= EV_BIT_CLIENT_SOCKS5,
	EV_BIT_IOU_CLIENT_RECV		= EV_BIT_CLIENT,
	EV_BIT_IOU_TARGET_RECV		= EV_BIT_TARGET,
	EV_BIT_IOU_TARGET_SEND		= (9ull << 48ull),
	EV_BIT_IOU_CLIENT_SEND		= (10ull << 48ull),
	EV_BIT_IOU_CLOSE		= (11ull << 48ull),
	/* 12 was the single target connect, now EV_BIT_TARGET_ATTEMPT. */
	EV_BIT_IOU_TARGET_CANCEL	= (13ull << 48ull),
	EV_BIT_IOU_CLIENT_CANCEL	= (14ull << 48ull),
	EV_BIT_IOU_TIMER_DEL		= (15ull << 48ull),
	EV_BIT_IOU_MSG_RING		= (16ull << 48ull),
	EV_BIT_IOU_TLS_DETECT		= (17ull << 48ull),
	EV_BIT_IOU_TLS_HS_RECV		= (18ull << 48ull),
	EV_BIT_IOU_TLS_HS_SEND		= (19ull << 48ull),
	EV_BIT_IOU_UPSTREAM_S5		= (20ull << 48ull),
	EV_BIT_IOU_ACCEPT_RETRY		= (21ull << 48ull),

	/*
	 * SOCKS5 UDP relay on io_uring. The recvmsg reuses the shared
	 * EV_BIT_UDP_RELAY (22); the sendmsg and the fd-cancel need their own
	 * selectors so the completion dispatch can tell them apart.
	 */
	EV_BIT_IOU_UDP_RX		= EV_BIT_UDP_RELAY,
	EV_BIT_IOU_UDP_TX		= (23ull << 48ull),
	EV_BIT_IOU_UDP_CANCEL		= (24ull << 48ull),
	EV_BIT_IOU_ACL_FILE		= EV_BIT_ACL_FILE,

	/*
	 * Happy Eyeballs on io_uring. The attempt-delay timeout shares the
	 * generic EV_BIT_ATTEMPT_TIMER selector, but it needs a removal key
	 * distinct from the connect timer's (EV_BIT_IOU_TIMER | gcp): the two
	 * are live at the same time, and io_uring_prep_timeout_remove()
	 * addresses a timeout solely by its user_data. A losing attempt's
	 * socket is retired with its own cancel selector so the completion is
	 * not mistaken for the adopted target's.
	 */
	EV_BIT_IOU_ATTEMPT_TIMER	= EV_BIT_ATTEMPT_TIMER,
	EV_BIT_IOU_ATTEMPT_TIMER_DEL	= (49ull << 48ull),
	EV_BIT_IOU_ATTEMPT_CANCEL	= (50ull << 48ull),
#endif
};


/*
 * The event word packs a payload pointer in bits 0..47 and a selector in bits
 * 48..63. That is sound on Linux because the kernel will not hand userspace a
 * virtual address above the 47-bit default mapping window unless the process
 * asks for one with an mmap() hint above 2^47 -- a policy the kernel adopted
 * *precisely* to keep pointer-tagging schemes like this one working when
 * 5-level paging widened the hardware VA to 57 bits. See
 * Documentation/arch/x86/x86_64/5level-paging.rst ("we are not going to
 * allocate virtual address space above 47-bit by default") and
 * Documentation/arch/arm64/memory.rst, where the default window is 48-bit and
 * 52-bit needs the same opt-in. Note bit 47 is live on arm64, which is why the
 * selector starts at 48 and not 47.
 *
 * gwproxy never opts in: every tagged payload comes from calloc(), and there
 * is no mmap()/MAP_FIXED/arch_prctl() anywhere in this tree. So a 57-bit-VA
 * host does not break the encoding.
 *
 * Do not introduce a high mmap() hint, arm64 MTE/HWASAN heap tagging, or x86
 * LAM without revisiting this. EV_PTR_OK() is the enforcement, and it is
 * deliberately not assert(): release builds define NDEBUG (Makefile, configure)
 * and would compile the check out exactly where it matters.
 *
 * Combine the halves arithmetically, never by writing a pointer through one
 * union member and the selector through another -- on a 32-bit big-endian
 * target epoll_data.ptr aliases the *high* half of .u64 and the two overlap.
 */
#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)
#define EV_PTR_OK(P)	(!((uint64_t)(uintptr_t)(P) & EV_BIT_ALL))

static_assert((EV_BIT_CLIENT_PROT & ~EV_BIT_ALL) == 0,
	      "the largest event selector must fit inside EV_BIT_ALL");

enum {
	CONN_STATE_INIT			= 0,
	CONN_STATE_FORWARDING		= 1,

	CONN_STATE_SOCKS5_MIN		= 100,
	CONN_STATE_SOCKS5_DATA		= 101,
	CONN_STATE_SOCKS5_CONNECT	= 102,
	CONN_STATE_SOCKS5_UDP_ASSOCIATE	= 103,	/* relay active; TCP conn idle */
	CONN_STATE_SOCKS5_DNS_QUERY	= 104,
	CONN_STATE_SOCKS5_MAX		= 199,

	/*
	 * The target socket is connected to an upstream SOCKS5 proxy and we
	 * are performing the client-side handshake with it before forwarding.
	 */
	CONN_STATE_UPSTREAM_S5_MIN	= 200,
	CONN_STATE_UPSTREAM_S5_METHOD	= 201,	/* await method selection    */
	CONN_STATE_UPSTREAM_S5_AUTH	= 202,	/* await user/pass status    */
	CONN_STATE_UPSTREAM_S5_CONNECT	= 203,	/* await CONNECT reply       */
	CONN_STATE_UPSTREAM_S5_MAX	= 299,

	/*
	 * The target socket is connected to an upstream HTTP proxy and we are
	 * performing an HTTP CONNECT to it before forwarding.
	 */
	CONN_STATE_UPSTREAM_HTTP_MIN	= 300,
	CONN_STATE_UPSTREAM_HTTP_CONNECT = 301,	/* await "HTTP/1.x 2xx"      */
	CONN_STATE_UPSTREAM_HTTP_MAX	= 399,

	CONN_STATE_HTTP_MIN		= 400,
	CONN_STATE_HTTP_HDR		= 401,
	CONN_STATE_HTTP_CONNECT		= 402,
	CONN_STATE_HTTP_DNS_QUERY	= 403,
	CONN_STATE_HTTP_MAX		= 499,

	/*
	 * Still waiting for protocol specific. Can be one of these:
	 *    - SOCKS5
	 *    - HTTP
	 */
	CONN_STATE_PROT			= 500,

	/*
	 * HTTPS proxy: the listener may speak TLS. TLS_DETECT peeks the first
	 * byte to tell a TLS ClientHello (0x16) from a plaintext SOCKS5/HTTP
	 * client; TLS_HANDSHAKE runs the server-side handshake. Both are
	 * serviced under EV_BIT_CLIENT_PROT (EPOLLIN and EPOLLOUT). On success
	 * the connection continues at CONN_STATE_PROT on the decrypted stream.
	 */
	CONN_STATE_TLS_MIN		= 600,
	CONN_STATE_TLS_DETECT		= 601,
	CONN_STATE_TLS_HANDSHAKE	= 602,
	CONN_STATE_TLS_MAX		= 699,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;

	/*
	 * Half-close bookkeeping for the forwarding path. @rd_eof is set once
	 * this fd's read side has reached EOF (the peer closed its write side
	 * and we have drained everything). @wr_shut is set once we have shut
	 * this fd's write side (propagated the peer's EOF towards it). The
	 * connection pair is torn down only after both directions have been
	 * fully drained and shut, so no buffered data is dropped on close.
	 */
	bool		rd_eof;
	bool		wr_shut;

	/*
	 * TLS state for this endpoint (HTTPS proxy). NULL for a plaintext
	 * endpoint; only the client side is ever TLS in this cut. Once set and
	 * the handshake has completed, __do_recv()/__do_send() transparently
	 * decrypt/encrypt through it. Owned here and released in
	 * gwp_free_conn_pair().
	 */
	struct gwp_ssl	*tls;
};

enum {
	/*
	 * Don't close the file descriptor when freeing the connection pair.
	 */
	GWP_CONN_FLAG_NO_CLOSE_FD	= (1ull << 0ull),
	GWP_CONN_FLAG_IS_DYING		= (1ull << 1ull),
	GWP_CONN_FLAG_IS_CANCEL		= (1ull << 2ull),
	/*
	 * At least one candidate address made it past the OUTPUT chain, so a
	 * later denial cannot be the reason the request failed. Sticky for the
	 * life of the pair: the candidate walk is re-entered once per failed
	 * attempt, and a local would only remember the most recent walk.
	 */
	GWP_CONN_FLAG_ACL_CAND_OK	= (1ull << 3ull),
};

enum {
	GWP_PROT_TYPE_NONE	= 0,
	GWP_PROT_TYPE_SOCKS5	= 1,
	GWP_PROT_TYPE_HTTP	= 2,
};

struct gwp_dns_packet;

/*
 * Per-connection socket options that the ACL OUTPUT chain can impose on the
 * outgoing target socket (composable -j MARK / -j BIND modifiers). Built from
 * the ACL result and applied in gwp_create_sock_target() before connect(). A
 * NULL pointer (or all-unset fields) means "use the global defaults".
 */
struct gwp_conn_sockopt {
	bool			mark_set;	/* -j MARK: use @mark, not cfg.mark */
	uint32_t		mark;		/* SO_MARK value */
	struct gwp_acl_bind	bind;		/* -j BIND: bind.set when present */
};

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	uint8_t			prot_type;

#ifdef CONFIG_IO_URING
	int				ref_cnt;
	struct __kernel_timespec	ts;
	/*
	 * The Connection Attempt Delay needs its own timespec: an armed
	 * io_uring timeout keeps reading the struct it was given, so it cannot
	 * share @ts with the connect timer that is live alongside it.
	 * @attempt_timer_armed tracks whether one is outstanding, since
	 * io_uring has no timerfd to test for.
	 */
	struct __kernel_timespec	ats;
	bool				attempt_timer_armed;
#ifdef CONFIG_HTTPS
	/*
	 * Persistent ciphertext scratch for the client's TLS on the io_uring
	 * loop. Unlike epoll (synchronous stack scratch), an async recv/send
	 * needs the wire buffers to outlive the operation. Allocated when a TLS
	 * handshake starts, freed in gwp_free_conn_pair().
	 */
	struct gwp_iou_tls		*tls_io;
#endif
#endif

	uint64_t		flags;
	int			conn_state;
	int			timer_fd;

	/*
	 * SOCKS5 UDP ASSOCIATE relay. @udp_fd is the per-connection bound UDP
	 * socket the client sends datagrams to (-1 when not a UDP association);
	 * its lifetime is tied to this (TCP control) connection. @udp_peer is
	 * the client's UDP source address, pinned from its first datagram
	 * (@udp_pinned); datagrams from other sources are treated as replies
	 * from targets. @udp_iou is the io_uring relay's per-connection async
	 * scratch (msghdr + buffer), NULL on the epoll loop which relays
	 * synchronously into the per-worker udp_buf.
	 */
	int			udp_fd;
	bool			udp_pinned;
	struct gwp_sockaddr	udp_peer;
	struct gwp_iou_udp	*udp_iou;

	uint32_t		idx;
	union {
		struct gwp_socks5_conn	*s5_conn;
		struct gwp_http_conn	*http_conn;
	};
	union {
		struct gwp_dns_entry	*gde;
		struct gwp_dns_packet	*gdp;
	};
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;

	/*
	 * Candidate target addresses, in the order they should be tried (see
	 * struct gwp_dns_entry). A name that resolves to several addresses
	 * fills all of them, so a dead address can be stepped over instead of
	 * failing the connection; a literal IP, a transparent redirect or an
	 * upstream proxy fills exactly one.
	 *
	 * @nr_cand is how many are valid, @next_cand the index of the first
	 * one not yet tried. target_addr always holds the candidate currently
	 * being attempted -- it is re-copied from here on every attempt, since
	 * a "-j DNAT" rule rewrites it in place.
	 */
	struct gwp_sockaddr	cand[GWP_MAX_CONN_CAND];
	uint8_t			nr_cand;
	uint8_t			next_cand;

	/*
	 * Connect attempts still in flight, one slot per candidate already
	 * started, -1 when idle. Happy Eyeballs races several at once, so the
	 * winner is not known until one of them reports success; the winning
	 * fd then moves into target.fd and the rest are closed.
	 *
	 * @attempt_timer_fd fires when the next attempt should be started. It
	 * is separate from timer_fd, which bounds the whole connect.
	 */
	int			attempt_fd[GWP_MAX_CONN_CAND];
	int			attempt_timer_fd;

	/*
	 * The address each attempt actually dialled, captured after the ACL
	 * ran. It is not simply cand[slot]: a "-j DNAT" rule rewrites the
	 * destination in place, so the winner must be reported (and used for
	 * up_dst) as the rewritten address, not the resolved one.
	 */
	struct gwp_sockaddr	attempt_addr[GWP_MAX_CONN_CAND];

	/*
	 * The hostname the client asked for, when it used a domain target
	 * (SOCKS5 ATYP 0x03 or an HTTP host), for ACL "-m domain" matching.
	 * Points into s5_conn/http_conn and stays valid for the connection's
	 * life; NULL for literal-IP requests.
	 */
	const char		*req_domain;

	/*
	 * Per-connection socket options from the ACL OUTPUT chain (-j MARK /
	 * -j BIND), filled by gwp_ctx_acl_target_allowed() and applied when the
	 * target socket is created.
	 */
	struct gwp_conn_sockopt	acl_sockopt;

	/*
	 * Destination requested from the upstream SOCKS5 proxy. Only used
	 * when ctx->upstream.enabled. For socks5:// this is filled from
	 * target_addr (an IP); for socks5h:// it carries the hostname.
	 */
	struct gwp_socks5_addr	up_dst;

	/*
	 * True while an upstream-handshake request is still being flushed to
	 * the proxy (target buffer holds outbound bytes); false while awaiting
	 * a reply.
	 */
	bool			up_tx;
};


struct gwp_conn_slot {
	struct gwp_conn_pair	**pairs;
	uint32_t		nr;
	uint32_t		cap;
};

#ifdef CONFIG_IO_URING
struct iou {
	struct io_uring		ring;
	struct gwp_sockaddr	accept_addr;
	socklen_t		accept_addr_len;

	/*
	 * Deadline for the accept-retry timer armed when accept() is paused
	 * due to fd exhaustion (EMFILE/ENFILE). Must outlive SQE submission.
	 */
	struct __kernel_timespec accept_retry_ts;
};
#endif

struct gwp_dns_resolver;

struct gwp_wrk_dns {
	struct gwp_dns_resolver		*resolvers;
	uint32_t			nr;
};

struct gwp_wrk {
	int			tcp_fd;
	struct gwp_conn_slot	conn_slot;

	union {
		struct {
			int			ep_fd;
			int			ev_fd;
			struct epoll_event	*events;
			uint16_t		evsz;
			/*
			 * If it's true, the worker MUST call epoll_wait() again
			 * before continue iterating over the events.
			 */
			bool			ev_need_reload;
		};
#ifdef CONFIG_IO_URING
		struct iou	*iou;
#endif
	};

	bool			accept_is_stopped;
	bool			need_join;
	struct gwp_ctx		*ctx;
	uint32_t		idx;
	pthread_t		thread;

	/*
	 * Per-worker scratch for the SOCKS5 UDP relay, allocated at worker
	 * start when SOCKS5 is enabled. A datagram is received at offset
	 * GWP_SOCKS5_UDP_HDR_MAX so a reply header can be prepended in-place
	 * (no copy); the tail holds up to one max-size UDP payload.
	 */
	unsigned char		*udp_buf;

#ifdef CONFIG_NEW_DNS_RESOLVER
	struct gwp_wrk_dns	*dns;
#endif
};

enum {
	GWP_EV_EPOLL,
	GWP_EV_IO_URING
};

struct gwp_ctx {
	volatile bool			stop;
	uint8_t				ev_used;
	struct log_handle		lh;
	struct gwp_wrk			*workers;
	struct gwp_sockaddr		target_addr;
	struct gwp_socks5_ctx		*socks5;
	struct gwp_auth			*auth;
	struct gwp_ssl_ctx		*ssl_ctx;
	struct gwp_dns_ctx		*dns;
	struct gwp_upstream		upstream;
	struct gwp_cfg			cfg;
	int				ino_fd;
	char				*ino_buf;
	/* ACL rule store (--acl-file) and its own inotify watch. Global to all
	 * proxy modes, unlike @auth which is prot-only. */
	struct gwp_acl			*acl;
	int				acl_ino_fd;
	char				*acl_ino_buf;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
};

struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w);
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   const struct gwp_conn_sockopt *so,
			   bool *is_target_alive, bool non_block);
int gwp_create_timer(int fd, int sec, int nsec);
void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd);

/*
 * Per-worker SOCKS5 UDP relay scratch: room to prepend a max relay header plus
 * one max-size UDP payload (65535 bytes). Datagrams are received at offset
 * GWP_SOCKS5_UDP_HDR_MAX within it.
 */
#define GWP_UDP_RELAY_BUFSZ	(GWP_SOCKS5_UDP_HDR_MAX + 65535)

/*
 * Create and bind the per-connection UDP relay socket for a SOCKS5 UDP
 * ASSOCIATE, derive its BND.ADDR:PORT and write the SOCKS5 reply into
 * gcp->target.buf (for the caller to flush to the client), and stash the fd in
 * gcp->udp_fd. On failure a SOCKS5 failure reply is queued instead and a
 * negative error is returned. The caller registers the fd with its event loop.
 */
int gwp_socks5_udp_associate_setup(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Convert a SOCKS5 IPv4/IPv6 target to a sockaddr for the dual-stack UDP relay
 * (always AF_INET6; IPv4 is returned v4-mapped). Domain -> -EAFNOSUPPORT.
 */
int gwp_socks5_addr_to_sockaddr(const struct gwp_socks5_addr *a,
				struct gwp_sockaddr *sa, socklen_t *slen);

/* Fill a SOCKS5 UDP reply-header address from a datagram source (unmaps v4). */
void gwp_socks5_reply_addr_from_sockaddr(const struct gwp_sockaddr *src,
					 struct gwp_socks5_addr *a);

/* Compare two addresses by IP only, matching IPv4 with its v4-mapped form. */
bool gwp_sockaddr_ip_eq(const struct gwp_sockaddr *a,
			const struct gwp_sockaddr *b);

/* Compare two addresses by family, port, and IP; v4 and v4-mapped v6 differ. */
bool gwp_sockaddr_eq(const struct gwp_sockaddr *a,
		     const struct gwp_sockaddr *b);

enum gwp_udp_act { GWP_UDP_DROP, GWP_UDP_TO_TARGET, GWP_UDP_TO_CLIENT };

struct gwp_udp_out {
	unsigned char		*buf;
	size_t			len;
	struct gwp_sockaddr	dst;
	socklen_t		dstlen;
};

/*
 * SOCKS5 UDP relay per-datagram classifier, shared by both event loops. @base
 * points at a received datagram of @n bytes, with GWP_SOCKS5_UDP_HDR_MAX bytes
 * of slack before it; @src is its source. Maintain the client pin
 * (gcp->udp_peer / gcp->udp_pinned) and decide:
 *   GWP_UDP_TO_TARGET - client datagram: strip the SOCKS5 header, forward @out
 *                       to the encapsulated target.
 *   GWP_UDP_TO_CLIENT - target reply: prepend a SOCKS5 header in the slack, send
 *                       @out back to the pinned client.
 *   GWP_UDP_DROP      - unpinned/wrong source, bad header, domain target, or ACL
 *                       denial.
 * On a forward verdict @out holds the buffer + destination; each loop performs
 * the send with its own I/O primitive.
 */
enum gwp_udp_act gwp_udp_relay_classify(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp,
					unsigned char *base, size_t n,
					const struct gwp_sockaddr *src,
					struct gwp_udp_out *out);

/* True if the ACL OUTPUT chain permits a @proto connection from @client to
 * @target (allow-all when no ACL is loaded or @target has no resolved IP).
 * @user is the authenticated username for "-m user", or NULL when the
 * connection is unauthenticated. */
bool gwp_ctx_acl_output_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				const struct gwp_sockaddr *target,
				const char *user, enum gwp_acl_proto proto);

/* As gwp_ctx_acl_output_allowed(), but a matching -j DNAT rewrites *@target and
 * any -j MARK/-j BIND modifiers are written to *@so (ignored when @so is NULL).
 * For the accept-time plain/transparent path, which has no gwp_conn_pair. */
bool gwp_ctx_acl_output_dnat(struct gwp_ctx *ctx,
			     const struct gwp_sockaddr *client,
			     struct gwp_sockaddr *target,
			     struct gwp_conn_sockopt *so,
			     enum gwp_acl_proto proto);

/* Convenience wrapper: ACL OUTPUT check for a TCP target (gcp->target_addr). */
bool gwp_ctx_acl_target_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp);

/*
 * Install the addresses the connect path may try, in priority order, and reset
 * the attempt cursor. At most GWP_MAX_CONN_CAND are kept.
 */
void gwp_conn_set_candidates(struct gwp_conn_pair *gcp,
			     const struct gwp_sockaddr *addrs, uint8_t nr);
/* The one-address case: a literal IP, a transparent redirect, an upstream. */
void gwp_conn_set_single_candidate(struct gwp_conn_pair *gcp,
				   const struct gwp_sockaddr *addr);

/*
 * Close every connect attempt still in flight and the attempt timer, e.g. once
 * one attempt has won the race or the pair is being torn down. Returns how many
 * descriptors were closed, which the epoll loop credits to its accept-rearm
 * accounting.
 */
int gwp_conn_close_attempts(struct gwp_conn_pair *gcp);

/* True if the ACL INPUT chain permits an incoming client for @proto (allow-all
 * with no ACL). */
bool gwp_ctx_acl_client_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				enum gwp_acl_proto proto);
int gwp_get_orig_dst(int fd, const struct gwp_sockaddr *client,
		     struct gwp_sockaddr *dst);
const char *ip_to_str(const struct gwp_sockaddr *gs);

/* True when a drained inotify buffer names the basename of @path. The auth/ACL
 * reload watches sit on the parent directory (so atomic renames still fire), so
 * the reload handlers use this to reload only for their own file. */
bool gwp_inotify_event_matches(const void *buf, size_t len, const char *path);

static inline void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	assert(len <= conn->len);
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

static inline
void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(&ctx->lh, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);

/*
 * Build the "ACL denied" downstream reply (SOCKS5 CONNECT refusal or HTTP 403)
 * into gcp->target.buf, ready for the caller to flush its own way. Logs the
 * denial. Returns -EACCES (the terminal handshake verdict) once the reply is
 * built, or a negative errno if it could not be built.
 */
int gwp_acl_reject_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Build the "could not reach the origin" reply for whichever protocol the
 * client speaks -- a SOCKS5 reply carrying the REP for @err, or HTTP 502 --
 * into gcp->target.buf, ready for the caller to flush its own way. @err is a
 * negative errno. Returns 0 (including for plain forwarding, which has no
 * protocol to answer in), or a negative errno if the reply could not be built.
 */
int gwp_conn_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int err);
int gwp_socks5_build_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int err, void *out, size_t *out_len);
int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_upstream_finalize_dst(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_upstream_authority(const struct gwp_socks5_addr *dst, char *buf,
			   size_t cap);

/*
 * The upstream proxy handshake succeeded: build our downstream CONNECT reply
 * (SOCKS5 or HTTP), drop the proxy's @consumed reply bytes from the target
 * buffer while keeping any early destination data, and splice our reply ahead
 * of it. Returns 0, or a negative errno if the reply could not be built or fit.
 */
int gwp_upstream_splice_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      size_t consumed);

/* "host:port" for a domain upstream target, else its resolved IP. Returns a
 * thread-local buffer valid until the next call on the same thread. */
const char *gwp_upstream_dst_str(struct gwp_conn_pair *gcp);

/*
 * The next I/O step in the transport-agnostic upstream-proxy handshake state
 * machine (gwp_upstream_hs_start / gwp_upstream_hs_on_reply). The request bytes
 * live in gcp->target.buf; the caller performs the send/recv with its own I/O
 * primitive.
 */
enum gwp_upstream_io {
	GWP_UPSTREAM_IO_SEND,	/* a request is built; flush target.buf */
	GWP_UPSTREAM_IO_RECV,	/* reply incomplete; read more into target.buf */
	GWP_UPSTREAM_IO_DONE,	/* tunnel up (reply spliced); start forwarding */
};

/*
 * Begin the upstream-proxy handshake: finalize gcp->up_dst and build the SOCKS5
 * greeting or HTTP CONNECT into gcp->target.buf. Returns GWP_UPSTREAM_IO_SEND,
 * or a negative errno.
 */
int gwp_upstream_hs_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Fresh proxy bytes were appended to gcp->target.buf: parse the current
 * handshake state and either build the next request (GWP_UPSTREAM_IO_SEND), ask
 * for more (GWP_UPSTREAM_IO_RECV), or on final success splice the downstream
 * reply and report GWP_UPSTREAM_IO_DONE. On failure returns a negative errno
 * (logging its own pr_err) and, when @notify is non-NULL, sets *@notify true if
 * the failure is a protocol-level rejection whose downstream client should be
 * told; the caller owns that notification and all timer / forwarding state.
 */
int gwp_upstream_hs_on_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			     bool *notify);

int gwp_socks5_handle_data(struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

#endif /* #ifndef GWPROXY_H */
