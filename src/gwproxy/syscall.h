// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_SYSCALL_H
#define GWPROXY_SYSCALL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Advantages of using inline assembly for syscalls:
 *
 *  1) Avoid the use of `errno`. Mostly it's implemented as
 *     a function call to `__errno_location()`.
 *
 *  2) Fewer register clobberings. x86-64 syscall only clobbers
 *     `rax`, `rcx`, `r11`, and `memory`. While libc function
 *     calls clobber `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`,
 *     `r9`, `rcx`, `r11`, and `memory`.
 *
 * WARNING: do NOT pass the address of a `__thread` (thread-local) object as a
 * buffer/pointer argument to these wrappers. Because gwproxy is built -fPIC,
 * resolving a TLS address emits a hidden `call __tls_get_addr@PLT`; GCC (11-13
 * at least) then drops the `register asm` operands that carry syscall args 4-6
 * (r10/r8/r9), so e.g. recv() runs with a garbage `flags`. clang is fine; so is
 * -O0 or a non-TLS buffer. Use a stack, heap, or plain global buffer instead.
 * (This is why ev/epoll.c's TLS scratch buffers are on the stack, not __thread.)
 * GCC bug: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=126290
 */
#ifdef __x86_64__
#define __do_syscall0(NUM) ({			\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM)	/* %rax */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall1(NUM, ARG1) ({		\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1)	/* %rdi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1),	/* %rdi */	\
		  "S"(ARG2)	/* %rsi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1),	/* %rdi */	\
		  "S"(ARG2),	/* %rsi */	\
		  "d"(ARG3)	/* %rdx */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({			\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10)	/* %r10 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({		\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8)	/* %r8 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) ({	\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
	register __typeof__(ARG6) __r9 __asm__("r9") = (ARG6);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8),	/* %r8 */				\
		  "r"(__r9)	/* %r9 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	return (int) __do_syscall4(__NR_epoll_wait, epfd, events, maxevents,
				   timeout);
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	return (ssize_t) __do_syscall3(__NR_read, fd, buf, len);
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	return (ssize_t) __do_syscall3(__NR_write, fd, buf, len);
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	return (ssize_t) __do_syscall6(__NR_recvfrom, sockfd, buf, len, flags,
				       src_addr, addrlen);
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	return (ssize_t) __do_syscall6(__NR_sendto, sockfd, buf, len, flags,
				       dest_addr, addrlen);
}

static inline ssize_t __sys_sendmsg(int sockfd, const struct msghdr *msg,
				    int flags)
{
	return (ssize_t) __do_syscall3(__NR_sendmsg, sockfd, msg, flags);
}

static inline int __sys_close(int fd)
{
	return (int) __do_syscall1(__NR_close, fd);
}

static inline int __sys_accept4(int sockfd, struct sockaddr *addr,
				 socklen_t *addrlen, int flags)
{
	return (int) __do_syscall4(__NR_accept4, sockfd, addr, addrlen, flags);
}

static inline int __sys_epoll_ctl(int epfd, int op, int fd,
				 struct epoll_event *event)
{
	return (int) __do_syscall4(__NR_epoll_ctl, epfd, op, fd, event);
}

static inline int __sys_setsockopt(int sockfd, int level, int optname,
				   const void *optval, socklen_t optlen)
{
	return (int) __do_syscall5(__NR_setsockopt, sockfd, level, optname,
				   optval, optlen);
}

static inline int __sys_getsockopt(int sockfd, int level, int optname,
				   void *optval, socklen_t *optlen)
{
	return (int) __do_syscall5(__NR_getsockopt, sockfd, level, optname,
				   optval, optlen);
}

static inline int __sys_socket(int domain, int type, int protocol)
{
	return (int) __do_syscall3(__NR_socket, domain, type, protocol);
}

static inline int __sys_bind(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen)
{
	return (int) __do_syscall3(__NR_bind, sockfd, addr, addrlen);
}

static inline int __sys_listen(int sockfd, int backlog)
{
	return (int) __do_syscall2(__NR_listen, sockfd, backlog);
}

static inline int __sys_epoll_create1(int flags)
{
	return (int) __do_syscall1(__NR_epoll_create1, flags);
}

static inline int __sys_connect(int sockfd, const struct sockaddr *addr,
				socklen_t addrlen)
{
	return (int) __do_syscall3(__NR_connect, sockfd, addr, addrlen);
}

static inline int __sys_getsockname(int sockfd, struct sockaddr *addr,
				socklen_t *addrlen)
{
	return (int) __do_syscall3(__NR_getsockname, sockfd, addr, addrlen);
}

static inline int __sys_timerfd_create(int clockid, int flags)
{
	return (int) __do_syscall2(__NR_timerfd_create, clockid, flags);
}

static inline int __sys_timerfd_settime(int fd, int flags,
				 const struct itimerspec *new_value,
				 struct itimerspec *old_value)
{
	return (int) __do_syscall4(__NR_timerfd_settime, fd, flags, new_value,
				   old_value);
}

static inline int __sys_shutdown(int sockfd, int how)
{
	return (int) __do_syscall2(__NR_shutdown, sockfd, how);
}

#ifndef __NR_eventfd2
#error "eventfd2 syscall not defined"
#endif

static inline int __sys_eventfd(unsigned int c, int flags)
{
	return (int) __do_syscall2(__NR_eventfd2, c, flags);
}

static inline pid_t __sys_gettid(void)
{
	return (pid_t)__do_syscall0(__NR_gettid);
}
#else /* #ifdef __x86_64__ */

/*
 * The libc calls below return -1 and set errno; the wrappers return -errno
 * like the raw syscalls above. @r is the libc call's result, evaluated as
 * the argument, so errno is read right after the call. A long holds every
 * int and ssize_t result.
 */
static inline long __sys_ret(long r)
{
	return (r < 0) ? -errno : r;
}

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	return (int)__sys_ret(epoll_wait(epfd, events, maxevents, timeout));
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	return __sys_ret(read(fd, buf, len));
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	return __sys_ret(write(fd, buf, len));
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	return __sys_ret(recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	return __sys_ret(sendto(sockfd, buf, len, flags, dest_addr, addrlen));
}

static inline ssize_t __sys_sendmsg(int sockfd, const struct msghdr *msg,
				    int flags)
{
	return __sys_ret(sendmsg(sockfd, msg, flags));
}

static inline int __sys_close(int fd)
{
	return (int)__sys_ret(close(fd));
}

static inline int __sys_accept4(int sockfd, struct sockaddr *addr,
				 socklen_t *addrlen, int flags)
{
	return (int)__sys_ret(accept4(sockfd, addr, addrlen, flags));
}

static inline int __sys_epoll_ctl(int epfd, int op, int fd,
				 struct epoll_event *event)
{
	return (int)__sys_ret(epoll_ctl(epfd, op, fd, event));
}

static inline int __sys_setsockopt(int sockfd, int level, int optname,
				   const void *optval, socklen_t optlen)
{
	return (int)__sys_ret(setsockopt(sockfd, level, optname, optval,
					 optlen));
}

static inline int __sys_getsockopt(int sockfd, int level, int optname,
				   void *optval, socklen_t *optlen)
{
	return (int)__sys_ret(getsockopt(sockfd, level, optname, optval,
					 optlen));
}

static inline int __sys_socket(int domain, int type, int protocol)
{
	return (int)__sys_ret(socket(domain, type, protocol));
}

static inline int __sys_bind(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen)
{
	return (int)__sys_ret(bind(sockfd, addr, addrlen));
}

static inline int __sys_listen(int sockfd, int backlog)
{
	return (int)__sys_ret(listen(sockfd, backlog));
}

static inline int __sys_epoll_create1(int flags)
{
	return (int)__sys_ret(epoll_create1(flags));
}

static inline int __sys_eventfd(unsigned int c, int flags)
{
	return (int)__sys_ret(eventfd(c, flags));
}

static inline int __sys_connect(int sockfd, const struct sockaddr *addr,
				socklen_t addrlen)
{
	return (int)__sys_ret(connect(sockfd, addr, addrlen));
}

static inline int __sys_getsockname(int sockfd, struct sockaddr *addr,
				socklen_t *addrlen)
{
	return (int)__sys_ret(getsockname(sockfd, addr, addrlen));
}

static inline int __sys_timerfd_create(int clockid, int flags)
{
	return (int)__sys_ret(timerfd_create(clockid, flags));
}

static inline int __sys_timerfd_settime(int fd, int flags,
				 const struct itimerspec *new_value,
				 struct itimerspec *old_value)
{
	return (int)__sys_ret(timerfd_settime(fd, flags, new_value, old_value));
}

static inline int __sys_shutdown(int sockfd, int how)
{
	return (int)__sys_ret(shutdown(sockfd, how));
}

static inline pid_t __sys_gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}
#endif /* #endif __x86_64__ */

/* Built on the wrappers above, the same for either branch. */
static inline ssize_t __sys_recv(int sockfd, void *buf, size_t len, int flags)
{
	return __sys_recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

static inline ssize_t __sys_send(int sockfd, const void *buf, size_t len,
				 int flags)
{
	return __sys_sendto(sockfd, buf, len, flags, NULL, 0);
}

/*
 * Have the close of @fd reset the connection (SO_LINGER with a zero timeout)
 * instead of ending the stream with a FIN. Best effort: a failure leaves the
 * plain close.
 */
static inline void gwp_set_reset_on_close(int fd)
{
	static const struct linger l = { .l_onoff = 1, .l_linger = 0 };

	__sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
}

/* Close *@fd if it is open and mark it closed, so a second call is a no-op. */
static inline void gwp_close_fd(int *fd)
{
	if (*fd >= 0) {
		__sys_close(*fd);
		*fd = -1;
	}
}

#endif /* #ifndef GWPROXY_SYSCALL_H */
