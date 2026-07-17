// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * iptables-style access-control list for gwproxy. Rules are read from a file
 * (see gwp_acl_create) and evaluated top-to-bottom, first-match-wins, against
 * incoming clients (the INPUT chain) and outgoing targets (the OUTPUT chain);
 * a chain's -P policy applies when no rule matches.
 *
 * This module is self-contained (depends only on net.h types and libc) so it
 * can be unit-tested in isolation.
 */
#ifndef GWP_ACL_H
#define GWP_ACL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <gwproxy/net.h>

enum gwp_acl_verdict {
	GWP_ACL_ACCEPT	= 0,
	GWP_ACL_REJECT	= 1,
};

enum gwp_acl_proto {
	GWP_ACL_PROTO_TCP	= 0,
	GWP_ACL_PROTO_UDP	= 1,
};

struct gwp_acl;

/*
 * A -j BIND request: pin the outgoing connection to a source address (and/or
 * port) and/or a network interface. At least one of @have_src / a non-empty
 * @iface is present. @set marks that a BIND rule matched. The 16-byte @iface is
 * IFNAMSIZ (SO_BINDTODEVICE); "" means "no interface".
 */
struct gwp_acl_bind {
	bool			set;
	bool			have_src;
	struct gwp_sockaddr	src;
	char			iface[16];
};

/*
 * Parse an ACL rule file at @path into a new ACL. Returns 0 and stores the ACL
 * in *@out on success; a negative errno on failure (a bad rule is reported to
 * stderr with its line number). An empty/NULL @path yields *@out == NULL,
 * meaning "no ACL" (everything allowed) -- callers treat that as disabled.
 */
int gwp_acl_create(struct gwp_acl **out, const char *path);

/* Parse an ACL from an in-memory NUL-terminated rule text (used by tests). */
int gwp_acl_parse_str(struct gwp_acl **out, const char *text);

/*
 * Re-read the file the ACL was created from and atomically swap in the new
 * rules. On any parse error the previous rules are kept and a negative errno is
 * returned.
 */
int gwp_acl_reload(struct gwp_acl *acl);

/* Free an ACL (NULL is a no-op). */
void gwp_acl_destroy(struct gwp_acl *acl);

/*
 * A single evaluation request, passed by pointer to the eval helpers. Bundling
 * the parameters (and results) in one struct keeps the call sites stable as new
 * match criteria are added -- extend this struct and the matcher, not every
 * caller's argument list.
 *
 * Inputs (fields not relevant to a chain are ignored, so zero-initialise and
 * set only what applies):
 *   @client  source/client address, for -s and (via @sport) --sports; may be NULL.
 *   @target  resolved destination address, for -d; NULL when only @domain is
 *            known (e.g. socks5h remote-DNS upstream).
 *   @domain  client-requested destination hostname for -m domain, or NULL.
 *   @user    authenticated username for -m user (OUTPUT), or NULL when the
 *            connection is unauthenticated (no -m user rule then matches).
 *   @sport   client source port, host byte order (both chains).
 *   @dport   destination port, host byte order (OUTPUT).
 *   @proto   GWP_ACL_PROTO_TCP / _UDP.
 *
 * Outputs (set by gwp_acl_eval_output()):
 *   @dnat_applied  true if a -j DNAT rule matched; @dnat then holds the rewrite.
 *   @mark_set/@mark  true and the fwmark from the last matched -j MARK rule.
 *                    MARK is a composable modifier: it records state and eval
 *                    keeps matching (only ACCEPT/REJECT/DNAT terminate).
 *   @bind    the source/interface from the last matched -j BIND rule (also a
 *            composable modifier); @bind.set is false when none matched.
 */
struct gwp_acl_req {
	const struct gwp_sockaddr	*client;
	const struct gwp_sockaddr	*target;
	const char			*domain;
	const char			*user;
	uint16_t			sport;
	uint16_t			dport;
	enum gwp_acl_proto		proto;

	bool				dnat_applied;
	struct gwp_sockaddr		dnat;
	bool				mark_set;
	uint32_t			mark;
	struct gwp_acl_bind		bind;
};

/*
 * Evaluate the OUTPUT chain (outgoing target) for @req. Returns GWP_ACL_ACCEPT
 * or GWP_ACL_REJECT; a NULL @acl returns ACCEPT. Sets @req->dnat_applied.
 */
enum gwp_acl_verdict gwp_acl_eval_output(struct gwp_acl *acl,
					 struct gwp_acl_req *req);

/*
 * Evaluate the INPUT chain (incoming client) for @req. Returns GWP_ACL_ACCEPT
 * or GWP_ACL_REJECT; a NULL @acl returns ACCEPT.
 */
enum gwp_acl_verdict gwp_acl_eval_input(struct gwp_acl *acl,
					struct gwp_acl_req *req);

#endif /* #ifndef GWP_ACL_H */
