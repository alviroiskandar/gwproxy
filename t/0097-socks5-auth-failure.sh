#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# After a SOCKS5 failure reply to the greeting or to the RFC 1929
# credentials, the proxy must close the connection, also when the client
# sends nothing more: it used to wait for more bytes and keep the
# connection until the protocol timeout. Exercised on every event loop,
# for a greeting answered in one read and in a later one.

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

greet=05020002
bad=0104757365720478787878

probe() { python3 "$SERVERS_DIR/socks5_oneshot.py" "$@"; }

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for http in 0 1; do
		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http="$http" \
			--auth-file="$WORK/auth" --event-loop="$loop" \
			--nr-workers=1

		got="$(probe "$p" "$greet$bad")"
		[ "$got" = "05020101 CLOSED" ] ||
			fail "[$loop http=$http] wrong password: $got"

		got="$(probe --split "$p" "$greet" "$bad")"
		[ "$got" = "0502 0101 CLOSED" ] ||
			fail "[$loop http=$http] wrong password, own read: $got"

		got="$(probe "$p" 050100)"
		[ "$got" = "05ff CLOSED" ] ||
			fail "[$loop http=$http] no acceptable method: $got"

		kill "$GWP_PID" 2>/dev/null
	done
done

pass
