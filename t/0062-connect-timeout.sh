#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --connect-timeout: when the target never completes the TCP handshake, the
# proxy must give up after the timeout and release the connection -- closing
# the client and reclaiming both descriptors. Asserting only that a timeout is
# logged is not enough: an event loop can log it and still hold the pair
# forever, which leaks two fds per attempt and is remotely triggerable. So this
# checks the client-visible outcome (the proxy closes us) and that the
# descriptor count returns to its baseline. Exercised on every available loop.

. "$(dirname "$0")/lib.sh"
require python3

# A target that leaves every connect() hanging in SYN_SENT.
python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh.port" 2>"$WORK/bh.log" &
_PIDS+=("$!")
for i in $(seq 1 50); do
	tport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$tport" ] && break
	sleep 0.1
done
[ -n "${tport:-}" ] || fail "blackhole listener did not report its port"

# Connect, then wait for the proxy to close us. Prints the wait in seconds, or
# "OPEN" if the proxy was still holding the connection at the deadline.
# NOTE: <<- strips leading tabs, so the Python below indents with spaces.
wait_for_close() {			# $1=port $2=deadline_secs
	python3 - "$1" "$2" <<-'PY'
	import socket, sys, time
	port, deadline = int(sys.argv[1]), float(sys.argv[2])
	s = socket.create_connection(('127.0.0.1', port))
	s.settimeout(deadline)
	t0 = time.time()
	try:
	    data = s.recv(1)
	except socket.timeout:
	    print('OPEN')
	    sys.exit(0)
	if data:
	    print('DATA')
	    sys.exit(0)
	print('%.2f' % (time.time() - t0))
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tport" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=1

	# The proxy must drop us once the connect timeout expires. A loop that
	# never releases the pair leaves the client hanging instead.
	got="$(wait_for_close "$pp" 8)"
	case "$got" in
	OPEN)	fail "[$loop] proxy never closed the client after --connect-timeout=1" ;;
	DATA)	fail "[$loop] proxy sent payload for a target that never connected" ;;
	[0-9]*)	;;			# closed after $got seconds: correct
	*)	fail "[$loop] connect-timeout probe failed: '$got'" ;;
	esac

	# Descriptors must come back: a pair that is logged as timed out but
	# never freed burns the client fd and the target fd on every attempt.
	nfd() { ls "/proc/$GWP_PID/fd" 2>/dev/null | wc -l; }
	base="$(nfd)"
	for i in $(seq 1 10); do
		wait_for_close "$pp" 8 >/dev/null
	done
	sleep 2
	after="$(nfd)"
	[ "$after" -le $((base + 4)) ] \
		|| fail "[$loop] descriptors leaked on connect timeout: $base -> $after"

	kill "$GWP_PID" 2>/dev/null
done

pass
