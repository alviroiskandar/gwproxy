#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Plain forwarding through an upstream proxy (-x) that refuses the
# connection must end the client connection at once: no bytes reach the
# client, and the worker does not spin in the meantime (a failed connect
# leaves EPOLLERR raised on the socket until it is closed). Exercised with
# both upstream protocols on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

# A port nothing listens on: bind it, never listen, and keep it bound so no
# one else can take it while the test runs.
python3 -c '
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1], flush=True)
time.sleep(600)' >"$WORK/closed.port" &
_PIDS+=("$!")
cport=""
for _ in $(seq 1 50); do
	cport="$(cat "$WORK/closed.port" 2>/dev/null)"
	[ -n "$cport" ] && break
	sleep 0.1
done
[ -n "$cport" ] || fail "could not reserve a closed port"

# probe <port> <pid>: connect and wait for the proxy to close us. Prints
# "<secs> <ticks> <hex bytes>": the wait, the proxy's CPU ticks over it, and
# everything we received ("-" for nothing), or "OPEN" on a timeout.
probe()
{
	python3 - "$@" <<-'PY'
	import socket, sys, time
	port, pid = int(sys.argv[1]), sys.argv[2]
	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])
	c = socket.create_connection(("127.0.0.1", port))
	c.settimeout(8)
	t0, k0 = time.monotonic(), ticks()
	got = b""
	try:
	    while True:
	        d = c.recv(4096)
	        if not d:
	            break
	        got += d
	except socket.timeout:
	    print("OPEN")
	    sys.exit(0)
	print("%.2f %d %s" % (time.monotonic() - t0, ticks() - k0, got.hex() or "-"))
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scheme in socks5 http; do
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="127.0.0.1:9" \
			--upstream-proxy="$scheme://127.0.0.1:$cport" \
			--event-loop="$loop" --nr-workers=1 --connect-timeout=3
		read -r secs ticks bytes < <(probe "$pp" "$GWP_PID")
		diag "[$loop] refused $scheme upstream: closed after ${secs}s, $ticks ticks, bytes $bytes"
		[ "$secs" != OPEN ] || fail "[$loop] refused $scheme upstream: client left open"
		[ "$bytes" = - ] || \
			fail "[$loop] refused $scheme upstream: client got upstream bytes $bytes"
		awk -v s="$secs" 'BEGIN { exit !(s < 1.5) }' || \
			fail "[$loop] refused $scheme upstream: client closed only after ${secs}s"
		[ "$ticks" -le 20 ] || \
			fail "[$loop] refused $scheme upstream: proxy used $ticks ticks of CPU"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done
done

pass
