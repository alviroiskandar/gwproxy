#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A target that half-closes while the proxy holds a full buffer for a client
# that is not reading must not make the worker spin. This is the ordinary
# shape of a download to a slow reader: the origin writes its response and
# closes, and the FIN sits in the proxy's receive queue behind data there is
# no room for yet. The proxy may only act on that FIN once the buffered data
# has gone out, so until then it has to wait without burning CPU.
#
# The client clamps its MSS so the proxy's send queue towards it stays small
# and predictable; otherwise loopback's 64 KiB MSS lets that queue grow to
# megabytes and the FIN only arrives once nearly everything has been read.
# The size that puts the FIN in the proxy's receive queue while its buffer is
# full depends on the kernel's buffer tuning, so a range of sizes is tried at
# once, one connection each. The client stays idle for a while and then reads
# everything; the proxy's CPU time over that idle period must stay near zero,
# and every byte must arrive. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

op="$(pick_port)"
python3 "$SERVERS_DIR/sized_close_origin.py" "$op" >"$WORK/origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" || fail "origin did not start on $op"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$op" \
		--event-loop="$loop" --nr-workers=1
	out="$(python3 - "$pp" "$GWP_PID" <<-'PY'
	import os, socket, sys, time

	port, pid = int(sys.argv[1]), sys.argv[2]
	hz = os.sysconf("SC_CLK_TCK")
	idle = 0.5

	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])     # utime + stime

	conns = []
	for kib in range(48, 257, 16):
	    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
	    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1000)
	    c.settimeout(20)
	    c.connect(("127.0.0.1", port))
	    c.sendall(b"%d\n" % (kib * 1024))
	    conns.append((c, kib * 1024))

	t0 = ticks()
	time.sleep(idle)
	used = ticks() - t0

	for c, n in conns:
	    got = 0
	    while True:
	        d = c.recv(65536)
	        if not d:
	            break
	        got += len(d)
	    c.close()
	    if got != n:
	        print("short %d of %d bytes" % (got, n))
	        sys.exit(1)

	# Spinning shows up as most of the idle period; allow a quarter of it
	# for a loaded machine and the bookkeeping of the transfer itself.
	limit = int(idle * hz / 4)
	print("%d ticks while idle (limit %d, %d Hz)" % (used, limit, hz))
	sys.exit(2 if used > limit else 0)
	PY
	)"
	rc=$?
	diag "[$loop] $out"
	case $rc in
	0) ;;
	2) fail "[$loop] the worker spun while a half-closed target waited for a slow client" ;;
	*) fail "[$loop] transfer to the slow client failed: $out" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
