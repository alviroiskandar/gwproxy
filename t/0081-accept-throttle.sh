#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The accept throttle after EMFILE must not be pre-paid. Once accept() runs
# out of descriptors, the epoll worker stops accepting until enough of them
# have been returned (a few pairs' worth), so that it does not bounce
# between EMFILE and rearming on every close. Descriptors closed while
# accept is running must not count towards that: before the fix, every
# failed connect attempt was credited, the credit piled up during normal
# operation, and the first close after the next EMFILE rearmed at once.
#
# Here many SOCKS5 CONNECTs to a closed port first fail in normal operation.
# Then idle clients fill the proxy's descriptor table until one is left
# waiting in the listen backlog. Closing one idle client must not let that
# one in; closing all of them must.
#
# Each client takes two descriptors, its socket and its protocol timer. No
# client may be accepted and then dropped because the table ran out at its
# timer: the proxy must stop accepting first and leave it in the backlog.
# Whether the table runs out at the socket or at the timer depends on the
# parity of the free descriptors, so this runs with two limits.

. "$(dirname "$0")/lib.sh"
require python3

soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt 256 ]; then
	skip "harness fd limit ($soft) too low"
fi

# A port nothing listens on, kept bound for the duration of the test.
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

run_with_limit()
{
	local FDLIMIT="$1" pp gwp_pid out rc

	pp="$(pick_port)"
	( ulimit -n "$FDLIMIT"; exec "$GWPROXY" --event-loop=epoll --as-socks5=1 \
		--bind="127.0.0.1:$pp" --acl-allow-all --nr-workers=1 \
		--log-level=3 ) >"$WORK/gwp.$FDLIMIT.log" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

	out="$(python3 - "$pp" "$cport" <<-'PY'
	import socket, sys, time
	port, cport = int(sys.argv[1]), int(sys.argv[2])

	def greet(c, timeout):
	    c.settimeout(timeout)
	    try:
	        return c.recv(2) == b"\x05\x00"
	    except socket.timeout:
	        return False

	# Failed connect attempts while accept is running.
	for _ in range(60):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    if not greet(c, 5):
	        print("no greeting reply in normal operation")
	        sys.exit(1)
	    c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + cport.to_bytes(2, "big"))
	    c.settimeout(5)
	    rep = c.recv(16)
	    c.close()
	    if rep[:2] != b"\x05\x05":
	        print("expected REP 0x05 for a refused target, got %s" % rep.hex())
	        sys.exit(1)

	# Fill the descriptor table with idle clients until one is left waiting.
	# A client accepted and then closed, because no descriptor was left for its
	# timer, reads as a reset when its greeting had arrived and as an end of
	# stream when the proxy got there first.
	idle, waiting = [], None
	for _ in range(64):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    c.settimeout(0.5)
	    try:
	        rep = c.recv(2)
	    except socket.timeout:
	        rep = None
	    except ConnectionResetError:
	        rep = b""
	    if rep == b"":
	        print("client %d was accepted and dropped" % (len(idle) + 1))
	        sys.exit(3)
	    ok = rep == b"\x05\x00"
	    if ok:
	        idle.append(c)
	        continue
	    waiting = c
	    break
	if waiting is None:
	    print("never ran out of descriptors (%d idle clients)" % len(idle))
	    sys.exit(1)

	idle.pop().close()
	if greet(waiting, 1.0):
	    print("accept resumed after a single close (%d idle clients)" % len(idle))
	    sys.exit(2)

	for c in idle:
	    c.close()
	if not greet(waiting, 5.0):
	    print("accept did not resume after every idle client closed")
	    sys.exit(1)
	print("ok with %d idle clients" % (len(idle) + 1))
	PY
	)"
	rc=$?
	diag "fd limit $FDLIMIT: $out"
	kill -0 "$gwp_pid" 2>/dev/null || fail "proxy died"
	case $rc in
	0) ;;
	2) fail "the accept throttle was pre-paid by attempts closed in normal operation" ;;
	3) fail "fd limit $FDLIMIT: $out" ;;
	*) fail "$out" ;;
	esac
	kill "$gwp_pid" 2>/dev/null
}

for lim in 64 65; do
	run_with_limit "$lim"
done

# Plain forwarding creates the target socket at accept time. When the
# table ran out at the target socket, the client was accepted and closed
# at once; it must be kept instead, and connected once descriptors are
# returned. The origin closes a connection once the client has, so that
# the pair goes away.
#
# With a connect timer, the epoll loop's spare timer and accept() itself,
# which takes a descriptor before it looks at the backlog, always run out
# first in a single worker. Without one (--connect-timeout=0) a client
# takes two descriptors, and the parity of the free ones decides whether
# the table runs out at accept() or at the target socket, hence two
# limits; one of them has to end at the target socket. The io_uring loop
# keeps its timers in the ring and never takes a timer descriptor, so a
# client takes the same two there, and the same two limits cover it.
origin_port=""
python3 -c '
import socket, threading
def serve(c):
    c.sendall(b"R\n")
    while c.recv(4096):
        pass
    c.close()
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(256)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()' >"$WORK/origin.port" &
_PIDS+=("$!")
for _ in $(seq 1 50); do
	origin_port="$(cat "$WORK/origin.port" 2>/dev/null)"
	[ -n "$origin_port" ] && break
	sleep 0.1
done
[ -n "$origin_port" ] || fail "origin did not start"

run_plain()
{
	local ev="$1" lim pp log gwp_pid out hit_target=0

	for lim in 64 65; do
		pp="$(pick_port)"
		log="$WORK/gwp.plain.$ev.$lim.log"
		( ulimit -n "$lim"; exec "$GWPROXY" --event-loop="$ev" \
			--target="127.0.0.1:$origin_port" --bind="127.0.0.1:$pp" \
			--connect-timeout=0 \
			--acl-allow-all --nr-workers=1 --log-level=3 ) >"$log" 2>&1 &
		gwp_pid=$!
		_PIDS+=("$gwp_pid")
		wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

		out="$(python3 - "$pp" <<-'PY'
		import socket, sys
		port = int(sys.argv[1])

		def banner(c, timeout):
		    c.settimeout(timeout)
		    try:
		        return c.recv(2)
		    except socket.timeout:
		        return None
		    except ConnectionResetError:
		        return b""

		# Fill the table with forwarded clients until one is left waiting.
		idle, waiting = [], None
		for _ in range(64):
		    c = socket.create_connection(("127.0.0.1", port), timeout=5)
		    rep = banner(c, 0.5)
		    if rep == b"":
		        print("client %d was accepted and dropped" % (len(idle) + 1))
		        sys.exit(1)
		    if rep == b"R\n":
		        idle.append(c)
		        continue
		    waiting = c
		    break
		if waiting is None:
		    print("never ran out of descriptors (%d clients)" % len(idle))
		    sys.exit(1)

		for c in idle:
		    c.close()
		rep = banner(waiting, 4.0)
		if rep != b"R\n":
		    print("the waiting client was not connected once descriptors were "
		          "returned (%r)" % rep)
		    sys.exit(1)
		print("ok with %d clients" % (len(idle) + 1))
		PY
		)" || fail "[$ev] plain forwarding, fd limit $lim: $out"
		diag "[$ev] plain forwarding, fd limit $lim: $out"
		kill -0 "$gwp_pid" 2>/dev/null || fail "[$ev] proxy died"
		kill "$gwp_pid" 2>/dev/null
		wait "$gwp_pid" 2>/dev/null
		grep -q "retrying the target connect" "$log" && hit_target=1
	done
	[ "$hit_target" = 1 ] || \
		fail "[$ev] no limit ran out at the target socket; test inconclusive"
}

run_plain epoll

if grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null; then
	run_plain io_uring
else
	diag "gwproxy built without io_uring; skipping that leg"
fi

pass
