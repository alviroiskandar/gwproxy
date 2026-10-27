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

. "$(dirname "$0")/lib.sh"
require python3

FDLIMIT=64

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

pp="$(pick_port)"
( ulimit -n "$FDLIMIT"; exec "$GWPROXY" --event-loop=epoll --as-socks5=1 \
	--bind="127.0.0.1:$pp" --acl-allow-all --nr-workers=1 \
	--log-level=3 ) >"$WORK/gwp.log" 2>&1 &
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
idle, waiting = [], None
for _ in range(64):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(b"\x05\x01\x00")
    if greet(c, 0.5):
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
diag "$out"
kill -0 "$gwp_pid" 2>/dev/null || fail "proxy died"
case $rc in
0) ;;
2) fail "the accept throttle was pre-paid by attempts closed in normal operation" ;;
*) fail "$out" ;;
esac

pass
