#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE (RFC 1928): a client opens a TCP control connection,
# issues UDP ASSOCIATE, and the proxy returns a bound UDP relay endpoint. The
# client then sends SOCKS5-wrapped datagrams to that relay, which forwards them
# to a UDP echo server and relays the replies back. Verify datagrams of several
# sizes round-trip byte-exact, that the relay is torn down with its TCP control
# connection, and that plain SOCKS5 CONNECT still works on the same port. The
# relay is exercised on both event loops (epoll and, when built, io_uring).

. "$(dirname "$0")/lib.sh"
require curl
require python3
require ss

# Start the dual-purpose UDP echo server and wait until its socket is bound.
ep="$(pick_port)"
python3 "$SERVERS_DIR/udp_echo.py" 127.0.0.1 "$ep" \
	>"$WORK/udp_echo.$ep.log" 2>&1 &
_PIDS+=("$!")
for i in $(seq 1 50); do
	ss -uanH "sport = :$ep" 2>/dev/null | grep -q . && break
	sleep 0.1
	[ "$i" = 50 ] && fail "UDP echo server did not bind on $ep"
done

# A TCP HTTP origin for the coexisting CONNECT check.
hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100000
start_httpd "$hp" "$WORK" "1.1"

pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop=epoll --nr-workers=2

# (1) UDP ASSOCIATE relay: datagrams of assorted sizes echo back intact.
python3 "$SERVERS_DIR/socks5_udp_client.py" "$pp" "$ep" 1 60 1400 9000 60000 \
	|| fail "SOCKS5 UDP ASSOCIATE relay failed"

# (2) A fresh association works after the first is gone (each run opens and
#     closes its own control connection, exercising relay teardown).
python3 "$SERVERS_DIR/socks5_udp_client.py" "$pp" "$ep" 200 \
	|| fail "second SOCKS5 UDP association failed"

# (2b) The association outlives the protocol-handshake timeout (the handshake
#      timer must be disarmed once the relay is up). Use a short timeout and a
#      client that sends a datagram after it would have fired.
tp="$(pick_port)"
gwp_start "127.0.0.1:$tp" --as-socks5=1 --event-loop=epoll --protocol-timeout=1
GWP_TP="$GWP_PID"
python3 "$SERVERS_DIR/socks5_udp_client.py" "$tp" "$ep" --delay 2.0 64 \
	|| fail "UDP association did not survive the protocol timeout"
kill "$GWP_TP" 2>/dev/null

# (3) Coexistence: plain SOCKS5 CONNECT still works on the same port.
curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
	|| fail "SOCKS5 CONNECT on the UDP-capable port failed"
assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
	"SOCKS5 CONNECT corrupted the payload"

kill "$GWP_PID" 2>/dev/null

# (4) The io_uring loop relays too (when built): repeat the round-trip, a fresh
#     association, and the protocol-timeout survival check on that loop.
if grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null; then
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop=io_uring --nr-workers=2

	python3 "$SERVERS_DIR/socks5_udp_client.py" "$pp" "$ep" 1 60 1400 9000 60000 \
		|| fail "io_uring SOCKS5 UDP ASSOCIATE relay failed"
	python3 "$SERVERS_DIR/socks5_udp_client.py" "$pp" "$ep" 200 \
		|| fail "second io_uring SOCKS5 UDP association failed"

	# Coexistence: plain SOCKS5 CONNECT still works on the io_uring loop.
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.iou.bin" \
		|| fail "io_uring SOCKS5 CONNECT on the UDP-capable port failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.iou.bin" \
		"io_uring SOCKS5 CONNECT corrupted the payload"
	kill "$GWP_PID" 2>/dev/null

	tp="$(pick_port)"
	gwp_start "127.0.0.1:$tp" --as-socks5=1 --event-loop=io_uring \
		--protocol-timeout=1
	GWP_TP="$GWP_PID"
	python3 "$SERVERS_DIR/socks5_udp_client.py" "$tp" "$ep" --delay 2.0 64 \
		|| fail "io_uring UDP association did not survive the timeout"
	kill "$GWP_TP" 2>/dev/null
fi

pass
