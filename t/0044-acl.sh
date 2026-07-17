#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# ACL rule file (--acl-file): a malformed file must be refused at startup, and
# a valid file must load without disturbing normal proxying. Enforcement of the
# rules is exercised by later checks in this file as it is wired in; for now
# this covers loading and validation on both event loops.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"

# A malformed ACL is rejected at startup (gwproxy exits non-zero, no listener).
printf -- '-A OUTPUT -j BOGUS\n' >"$WORK/bad.acl"
bp="$(pick_port)"
if "$GWPROXY" --bind="127.0.0.1:$bp" --as-socks5=1 \
	--acl-file="$WORK/bad.acl" >"$WORK/bad.log" 2>&1; then
	fail "gwproxy accepted a malformed ACL file"
fi
grep -qi 'ACL' "$WORK/bad.log" || fail "malformed ACL startup lacked an error"

# A valid ACL loads and proxying still works, on every available loop.
printf -- '%s\n' \
	'# sample ACL: allow the HTTP origin port, deny port 9 (discard)' \
	'-P INPUT ACCEPT' \
	'-A OUTPUT --dports 9 -j REJECT' \
	'-P OUTPUT ACCEPT' >"$WORK/ok.acl"

# INPUT chain that rejects loopback clients (the test client is 127.0.0.1).
printf -- '%s\n' \
	'-A INPUT -s 127.0.0.1/32 -j REJECT' \
	'-P INPUT ACCEPT' >"$WORK/deny-client.acl"

# Read the SOCKS5 CONNECT reply code for a TCP target, via the given proxy.
socks5_connect_rep() {			# $1=proxy_port $2=dst_ip $3=dst_port
	python3 - "$@" <<-'PY'
	import socket, struct, sys
	pp, ip, dp = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
	t = socket.create_connection(('127.0.0.1', pp)); t.settimeout(10)
	t.sendall(b'\x05\x01\x00'); assert t.recv(2) == b'\x05\x00'
	t.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(ip) + struct.pack('!H', dp))
	print(t.recv(10)[1])
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# gwp_start succeeds only once gwproxy is listening, which a valid ACL
	# reaches and a malformed one (rejected at startup) does not.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"

	# An allowed target still proxies end-to-end.
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "$loop SOCKS5 CONNECT to an allowed target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"$loop payload corrupted for an allowed target"

	# A denied target: SOCKS5 replies REP 0x02 (not allowed by ruleset).
	rep="$(socks5_connect_rep "$pp" 127.0.0.1 9)"
	[ "$rep" = 2 ] \
		|| fail "$loop SOCKS5 CONNECT to a denied target got REP $rep (want 2)"

	# A denied target over HTTP forwarding: 403 Forbidden.
	code="$(curl -s --max-time 20 -x "http://127.0.0.1:$pp" \
		"http://127.0.0.1:9/" -o /dev/null -w '%{http_code}')"
	[ "$code" = 403 ] \
		|| fail "$loop HTTP forward to a denied target got $code (want 403)"

	kill "$GWP_PID" 2>/dev/null

	# INPUT chain: a denied client source is dropped at accept, before any
	# handshake, so the connection fails outright.
	ip="$(pick_port)"
	gwp_start "127.0.0.1:$ip" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/deny-client.acl"
	if curl -s --max-time 10 -x "socks5h://127.0.0.1:$ip" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop INPUT-denied client was served"
	fi
	kill "$GWP_PID" 2>/dev/null

	# Plain --target forwarding connects at accept time and enforces the
	# OUTPUT chain too: denied target -> dropped, allowed target -> served.
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" '-P OUTPUT ACCEPT' \
		>"$WORK/plain-deny.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:$hp" --event-loop="$loop" \
		--acl-file="$WORK/plain-deny.acl"
	if curl -s --max-time 10 "http://127.0.0.1:$fp/payload.bin" \
		-o /dev/null 2>/dev/null; then
		fail "$loop plain forward to a denied target was served"
	fi
	kill "$GWP_PID" 2>/dev/null

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:$hp" --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"
	curl -s --max-time 20 "http://127.0.0.1:$fp/payload.bin" \
		-o "$WORK/plain.out" \
		|| fail "$loop plain forward to an allowed target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/plain.out" \
		"$loop plain forward corrupted the payload"
	kill "$GWP_PID" 2>/dev/null
done

pass
