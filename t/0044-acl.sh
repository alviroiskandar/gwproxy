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

# A UDP echo server for the UDP-relay ACL checks (binds synchronously).
ep="$(pick_port)"
python3 "$SERVERS_DIR/udp_echo.py" 127.0.0.1 "$ep" >"$WORK/udp_echo.log" 2>&1 &
_PIDS+=("$!")
sleep 0.3

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

	# -m domain: a socks5h request naming a blocked host is refused (the
	# domain is matched before resolution), while a literal-IP request
	# (which carries no hostname) is allowed.
	printf -- '%s\n' '-A OUTPUT -m domain --domain localhost -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/domain.acl"
	dp="$(pick_port)"
	gwp_start "127.0.0.1:$dp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/domain.acl"
	if curl -s --max-time 10 -x "socks5h://127.0.0.1:$dp" \
		"http://localhost:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop -m domain rule did not block the hostname request"
	fi
	curl -s --max-time 20 -x "socks5://127.0.0.1:$dp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/dom.out" \
		|| fail "$loop literal-IP request wrongly blocked by -m domain"
	assert_files_equal "$WORK/payload.bin" "$WORK/dom.out" \
		"$loop -m domain corrupted the literal-IP payload"
	kill "$GWP_PID" 2>/dev/null

	# --domain-regexp (PCRE builds only): a raw/unanchored pattern matches
	# the requested hostname; a non-matching host is served.
	if grep -q CONFIG_PCRE "$ROOT/config.h" 2>/dev/null; then
		printf -- '%s\n' \
			'-A OUTPUT -m domain --domain-regexp ^localhost$ -j REJECT' \
			'-P OUTPUT ACCEPT' >"$WORK/domre.acl"
		rp="$(pick_port)"
		gwp_start "127.0.0.1:$rp" --as-socks5=1 --event-loop="$loop" \
			--acl-file="$WORK/domre.acl"
		if curl -s --max-time 10 -x "socks5h://127.0.0.1:$rp" \
			"http://localhost:$hp/payload.bin" -o /dev/null 2>/dev/null; then
			fail "$loop --domain-regexp did not block the hostname"
		fi
		curl -s --max-time 20 -x "socks5://127.0.0.1:$rp" \
			"http://127.0.0.1:$hp/payload.bin" -o "$WORK/domre.out" \
			|| fail "$loop literal-IP wrongly blocked by --domain-regexp"
		assert_files_equal "$WORK/payload.bin" "$WORK/domre.out" \
			"$loop --domain-regexp corrupted the literal-IP payload"
		kill "$GWP_PID" 2>/dev/null
	fi

	# -m user (OUTPUT-only): with an auth file, a rule keyed on the
	# authenticated username blocks that user while another is served. The
	# username is known only after the auth handshake.
	printf -- '%s\n' 'user001:pw1' 'user002:pw2' >"$WORK/user.auth"
	printf -- '%s\n' '-A OUTPUT -m user --user user001 -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/user.acl"
	uxp="$(pick_port)"
	gwp_start "127.0.0.1:$uxp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --auth-file="$WORK/user.auth" \
		--acl-file="$WORK/user.acl"
	if curl -s --max-time 10 -x "socks5h://user001:pw1@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop -m user did not block user001 (socks5)"
	fi
	curl -s --max-time 20 -x "socks5h://user002:pw2@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/user.out" \
		|| fail "$loop -m user wrongly blocked user002 (socks5)"
	assert_files_equal "$WORK/payload.bin" "$WORK/user.out" \
		"$loop -m user corrupted user002's payload"
	code="$(curl -s --max-time 20 -x "http://user001:pw1@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
	[ "$code" = 403 ] \
		|| fail "$loop -m user over HTTP got $code for user001 (want 403)"
	kill "$GWP_PID" 2>/dev/null

	# -j DNAT rewrites the destination: a CONNECT to a dead port is
	# redirected to the real origin and succeeds.
	printf -- '%s\n' \
		"-A OUTPUT -d 127.0.0.1 --dports 8080 -j DNAT --to :$hp" \
		'-P OUTPUT ACCEPT' >"$WORK/dnat.acl"
	np="$(pick_port)"
	gwp_start "127.0.0.1:$np" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/dnat.acl"
	curl -s --max-time 20 -x "socks5://127.0.0.1:$np" \
		"http://127.0.0.1:8080/payload.bin" -o "$WORK/dnat.out" \
		|| fail "$loop DNAT-redirected CONNECT failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/dnat.out" \
		"$loop DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# DNAT also applies to plain --target forwarding: the fixed dead target
	# is redirected to the real origin.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:8080" --event-loop="$loop" \
		--acl-file="$WORK/dnat.acl"
	curl -s --max-time 20 "http://127.0.0.1:$fp/payload.bin" \
		-o "$WORK/dnat.plain.out" \
		|| fail "$loop plain DNAT-redirected forward failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/dnat.plain.out" \
		"$loop plain DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# Hot reload survives an atomic replace (write-temp + rename-over, as
	# editors and install(1) do): the watch is on the directory, so a
	# renamed-in acl file is still picked up. A file/inode watch would go
	# stale here and never reload.
	cp "$WORK/ok.acl" "$WORK/reload.acl"
	rp="$(pick_port)"
	gwp_start "127.0.0.1:$rp" --as-http=1 --event-loop="$loop" \
		--acl-file="$WORK/reload.acl"
	code="$(curl -s --max-time 20 -x "http://127.0.0.1:$rp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
	[ "$code" = 200 ] || fail "$loop pre-reload fetch got $code (want 200)"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" '-P OUTPUT ACCEPT' \
		>"$WORK/reload.new"
	mv -f "$WORK/reload.new" "$WORK/reload.acl"
	code=""
	for _ in $(seq 1 50); do
		code="$(curl -s --max-time 20 -x "http://127.0.0.1:$rp" \
			"http://127.0.0.1:$hp/payload.bin" -o /dev/null \
			-w '%{http_code}')"
		[ "$code" = 403 ] && break
		sleep 0.1
	done
	[ "$code" = 403 ] \
		|| fail "$loop acl not reloaded after atomic rename ($code, want 403)"
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

	# UDP relay OUTPUT: a datagram to a denied target is dropped, while an
	# allowed target (ok.acl only denies TCP port 9) round-trips.
	printf -- '%s\n' "-A OUTPUT -p udp --dports $ep -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/udp-deny.acl"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp-deny.acl"
	if python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		>/dev/null 2>&1; then
		fail "$loop UDP datagram to a denied target was relayed"
	fi
	kill "$GWP_PID" 2>/dev/null

	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"
	python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		|| fail "$loop UDP datagram to an allowed target failed"

	# INPUT with -p udp: the UDP ASSOCIATE is refused, but TCP still works
	# (the rule is protocol-specific).
	printf -- '%s\n' '-A INPUT -s 127.0.0.1/32 -p udp -j REJECT' \
		'-P INPUT ACCEPT' >"$WORK/udp-in-deny.acl"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp-in-deny.acl"
	if python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		>/dev/null 2>&1; then
		fail "$loop UDP ASSOCIATE from a udp-denied client succeeded"
	fi
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$up" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null \
		|| fail "$loop TCP wrongly blocked by a -p udp INPUT rule"
	kill "$GWP_PID" 2>/dev/null
done

pass
