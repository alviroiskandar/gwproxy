#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 with a hostname target: point curl at "localhost" (an ATYP=DOMAINNAME
# request) so gwproxy itself must resolve the name before connecting, then
# verify the fetched payload is byte-exact, on every available event loop.
# A name that does not resolve must be answered with REP 0x04 (host
# unreachable) rather than a bare hang-up, so the client can tell a bad name
# from a broken proxy.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=2
	curl -s --max-time 20 --proxy "socks5h://[::1]:$pp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl via SOCKS5 to hostname target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] SOCKS5 domain proxy corrupted the payload"

	# An unresolvable name gets REP 0x04, not silence. ".invalid" is
	# reserved by RFC 2606 and never resolves.
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host ::1 --atyp domain \
		--dst no-such-host.invalid "$pp" 80)"
	[ "$rep" = "REP=0x04" ] \
		|| fail "[$loop] unresolvable name got '$rep' (want REP=0x04)"

	kill "$GWP_PID" 2>/dev/null
done

pass
