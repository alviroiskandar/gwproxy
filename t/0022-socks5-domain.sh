#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 with a hostname target: point curl at "localhost" (an ATYP=DOMAINNAME
# request) so gwproxy itself must resolve the name before connecting, then
# verify the fetched payload is byte-exact, on every available event loop.

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
	kill "$GWP_PID" 2>/dev/null

	# With DNS caching enabled (bounded), two fetches of the same hostname
	# must both succeed byte-exact: the first resolves and populates the
	# cache, the second is served from it.
	cp="$(pick_port)"
	gwp_start "[::1]:$cp" --as-socks5=1 --event-loop="$loop" --nr-workers=2 \
		--dns-cache-secs=60 --dns-cache-max-entries=128
	for n in 1 2; do
		curl -s --max-time 20 --proxy "socks5h://[::1]:$cp" \
			"http://localhost:$hp/payload.bin" -o "$WORK/cout.$n" \
			|| fail "[$loop] cached SOCKS5 fetch $n failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/cout.$n" \
			"[$loop] cached SOCKS5 fetch $n corrupted the payload"
	done
	kill "$GWP_PID" 2>/dev/null
done

pass
