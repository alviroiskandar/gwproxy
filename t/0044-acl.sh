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
	'# sample ACL' \
	'-P INPUT ACCEPT' \
	'-A OUTPUT -d 10.0.0.0/8 -j REJECT' \
	'-P OUTPUT ACCEPT' >"$WORK/ok.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# gwp_start succeeds only once gwproxy is listening, which a valid ACL
	# reaches and a malformed one (rejected at startup) does not.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "$loop SOCKS5 CONNECT failed with an ACL loaded"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"$loop payload corrupted with an ACL loaded"
	kill "$GWP_PID" 2>/dev/null
done

pass
