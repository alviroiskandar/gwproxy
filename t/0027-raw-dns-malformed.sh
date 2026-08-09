#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The raw DNS resolver against responses it should not trust.
#
# --raw-dns parses replies itself, and a reply is whatever arrived on a UDP
# socket: a hostile server, a broken one, or an off-path packet that guessed
# the port. Getting any of it wrong takes down a worker and every connection
# it was carrying, so each case here asserts the proxy is still serving
# afterwards rather than merely still running.
#
# The cases, in the order they bit:
#
#   good              a compressed-name A record, so a failure elsewhere in
#                     this file cannot be mistaken for "raw DNS never worked";
#   uncompressed-name an owner name written out in full. RFC 1035 makes
#                     compression optional, so this is a CONFORMING answer --
#                     it used to hit an assert, and must now resolve;
#   cname-jump        a CNAME whose RDLENGTH walks the cursor past the buffer;
#   rdata-truncated   an AAAA claiming 16 bytes of RDATA that stops after one;
#   question-label    a question label length of 0xC0, which strides 193 bytes.
#
# The last three must be refused, not parsed -- the client sees nothing and
# gives up, which is the point: the failure stays inside that one request.
#
# The port matters as much as the payload here. --dns-server used to drop the
# port from "addr:port" and query 53 regardless, and because the socket is
# connected, the ICMP unreachable that came back killed the worker before any
# response was ever parsed. Binding the responder to a high port is therefore
# also a regression test for that.

. "$(dirname "$0")/lib.sh"
require python3
require curl

grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 1024
hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# Ask the proxy to reach a name, and report the SOCKS5 reply byte, or nothing
# at all when the request was simply abandoned.
ask()
{
	python3 -c '
import socket, sys
try:
    s = socket.socket(); s.settimeout(4)
    s.connect(("127.0.0.1", int(sys.argv[1])))
    s.sendall(b"\x05\x01\x00"); s.recv(2)
    d = b"probe.example.com"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
              + int(sys.argv[2]).to_bytes(2, "big"))
    r = s.recv(16)
    print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
    s.close()
except Exception:
    print("NONE")' "$1" "$2" 2>/dev/null
}

# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring
# ("The raw DNS feature is currently not supported with the io_uring event
# loop"), so there is no second loop to iterate here. Spelling it out because
# every other test in this directory does iterate both, and a build without
# io_uring hides the difference.
for loop in epoll; do

	for mode in good uncompressed-name cname-jump rdata-truncated question-label; do
		dp="$(pick_port)"
		python3 "$SERVERS_DIR/dns_malformed.py" "$mode" "$dp" 2>/dev/null &
		dns_pid=$!
		_PIDS+=("$dns_pid")
		sleep 0.4

		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
			--dns-server="127.0.0.1:$dp" --event-loop="$loop" \
			--nr-workers=1

		rep="$(ask "$p" "$hp")"
		case "$mode" in
		good|uncompressed-name)
			# Resolved to 127.0.0.1 and connected to the origin.
			[ "$rep" = "REP=0x00" ] || \
				fail "[$loop] $mode did not resolve (got '$rep')"
			;;
		*)
			[ "$rep" = "NONE" ] || \
				fail "[$loop] $mode was parsed rather than refused (got '$rep')"
			;;
		esac

		# Still serving, not merely still running.
		kill -0 "$GWP_PID" 2>/dev/null || \
			fail "[$loop] proxy died on a '$mode' DNS response"

		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
		kill "$dns_pid" 2>/dev/null
	done

	# ...and the case where no response comes back at all. The socket is
	# connected, so a DNS server that is simply not there answers with an
	# ICMP port unreachable, which surfaces as -ECONNREFUSED on recv. That
	# used to break the event loop: one unreachable resolver and the worker
	# took every connection down with it. Nothing is started on this port
	# on purpose.
	dp="$(pick_port)"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$dp" --event-loop="$loop" --nr-workers=1
	rep="$(ask "$p" "$hp")"
	[ "$rep" = "NONE" ] || \
		fail "[$loop] an absent DNS server somehow answered (got '$rep')"
	kill -0 "$GWP_PID" 2>/dev/null || \
		fail "[$loop] proxy died because its DNS server was unreachable"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
