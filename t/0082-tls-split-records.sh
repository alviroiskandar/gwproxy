#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client whose CONNECT request spans several TLS records that arrive
# in one TCP segment, optionally followed by the first tunnel bytes. The
# proxy decrypts one record at a time, and the rest is already off the
# socket, held by its TLS engine: it must work through those records
# before waiting for the client again, or the client, which is waiting
# for the reply, hangs. Exercised on every event loop.
#
# The same must hold when the client buffer fills before the engine runs
# dry while a reply is still being sent: a SOCKS5 greeting, a 255-byte
# username/password request and the CONNECT request, all in small records
# in one segment, against a 256-byte client buffer. Once the method reply
# is out, the records the engine still holds must be worked through.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# Long enough that the greeting and this request overflow a 256-byte buffer.
user="$(printf 'u%.0s' $(seq 126))"
pass="$(printf 'p%.0s' $(seq 126))"
printf '%s:%s\n' "$user" "$pass" >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" --nr-workers=1
	timeout 30 python3 "$SERVERS_DIR/tls_tunnel_client.py" splitrec "$pp" \
		|| fail "[$loop] a CONNECT split across TLS records got no reply"
	kill "$GWP_PID" 2>/dev/null

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--client-buf-size=256 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" --nr-workers=1
	timeout 30 python3 "$SERVERS_DIR/tls_tunnel_client.py" splitauth "$pp" \
		"$user" "$pass" \
		|| fail "[$loop] a SOCKS5 handshake overflowing the client buffer got no reply"
	kill "$GWP_PID" 2>/dev/null
done

pass
