#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client whose CONNECT request spans several TLS records that arrive
# in one TCP segment, optionally followed by the first tunnel bytes. The
# proxy decrypts one record at a time, and the rest is already off the
# socket, held by its TLS engine: it must work through those records
# before waiting for the client again, or the client, which is waiting
# for the reply, hangs. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" --nr-workers=1
	timeout 30 python3 "$SERVERS_DIR/tls_tunnel_client.py" splitrec "$pp" \
		|| fail "[$loop] a CONNECT split across TLS records got no reply"
	kill "$GWP_PID" 2>/dev/null
done

pass
