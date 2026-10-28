#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The upstream proxy password must not leak to other users of the host:
#
#   (1) an --upstream-proxy URL that fails to parse is named in the error
#       message, but with its password masked.

. "$(dirname "$0")/lib.sh"
require_opt "--upstream-proxy"

SECRET="s3cr3t-Upstream-Pw"

# (1) A URL with credentials but an unresolvable host (the space makes it
# invalid on any resolver) is rejected at startup; the message names the user
# and the host, and must not carry the password.
out="$(timeout 5 "$GWPROXY" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
	--upstream-proxy="http://opuser:$SECRET@bad host:1" 2>&1)" && \
	fail "a malformed --upstream-proxy URL was accepted"
printf '%s\n' "$out" | grep -q "Invalid --upstream-proxy value 'http://opuser:\*\*\*@bad host:1'" || \
	fail "no masked upstream URL in the error: $out"
printf '%s\n' "$out" | grep -qF "$SECRET" && \
	fail "the upstream password was logged: $out"

pass
