#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --bind-iface: the global default egress interface for outgoing (target)
# connections, and how an ACL "-j BIND" rule overrides it.
#
# SO_BINDTODEVICE needs CAP_NET_ADMIN and, to be worth asserting on, a second
# path to the origin -- so the test builds one: a veth pair with one end in a
# fresh network namespace, the origin server inside that namespace, and two
# addresses on the host end. That makes the assertions sharp. Binding the wrong
# device leaves the origin unreachable, so "the connection was dropped" really
# does mean the device was honoured, and the host end's second address is one
# the kernel would never pick by itself. The whole test is skipped without root
# or passwordless sudo; 0073-bind-source.sh covers the unprivileged half.
#
# Covered, on every event loop:
#   * --bind-iface alone: the right device carries traffic, the wrong one (lo)
#     is fatal rather than silently egressing via the default route;
#   * --bind-iface together with --bind-source;
#   * an ACL "-j BIND --to-iface" rule overriding a global default that would
#     otherwise drop the connection, and REPLACING it wholesale -- a rule that
#     names only an interface must not inherit the global --bind-source;
#   * a nonexistent global device: gwproxy still starts (the device may come up
#     later, e.g. a WireGuard link) but every connection is dropped.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --bind-iface

IP="$(command -v ip 2>/dev/null || echo /usr/sbin/ip)"
[ -x "$IP" ] || skip "iproute2 (ip) not available"

if [ "$(id -u)" = 0 ]; then
	SUDO=""
elif sudo -n true 2>/dev/null; then
	SUDO="sudo -n"
else
	skip "needs root or passwordless sudo (SO_BINDTODEVICE + netns)"
fi

NS="gwpns$$"		# all three fit IFNAMSIZ (15) for any pid width
VH="gwpvh$$"
VN="gwpvn$$"
NODEV="gwpnd$$"
# RFC 5737 TEST-NET-1: a range no host has a reason to route, let alone NAT.
# (A masquerade rule covering the test range would rewrite the very source
# addresses this test asserts on; the sanity checks below catch that anyway.)
NET=192.0.2

cleanup_priv()
{
	# CUR_PORT/PEER_PID are only assigned once the run gets that far, but
	# this handler is installed before that: under lib.sh's `set -u` a bare
	# reference would abort it on an early exit, leaving a root-owned
	# namespace and interface behind on the host.
	[ -n "${CUR_PORT:-}" ] && $SUDO pkill -f "bind=127.0.0.1:$CUR_PORT" 2>/dev/null
	[ -n "${PEER_PID:-}" ] && $SUDO kill "$PEER_PID" 2>/dev/null
	$SUDO "$IP" link del "$VH" 2>/dev/null
	$SUDO "$IP" netns del "$NS" 2>/dev/null
	return 0
}
# _cleanup exits via the EXIT trap in lib.sh; chain ours ahead of it.
trap 'cleanup_priv; _cleanup' EXIT
trap 'exit 143' INT TERM

$SUDO "$IP" -o addr show 2>/dev/null | grep -q "inet $NET\." && \
	skip "$NET.0/24 is already configured on this host"

setup_net()
{
	$SUDO "$IP" netns add "$NS" || return 1
	$SUDO "$IP" link add "$VH" type veth peer name "$VN" || return 1
	$SUDO "$IP" link set "$VN" netns "$NS" || return 1
	$SUDO "$IP" addr add "$NET.1/24" dev "$VH" || return 1
	$SUDO "$IP" addr add "$NET.3/24" dev "$VH" || return 1
	$SUDO "$IP" link set "$VH" up || return 1
	$SUDO "$IP" netns exec "$NS" "$IP" addr add "$NET.2/24" dev "$VN" || return 1
	$SUDO "$IP" netns exec "$NS" "$IP" link set "$VN" up || return 1
	$SUDO "$IP" netns exec "$NS" "$IP" link set lo up || return 1
	return 0
}
setup_net || skip "cannot build the veth/netns test network"

# Connect to <host>:<port> and print the source address the far end reports,
# or nothing at all if the connection was dropped without a reply. With a
# third argument, bind that source first -- used to check that a pinned source
# is observable at all on this host before asserting that gwproxy pins one.
peer_src()
{
	python3 -c 'import socket,sys
s=socket.socket()
if len(sys.argv) > 3:
    s.bind((sys.argv[3], 0))
s.settimeout(10); s.connect((sys.argv[1], int(sys.argv[2])))
print(s.recv(64).decode().strip())' "$1" "$2" ${3:+"$3"} 2>/dev/null
}

# The origin lives in the namespace, so the only way to reach it is out of the
# veth. Launch it detached and keep its pid: it runs as root, so the EXIT trap
# in lib.sh cannot reap it.
pa="$(pick_port)"
$SUDO "$IP" netns exec "$NS" bash -c \
	"python3 '$SERVERS_DIR/peer_addr.py' '$NET.2' $pa >'$WORK/peer.log' 2>&1 & echo \$! >'$WORK/peer.pid'" \
	|| skip "cannot start the origin server inside the netns"
sleep 0.5
PEER_PID="$(cat "$WORK/peer.pid" 2>/dev/null)"

# Establish what the kernel does on its own: every "the bind took effect"
# assertion below is a departure from this.
direct="$(peer_src "$NET.2" "$pa")"
[ "$direct" = "$NET.1" ] || \
	skip "the veth test network is unusable (direct connect saw '${direct:-<none>}')"

# ...and that a pinned source is visible to the origin at all. A NAT rule
# covering the test range would rewrite it back to the interface's primary
# address, silently turning the assertions below into assertions about nothing.
pinned="$(peer_src "$NET.2" "$pa" "$NET.3")"
[ "$pinned" = "$NET.3" ] || \
	skip "a pinned source is not observable here (saw '${pinned:-<none>}'; NAT on $NET.0/24?)"

# gwproxy needs CAP_NET_ADMIN here, so it runs under sudo; killing the sudo
# wrapper's pid would not reliably reach the child, hence pkill on the bind
# string. $1 = listen port, rest = extra arguments.
start_priv()
{
	CUR_PORT="$1"
	shift
	$SUDO "$GWPROXY" --bind="127.0.0.1:$CUR_PORT" --target="$NET.2:$pa" \
		--nr-workers=1 --log-level=3 --event-loop="$loop" "$@" \
		>"$WORK/priv.log" 2>&1 &
	wait_listen "$CUR_PORT" || {
		sed 's/^/# gwp: /' "$WORK/priv.log" >&2
		fail "[$loop] gwproxy did not listen on $CUR_PORT (args: $*)"
	}
}

stop_priv()
{
	$SUDO pkill -f "bind=127.0.0.1:$CUR_PORT" 2>/dev/null
	sleep 0.2
	return 0
}

printf -- '%s\n' "-A OUTPUT -j BIND --to-iface $VH" '-P OUTPUT ACCEPT' \
	>"$WORK/iface.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# The device that actually reaches the origin: traffic flows.
	p="$(pick_port)"
	start_priv "$p" --acl-allow-all --bind-iface="$VH"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_priv
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] --bind-iface=$VH broke the connection (saw '${src:-<none>}')"

	# A device that cannot reach it: the connection must die rather than
	# leave by the route the kernel would have chosen.
	p="$(pick_port)"
	start_priv "$p" --acl-allow-all --bind-iface=lo
	src="$(peer_src 127.0.0.1 "$p")"
	stop_priv
	[ -z "$src" ] || \
		fail "[$loop] --bind-iface=lo did not pin the interface (saw '$src')"

	# Both options at once, with a source the kernel would never pick.
	p="$(pick_port)"
	start_priv "$p" --acl-allow-all --bind-iface="$VH" --bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_priv
	[ "$src" = "$NET.3" ] || \
		fail "[$loop] --bind-source with --bind-iface did not pin the source (saw '${src:-<none>}')"

	# The rule replaces the global spec wholesale. It names only an
	# interface, so it must both override the global --bind-iface=lo (which
	# would drop the connection) and leave the source at the kernel's
	# default -- inheriting the global --bind-source would show $NET.3.
	p="$(pick_port)"
	start_priv "$p" --acl-file="$WORK/iface.acl" --bind-iface=lo \
		--bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_priv
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] -j BIND did not replace the global bind wholesale (saw '${src:-<none>}')"

	# A device that does not exist yet is accepted at startup but is strict
	# per connection.
	p="$(pick_port)"
	start_priv "$p" --acl-allow-all --bind-iface="$NODEV"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_priv
	[ -z "$src" ] || \
		fail "[$loop] a nonexistent --bind-iface was not strict (saw '$src')"
done

pass
