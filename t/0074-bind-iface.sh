#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --bind-iface: the global default egress interface for outgoing (target)
# connections, and how an ACL "-j BIND" rule overrides it.
#
# SO_BINDTODEVICE itself has been unprivileged since Linux 5.7, but to be worth
# asserting on it needs a second path to the origin: a veth pair with one end in
# a separate network namespace, the origin server inside that namespace, and two
# addresses on our end. That makes the assertions sharp. Binding the wrong
# device leaves the origin unreachable, so "the connection was dropped" really
# does mean the device was honoured, and our end's second address is one the
# kernel would never pick by itself.
#
# None of that needs privilege. The body runs inside a private user+network
# namespace, where we hold CAP_NET_ADMIN over our own netns and can build the
# whole thing as an ordinary user -- the peer namespace is a parked "unshare -n"
# helper addressed by pid, not an "ip netns" entry, because that would want
# CAP_SYS_ADMIN to mount under /run/netns. Running in a fresh netns also means
# the test network cannot collide with the host's addresses or be rewritten by
# its NAT rules, so two former skip conditions are gone.
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
require unshare
require nsenter

IP="$(command -v ip 2>/dev/null || echo /usr/sbin/ip)"
[ -x "$IP" ] || skip "iproute2 (ip) not available"

# Re-exec: everything below the marker runs inside the namespace. See lib.sh
# for why ns_drop_setup has to run out here rather than inside.
if [ "${1:-}" != "--inner" ]; then
	ns_drop_setup
	$NS_DROP unshare -rn true 2>/dev/null \
		|| skip "no user+network namespaces (unshare -rn) available"
	out="$WORK/inner.out"
	# Detached: a backgrounded proxy holding the pipe would wedge the read.
	setsid $NS_DROP unshare -rn "$0" --inner "$WORK" \
		</dev/null >"$out" 2>&1 &
	for i in $(seq 1 120); do
		grep -q '^INNER-DONE' "$out" 2>/dev/null && break
		sleep 1
	done
	sed 's/^/# /' "$out" >&2
	# A skip decided inside the namespace has to come back out as a skip:
	# the inner exit status is lost, only INNER-DONE crosses the boundary.
	grep -q '^INNER-DONE rc=77' "$out" && \
		skip "$(sed -n 's/^SKIP: //p' "$out" | head -1)"
	grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
	pass
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
rc=1

VH=gwpvh0		# both fit IFNAMSIZ (15); the netns is private, so
VN=gwpvn0		# fixed names cannot collide with another run
NODEV=gwpnd0
# RFC 5737 TEST-NET-1. Nothing else is configured in this namespace, so the
# range is ours alone and no NAT rule exists to rewrite it.
NET=192.0.2

# setsid put this run in its own session, so the runner's process-group sweep
# cannot see anything started here -- it has to reap itself. "kill 0" signals
# exactly this group: the peer namespace holder, the origin, and any proxy
# still up. The namespace and its veth die with the last process in it.
cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

# lib.sh's skip() exits 77, but the outer half only ever sees INNER-DONE, so
# carry the code in rc and let the trap report it. fail() needs no equivalent:
# rc is already 1 and its message is echoed through with the rest.
inner_skip()
{
	rc=77
	echo "SKIP: $*"
	exit 0
}

setup_net()
{
	local i

	"$IP" link set lo up || return 1

	# The peer namespace is held open by a parked process and addressed by
	# its pid. "ip netns add" would want to bind-mount under /run/netns,
	# which needs CAP_SYS_ADMIN in the INITIAL user namespace -- the one
	# thing we deliberately do not have.
	rm -f "$WORK/ns.pid"
	unshare -n bash -c "echo \$\$ >'$WORK/ns.pid'; \
		'$IP' link set lo up; exec sleep 600" &
	for i in $(seq 1 50); do
		[ -s "$WORK/ns.pid" ] && break
		sleep 0.1
	done
	NSPID="$(cat "$WORK/ns.pid" 2>/dev/null)"
	[ -n "$NSPID" ] || return 1

	"$IP" link add "$VH" type veth peer name "$VN" || return 1
	"$IP" link set "$VN" netns "$NSPID" || return 1
	"$IP" addr add "$NET.1/24" dev "$VH" || return 1
	"$IP" addr add "$NET.3/24" dev "$VH" || return 1
	"$IP" link set "$VH" up || return 1
	nsenter -t "$NSPID" -n "$IP" addr add "$NET.2/24" dev "$VN" || return 1
	nsenter -t "$NSPID" -n "$IP" link set "$VN" up || return 1
	return 0
}
setup_net || inner_skip "cannot build the veth/netns test network"

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

# The origin lives in the peer namespace, so the only way to reach it is out of
# the veth. cleanup_inner reaps it with the rest of the process group.
pa="$(pick_port)"
nsenter -t "$NSPID" -n python3 "$SERVERS_DIR/peer_addr.py" "$NET.2" "$pa" \
	>"$WORK/peer.log" 2>&1 &

# Wait for it rather than sleeping a fixed amount. Probing too early gets an
# instant refusal -- there is no firewall in that namespace to absorb the SYN --
# which reads exactly like "the test network is unusable" and would skip all
# ten assertions while still reporting green. wait_listen() cannot serve here:
# ss in our namespace cannot see a listener in the peer's, so ask inside it.
origin_ready()
{
	local i
	for i in $(seq 1 100); do
		nsenter -t "$NSPID" -n ss -ltnH "sport = :$pa" 2>/dev/null \
			| grep -q . && return 0
		sleep 0.1
	done
	return 1
}
origin_ready || inner_skip "the origin never listened in the peer namespace"

# Establish what the kernel does on its own: every "the bind took effect"
# assertion below is a departure from this.
direct="$(peer_src "$NET.2" "$pa")"
[ "$direct" = "$NET.1" ] || \
	inner_skip "the veth test network is unusable (direct connect saw '${direct:-<none>}')"

# ...and that a pinned source is visible to the origin at all. A NAT rule
# covering the test range would rewrite it back to the interface's primary
# address, silently turning the assertions below into assertions about nothing.
pinned="$(peer_src "$NET.2" "$pa" "$NET.3")"
[ "$pinned" = "$NET.3" ] || \
	inner_skip "a pinned source is not observable here (saw '${pinned:-<none>}'; NAT on $NET.0/24?)"

# $1 = listen port, rest = extra arguments. The proxy is an ordinary child of
# this shell now, so $! really is its pid and a plain kill reaps it -- no
# gwp_kill_priv() walk, which existed only to find a proxy under sudo.
start_gwp()
{
	CUR_PORT="$1"
	shift
	"$GWPROXY" --bind="127.0.0.1:$CUR_PORT" --target="$NET.2:$pa" \
		--nr-workers=1 --log-level=3 --event-loop="$loop" "$@" \
		>"$WORK/gwp.log" 2>&1 &
	GWP_PID=$!
	wait_listen "$CUR_PORT" "$GWP_PID" || {
		sed 's/^/# gwp: /' "$WORK/gwp.log" >&2
		fail "[$loop] gwproxy did not listen on $CUR_PORT (args: $*)"
	}
}

stop_gwp()
{
	kill "${GWP_PID:-}" 2>/dev/null
	wait "${GWP_PID:-}" 2>/dev/null
	sleep 0.2
	return 0
}

printf -- '%s\n' "-A OUTPUT -j BIND --to-iface $VH" '-P OUTPUT ACCEPT' \
	>"$WORK/iface.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# The device that actually reaches the origin: traffic flows.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$VH"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] --bind-iface=$VH broke the connection (saw '${src:-<none>}')"

	# A device that cannot reach it: the connection must die rather than
	# leave by the route the kernel would have chosen.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface=lo
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ -z "$src" ] || \
		fail "[$loop] --bind-iface=lo did not pin the interface (saw '$src')"

	# Both options at once, with a source the kernel would never pick.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$VH" --bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.3" ] || \
		fail "[$loop] --bind-source with --bind-iface did not pin the source (saw '${src:-<none>}')"

	# The rule replaces the global spec wholesale. It names only an
	# interface, so it must both override the global --bind-iface=lo (which
	# would drop the connection) and leave the source at the kernel's
	# default -- inheriting the global --bind-source would show $NET.3.
	p="$(pick_port)"
	start_gwp "$p" --acl-file="$WORK/iface.acl" --bind-iface=lo \
		--bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] -j BIND did not replace the global bind wholesale (saw '${src:-<none>}')"

	# A device that does not exist yet is accepted at startup but is strict
	# per connection.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$NODEV"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ -z "$src" ] || \
		fail "[$loop] a nonexistent --bind-iface was not strict (saw '$src')"
done

rc=0
