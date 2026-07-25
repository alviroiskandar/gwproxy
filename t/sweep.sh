# SPDX-License-Identifier: GPL-2.0-only
#
# Shared "leave no gwproxy behind" sweep, sourced by t/lib.sh (so a test cleans
# up after itself) and t/run-one.sh (so the runner cleans up after a test that
# could not clean up after itself -- a SIGKILLed test never runs its EXIT trap,
# and its proxies are reparented to init and linger forever).
#
# MATCHING RULE: a process is only ever killed when /proc/<pid>/exe resolves to
# the gwproxy binary itself. Never match on the process name or command line:
# editors, shells, agent sessions and this very script routinely carry the
# string "gwproxy" in their argv, and killing those would be destructive. A
# binary that has been rebuilt since the process started shows up as
# "<path> (deleted)", so that spelling is matched too.
#
# SCOPE: by default only processes in OUR OWN process group are killed, because
# `make -jN` runs tests concurrently and a global kill would shoot down the
# proxies of every other test in flight. run-one.sh puts each test in its own
# process group (setsid), and a process keeps its process group even after it
# is orphaned and reparented to init -- which is exactly the case this sweep
# exists for. Pass --all to ignore the group and sweep everything, for cleaning
# up by hand after an interrupted session.

# _gwp_pgid_of <pid>: print the process group id of <pid>, or nothing.
# Parses /proc/<pid>/stat after the comm field, which may itself contain spaces
# and parentheses, so split on the last ')'.
_gwp_pgid_of()
{
	local st
	st="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
	st="${st##*) }"
	set -- $st
	printf '%s' "$3"
}

# gwp_sweep [-q] [--all]: kill the gwproxy processes this test left behind.
gwp_sweep()
{
	local quiet=0 all=0 arg
	for arg in "$@"; do
		case "$arg" in
		-q)	quiet=1 ;;
		--all)	all=1 ;;
		esac
	done

	local bin="${GWPROXY:-}"
	[ -n "$bin" ] || return 0
	bin="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
	[ -n "$bin" ] || return 0

	local mypg=""
	if [ "$all" = 0 ]; then
		mypg="$(_gwp_pgid_of $$)"
		[ -n "$mypg" ] || return 0
	fi

	local pass pid exe n=0
	for pass in TERM KILL; do
		for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
			exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
			case "$exe" in
			"$bin"|"$bin (deleted)") ;;
			*) continue ;;
			esac
			if [ -n "$mypg" ] && [ "$(_gwp_pgid_of "$pid")" != "$mypg" ]; then
				continue	# another test's proxy
			fi
			kill "-$pass" "$pid" 2>/dev/null || continue
			[ "$pass" = TERM ] && n=$((n + 1))
		done
		[ "$n" -gt 0 ] || break
		[ "$pass" = TERM ] && sleep 0.2
	done

	[ "$n" -gt 0 ] && [ "$quiet" = 0 ] && \
		echo "swept $n stray gwproxy process(es)" >&2
	return 0
}
