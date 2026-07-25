# SPDX-License-Identifier: GPL-2.0-only
#
# Shared "leave no gwproxy behind" sweep, sourced by both t/lib.sh (so a test
# cleans up after itself) and t/run.sh (so the runner cleans up after a test
# that could not clean up after itself -- a SIGKILLed test never runs its EXIT
# trap, and its proxies are reparented to init and linger forever).
#
# MATCHING RULE: a process is only ever killed when /proc/<pid>/exe resolves to
# the gwproxy binary itself. Never match on the process name or command line:
# editors, shells, agent sessions and this very script routinely carry the
# string "gwproxy" in their argv, and killing those would be destructive. A
# binary that has been rebuilt since the process started shows up as
# "<path> (deleted)", so that spelling is matched too.

# gwp_sweep [-q]: kill every live process running the gwproxy binary that this
# user owns. Prints how many it killed unless -q is given. Returns the count.
gwp_sweep()
{
	local quiet=0
	[ "${1:-}" = "-q" ] && quiet=1

	local bin="${GWPROXY:-}"
	[ -n "$bin" ] || return 0
	# Resolve to the same absolute form /proc/<pid>/exe reports.
	bin="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
	[ -n "$bin" ] || return 0

	local pid exe n=0
	for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
		exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
		case "$exe" in
		"$bin"|"$bin (deleted)")
			kill -TERM "$pid" 2>/dev/null && n=$((n + 1))
			;;
		esac
	done

	if [ "$n" -gt 0 ]; then
		sleep 0.2
		for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
			exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
			case "$exe" in
			"$bin"|"$bin (deleted)") kill -KILL "$pid" 2>/dev/null ;;
			esac
		done
		[ "$quiet" = 1 ] || echo "swept $n stray gwproxy process(es)" >&2
	fi
	return 0
}
