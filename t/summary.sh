#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Turn the per-test result files written by run-one.sh into one verdict.
# Kept separate from the running so that `make -jN` can schedule the tests
# itself and still get a single summary at the end, and so that a failing test
# does not stop the others from running.
#
# Usage: summary.sh <label> <result-dir> [--only <prefix>]
# Unit and integration results share a directory, so --only selects one set.
# Exits non-zero if any test failed.

set -u

label="$1"
dir="$2"
only=""
[ "${3:-}" = "--only" ] && only="${4:-}"

npass=0
nfail=0
nskip=0
failed=()
slowest=""

shopt -s nullglob
for res in "$dir"/${only:+$only-}*.res; do
	read -r status secs name <"$res" || continue
	case "$status" in
	PASS)	npass=$((npass + 1)) ;;
	SKIP)	nskip=$((nskip + 1)) ;;
	*)	nfail=$((nfail + 1)); failed+=("$name") ;;
	esac
	slowest+="$secs $name"$'\n'
done
shopt -u nullglob

if [ $((npass + nfail + nskip)) -eq 0 ]; then
	echo "$label: no tests ran" >&2
	exit 1
fi

echo "------------------------------------------------------------"
if [ -n "$slowest" ]; then
	printf 'slowest: %s\n' \
		"$(printf '%s' "$slowest" | sort -rn | head -3 | \
		   awk '{printf "%s(%ss) ", $2, $1}')"
fi
echo "$label: passed=$npass failed=$nfail skipped=$nskip"

if [ "$nfail" -ne 0 ]; then
	echo "FAILED: ${failed[*]}"
	echo "logs in $dir"
	exit 1
fi
exit 0
