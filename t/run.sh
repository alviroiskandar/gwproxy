#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run the integration tests sequentially and print a summary. This is the
# by-hand entry point; `make test` drives the same per-test runner through make
# targets instead, so that `make -jN` decides how many run at once.
#
# Exit status is non-zero if any test failed. Skipped tests (exit 77) do not
# count as failures.

set -u

T_DIR="$(cd "$(dirname "$0")" && pwd)"
export GWPROXY="${GWPROXY:-$T_DIR/../gwproxy}"

if [ ! -x "$GWPROXY" ]; then
	echo "gwproxy binary not found at $GWPROXY (run 'make' first)" >&2
	exit 1
fi

OUT="${GWP_TEST_OUT:-$T_DIR/../.test-out}"
rm -rf "$OUT"/integ-*
mkdir -p "$OUT"

shopt -s nullglob
tests=("$T_DIR"/[0-9]*.sh)
shopt -u nullglob

if [ ${#tests[@]} -eq 0 ]; then
	echo "no integration tests found in $T_DIR"
	exit 0
fi

for t in "${tests[@]}"; do
	name="$(basename "$t" .sh)"
	"$T_DIR/run-one.sh" integ "$name" "$t" "$OUT/integ-$name.res"
done

exec "$T_DIR/summary.sh" integration "$OUT" --only integ
