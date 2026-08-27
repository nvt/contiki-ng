#!/bin/bash
#
# Replay the output of a campaign through a build with the address and
# undefined behaviour sanitizers.
#
#   ./replay.sh <target>
#
# A campaign runs without the sanitizers, because they cost throughput that
# would otherwise go into finding inputs. This is where those inputs are
# examined. Every input the campaign kept is replayed, one to a process, which
# is why the harness processes one input per process to begin with.

set -e

. "$(dirname "$0")/target-lib.sh"

if [ $# -lt 1 ]; then
  echo "usage: $0 <target>" >&2
  usage_targets
  exit 1
fi

TARGET="$1"
load_target "$TARGET"
require_campaign "$TARGET"

echo "Building the harness with the sanitizers."
build_harness sanitize FUZZ_SANITIZE=1

# Report on the first error rather than continuing, and make an error fail the
# process, since a sanitizer only writes a diagnostic by default.
export ASAN_OPTIONS="abort_on_error=1:halt_on_error=1"
export UBSAN_OPTIONS="abort_on_error=1:halt_on_error=1:print_stacktrace=1"

TOTAL=0
FAILED=0
FAILED_INPUTS=""

while IFS= read -r input; do
  [ -n "$input" ] || continue
  TOTAL=$((TOTAL + 1))
  if ! output=$("$HARNESS" "$input" 2>&1); then
    FAILED=$((FAILED + 1))
    FAILED_INPUTS="$FAILED_INPUTS $input"
    echo
    echo "FAIL $input"
    echo "$output" | grep -aE "ERROR|runtime error|SUMMARY" | head -5
  fi
done <<< "$(campaign_inputs "$TARGET")"

echo
echo "Replayed $TOTAL inputs from the campaign for target $TARGET."

if [ "$FAILED" -gt 0 ]; then
  echo "$FAILED of them failed:"
  for input in $FAILED_INPUTS; do
    echo "  $input"
  done
  exit 1
fi

echo "None of them failed."
