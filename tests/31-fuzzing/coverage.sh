#!/bin/bash
#
# Measure what a campaign reached.
#
#   ./coverage.sh <target> [source directory ...]
#
# The fuzzer reports whether it is still finding new execution paths, which is
# not the same as which code it has reached. This replays everything the
# campaign kept through a build instrumented for coverage, and reports the
# proportion of each source file that was executed. A parser that stays at
# nothing is one that the seeds or the entry point are not reaching, which is
# a better thing to act on than a longer campaign.

set -e

. "$(dirname "$0")/target-lib.sh"

if [ $# -lt 1 ]; then
  echo "usage: $0 <target> [source directory ...]" >&2
  usage_targets
  exit 1
fi

TARGET="$1"
shift
load_target "$TARGET"
require_campaign "$TARGET"

# Report on the network stack by default.
if [ $# -gt 0 ]; then
  INTERESTING=("$@")
else
  INTERESTING=(os/net)
fi

if ! command -v gcov > /dev/null; then
  echo "gcov not found. It is needed to report coverage." >&2
  exit 1
fi

echo "Building the harness for coverage."
build_harness coverage FUZZ_COVERAGE=1

OBJ_DIR="$HARNESS_DIR/build/native/obj"

# Counts accumulate across runs, so start from nothing.
find "$OBJ_DIR" -name '*.gcda' -delete 2> /dev/null || true

COUNT=0
while IFS= read -r input; do
  [ -n "$input" ] || continue
  "$HARNESS" "$input" > /dev/null 2>&1 || true
  COUNT=$((COUNT + 1))
done <<< "$(campaign_inputs "$TARGET")"

echo "Replayed $COUNT inputs from the campaign for target $TARGET."
echo

REPORT="$(mktemp)"
trap 'rm -f "$REPORT"' EXIT

# gcov prints the file it is reporting on, then the proportion executed.
# The C locale keeps awk reading a decimal point as one, and printing one.
export LC_ALL=C
( cd "$OBJ_DIR" && gcov -n ./*.gcda 2> /dev/null ) | \
  awk '/^File /{
         file = $2
         gsub(/['"'"']/, "", file)
         sub(/^(\.\.\/)+/, "", file)
         next
       }
       /^Lines executed:/{
         split($0, a, ":")
         split(a[2], b, "% of ")
         printf "%s %s %s\n", b[1], b[2], file
       }' > "$REPORT"

for dir in "${INTERESTING[@]}"; do
  echo "Coverage under $dir, by proportion of lines executed:"
  echo
  # shellcheck disable=SC2016
  awk -v dir="$dir" '$3 ~ dir { printf "  %6.2f%%  %5d lines  %s\n", $1, $2, $3 }' \
      "$REPORT" | sort -rn
  echo
done

REACHED=$(awk '$1 > 0' "$REPORT" | wc -l | tr -d ' ')
TOTAL=$(wc -l < "$REPORT" | tr -d ' ')
echo "Executed some part of $REACHED of $TOTAL compiled source files."
