#!/bin/bash
#
# Check that the harness builds for every target, and that every seed passes
# through a build with the address and undefined behaviour sanitizers.
#
#   ./check-seeds.sh
#
# This is not a fuzzing campaign, and finds nothing that the seeds do not
# already reach. It catches a harness that no longer builds against the rest
# of the tree, and a seed that a campaign could no longer start from, which
# includes one that fails the oracle of its target. A failing target is
# recorded in the file summary, in the form that tests/check-test.sh reads.

. "$(dirname "$0")/target-lib.sh"

# Report on the first error, and make an error fail the process, as in
# replay.sh. The harness exits without freeing what its setup allocated, so
# the leak check would report every input.
export ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="abort_on_error=1:halt_on_error=1:print_stacktrace=1"

SUMMARY="$FUZZ_DIR/summary"
rm -f "$SUMMARY"

for target in $(list_targets); do
  load_target "$target"

  if ! build_harness sanitize FUZZ_SANITIZE=1 WERROR=1; then
    echo "$target: the harness does not build"
    printf "%-40s %-30s TEST FAIL\n" "$target" "build" >> "$SUMMARY"
    continue
  fi

  seeds=0
  failed=0
  for seed in "$TARGET_DIR"/seeds/*; do
    [ -f "$seed" ] || continue
    seeds=$((seeds + 1))
    # Standard input is closed for the reason given in replay.sh.
    if ! output=$(timeout 10s "$HARNESS" "$seed" < /dev/null 2>&1); then
      failed=$((failed + 1))
      echo "$target: seed $(basename "$seed") fails"
      echo "$output" | grep -aE "ERROR|runtime error|SUMMARY|^oracle:" | head -5
      printf "%-40s %-30s TEST FAIL\n" "$target" "$(basename "$seed")" \
        >> "$SUMMARY"
    fi
  done

  if [ "$seeds" -eq 0 ]; then
    echo "$target: no seeds"
    printf "%-40s %-30s TEST FAIL\n" "$target" "no seeds" >> "$SUMMARY"
  else
    echo "$target: $seeds seeds, $failed failed"
  fi
done

make -C "$HARNESS_DIR" distclean > /dev/null 2>&1 || true
