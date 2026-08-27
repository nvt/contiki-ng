#!/bin/bash
#
# Run a fuzzing campaign against one entry point of the network stack.
#
#   ./fuzz.sh <target> [duration]
#
# The duration accepts a plain number of seconds, or a number followed by s,
# m or h. It defaults to ten minutes, which is short enough to run casually.
# A campaign that is meant to find something needs considerably longer.
#
# A target is a directory under targets/ holding a target.conf, a seed corpus
# and an optional dictionary. Each campaign injects at exactly one entry
# point, so that the coverage the fuzzer accounts for, and the mutations it
# generates, belong to a single input format.

set -e

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_DIR="$FUZZ_DIR/fuzz-harness"
HARNESS="$HARNESS_DIR/build/native/fuzz-harness.native"

usage()
{
  echo "usage: $0 <target> [duration]" >&2
  echo >&2
  echo "available targets:" >&2
  for conf in "$FUZZ_DIR"/targets/*/target.conf; do
    [ -e "$conf" ] || continue
    echo "  $(basename "$(dirname "$conf")")" >&2
  done
  exit 1
}

# Convert a duration such as 10m or 24h into seconds.
duration_to_seconds()
{
  local value="$1"
  local number="${value%[smh]}"

  case "$number" in
    ''|*[!0-9]*)
      echo "invalid duration: $value" >&2
      exit 1
      ;;
  esac

  case "$value" in
    *s) echo $((number)) ;;
    *m) echo $((number * 60)) ;;
    *h) echo $((number * 3600)) ;;
    *)  echo $((number)) ;;
  esac
}

[ $# -ge 1 ] || usage

TARGET="$1"
TARGET_DIR="$FUZZ_DIR/targets/$TARGET"
DURATION="$(duration_to_seconds "${2:-10m}")"

if [ ! -f "$TARGET_DIR/target.conf" ]; then
  echo "no such target: $TARGET" >&2
  usage
fi

FUZZ_ENTRY_POINT=
FUZZ_PROTOCOLS=
FUZZ_DICTIONARY=
FUZZ_SEQUENCE=
# shellcheck source=/dev/null
. "$TARGET_DIR/target.conf"

if [ -z "$FUZZ_ENTRY_POINT" ]; then
  echo "$TARGET/target.conf does not set FUZZ_ENTRY_POINT" >&2
  exit 1
fi

if ! command -v afl-fuzz > /dev/null; then
  echo "afl-fuzz not found. Install AFL++ to run a campaign." >&2
  exit 1
fi

# The deferred fork server needs the LLVM instrumentation. Without it the
# campaign still runs, but it pays for the whole of the Contiki-NG startup on
# every input instead of once.
if command -v afl-clang-fast > /dev/null; then
  FUZZ_CC=afl-clang-fast
else
  FUZZ_CC=afl-cc
  echo "warning: afl-clang-fast not found, falling back to $FUZZ_CC." >&2
  echo "warning: the deferred fork server may be unavailable." >&2
fi

# The build system does not rebuild when only the protocol set changes, so
# compare it against the set that produced the existing binary.
PROTOCOL_STAMP="$HARNESS_DIR/build/native/.fuzz-protocols"
if [ ! -f "$PROTOCOL_STAMP" ] || \
   [ "$(cat "$PROTOCOL_STAMP")" != "$FUZZ_PROTOCOLS" ]; then
  make -C "$HARNESS_DIR" distclean > /dev/null 2>&1 || true
fi

echo "Building the harness for target $TARGET."
# The native platform sets its own linker, and only LD_OVERRIDE displaces it.
# Linking through the AFL compiler is what pulls in the instrumentation
# runtime that the compiled objects refer to.
make -C "$HARNESS_DIR" TARGET=native CC="$FUZZ_CC" LD_OVERRIDE="$FUZZ_CC" \
     FUZZ_PROTOCOLS="$FUZZ_PROTOCOLS" > /dev/null
mkdir -p "$(dirname "$PROTOCOL_STAMP")"
echo "$FUZZ_PROTOCOLS" > "$PROTOCOL_STAMP"

DICTIONARY_ARG=()
if [ -n "$FUZZ_DICTIONARY" ] && [ -f "$TARGET_DIR/$FUZZ_DICTIONARY" ]; then
  DICTIONARY_ARG=(-x "$TARGET_DIR/$FUZZ_DICTIONARY")
fi

OUT_DIR="$FUZZ_DIR/out/$TARGET"
mkdir -p "$OUT_DIR"

echo "Fuzzing $TARGET at entry point $FUZZ_ENTRY_POINT for $DURATION seconds."
echo "Output in $OUT_DIR."

# AFL_SKIP_CPUFREQ and AFL_NO_AFFINITY keep the campaign from refusing to
# start on machines where the governor cannot be read or cores cannot be
# bound, which covers most laptops and CI runners.
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1

# macOS caps a System V shared memory segment at kern.sysv.shmmax, which is
# four megabytes by default and less than AFL++ asks for, so the campaign
# would fail to start. The coverage map needs a small fraction of that for
# these targets, so ask for the customary size rather than requiring every
# contributor to change a system limit and reboot.
if [ "$(uname)" = "Darwin" ] && [ -z "${AFL_MAP_SIZE:-}" ]; then
  export AFL_MAP_SIZE=65536
fi
export FUZZ_ENTRY_POINT
if [ -n "$FUZZ_SEQUENCE" ]; then
  export FUZZ_SEQUENCE
fi

afl-fuzz -i "$TARGET_DIR/seeds" -o "$OUT_DIR" -V "$DURATION" \
         "${DICTIONARY_ARG[@]}" -- "$HARNESS" @@

echo
echo "Campaign finished. Replay the queue under the sanitizers with:"
echo "  ./replay.sh $TARGET"
