#
# Shared helpers for the fuzzing scripts. Not meant to be run on its own.
#

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="$FUZZ_DIR/fuzz-harness"
HARNESS="$HARNESS_DIR/build/native/fuzz-harness.native"

list_targets()
{
  local conf
  for conf in "$FUZZ_DIR"/targets/*/target.conf; do
    [ -e "$conf" ] || continue
    basename "$(dirname "$conf")"
  done
}

usage_targets()
{
  echo >&2
  echo "available targets:" >&2
  list_targets | sed 's/^/  /' >&2
}

# Read the description of a campaign. Sets TARGET_DIR and the FUZZ_ variables.
load_target()
{
  TARGET_DIR="$FUZZ_DIR/targets/$1"

  if [ ! -f "$TARGET_DIR/target.conf" ]; then
    echo "no such target: $1" >&2
    usage_targets
    exit 1
  fi

  FUZZ_ENTRY_POINT=
  FUZZ_PROTOCOLS=
  FUZZ_DICTIONARY=
  FUZZ_SEQUENCE=
  # shellcheck source=/dev/null
  . "$TARGET_DIR/target.conf"

  if [ -z "$FUZZ_ENTRY_POINT" ]; then
    echo "$1/target.conf does not set FUZZ_ENTRY_POINT" >&2
    exit 1
  fi

  export FUZZ_ENTRY_POINT
  if [ -n "$FUZZ_SEQUENCE" ]; then
    export FUZZ_SEQUENCE
  else
    unset FUZZ_SEQUENCE
  fi
}

# Build the harness. The first argument names the variant, and the rest are
# passed to make. The build system does not rebuild when only a definition
# changes, and the three variants cannot share object files, so the variant
# that produced the current build is recorded and a change forces a rebuild.
build_harness()
{
  local variant="$1"
  shift

  local stamp="$HARNESS_DIR/build/native/.fuzz-variant"
  local want="$variant|$FUZZ_PROTOCOLS"

  if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$want" ]; then
    make -C "$HARNESS_DIR" distclean > /dev/null 2>&1 || true
  fi

  make -C "$HARNESS_DIR" TARGET=native FUZZ_PROTOCOLS="$FUZZ_PROTOCOLS" \
       "$@" > /dev/null

  mkdir -p "$(dirname "$stamp")"
  echo "$want" > "$stamp"
}

# Every input that a campaign kept, which is the set that reached a distinct
# execution path, together with anything that made the harness fail.
campaign_inputs()
{
  local out_dir="$FUZZ_DIR/out/$1"
  find "$out_dir/default/queue" "$out_dir/default/crashes" \
       "$out_dir/default/hangs" -type f ! -name README.txt 2> /dev/null
}

require_campaign()
{
  if [ ! -d "$FUZZ_DIR/out/$1" ]; then
    echo "no campaign output for target $1. Run ./fuzz.sh $1 first." >&2
    exit 1
  fi
}
