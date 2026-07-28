#!/bin/bash
# Reach the production restored-SR interpreter barrier with and without a
# pending JIT specialty flag. The audited following terminal counters prove
# whether maybe_do_nothing fell through or took its exclusive do_nothing exit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-maybe-do-nothing-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-maybe-do-nothing | tail -1)"
for n in $(seq 100 199); do
  if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then
    DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break
  fi
done
[[ -n "${D:-}" ]] || { echo 'RAW_MAYBE_DO_NOTHING_FAIL no display' >&2; exit 1; }
for _ in $(seq 1 30); do DISPLAY="$D" xdpyinfo >/dev/null 2>&1 && break; sleep .1; done
DISPLAY="$D" xdpyinfo >/dev/null
cat >"$RUN/prefs" <<EOF
rom $ROM
disk $CLONE
ramsize 8388608
modelid 14
cpu 4
fpu false
jit true
jitfpu false
jitcachesize 8192
screen win/640/480
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
INIT='00002700 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007ef000 00002700'
HEX='46c0 7201 5281 2C7C A6E0 0001'
run_case(){
  local name=$1 spcflags=$2 expect_direct=$3 expect_entries=$4 expect_before=$5 expect_after=$6
  local log="$RUN/$name.log" summary direct normal entries before after
  env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX="$HEX" B2_TEST_INIT="$INIT" B2_TEST_DUMP=1 \
    B2_TEST_TWO_PASS=1 B2_TEST_REPLAY_COUNT=1 \
    B2_TEST_EXECUTE_NORMAL_CYCLES_SEED=10000 \
    B2_TEST_MAYBE_DO_NOTHING_SPCFLAGS="$spcflags" \
    B2_JIT_RESTORE_BARRIERS=sr B2_TEST_FORCE_L2_RAM=1 \
    B2_JIT_DIAG=1 B2_TEST_DISPATCH_SUMMARY=1 \
    timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
  summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
  [[ -n "$summary" ]] || { echo "RAW_MAYBE_DO_NOTHING_FAIL $name missing summary" >&2; tail -30 "$log" >&2; exit 1; }
  direct=$(sed -n 's/.* direct_execute_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  normal=$(sed -n 's/.* exec_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  entries=$(sed -n 's/.* execute_normal_cycles=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  before=$(sed -n 's/.* cycles_before=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  after=$(sed -n 's/.* cycles_after=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  [[ ${direct:-0} -eq "$expect_direct" && ${normal:-0} -eq 2 && \
      ${entries:-0} -eq "$expect_entries" && ${before:-0} -eq "$expect_before" && \
      ${after:-0} -eq "$expect_after" ]] || {
    echo "RAW_MAYBE_DO_NOTHING_FAIL $name unexpected summary: $summary" >&2; exit 1; }
  grep -q '^REGDUMP: D0=00002700 D1=00000002 ' "$log" || {
    echo "RAW_MAYBE_DO_NOTHING_FAIL $name terminal REGDUMP" >&2; exit 1; }
  printf 'RAW_MAYBE_DO_NOTHING_PASS case=%s %s\n' "$name" "$summary"
}
# Zero flags fall through into the following execute_normal_cycles terminal.
run_case fallthrough 0 1 1 10000 8976
# The JIT-only specialty takes popall_do_nothing; following terminal is absent.
run_case taken 64 0 0 0 0
printf 'METRIC raw_maybe_do_nothing_runtime_cases=2\n'
printf 'METRIC raw_maybe_do_nothing_live_fallthrough=1\n'
printf 'METRIC raw_maybe_do_nothing_live_taken=1\n'
printf 'METRIC raw_maybe_do_nothing_exclusive_terminals=1\n'
