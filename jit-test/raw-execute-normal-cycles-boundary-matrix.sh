#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-execute-normal-cycles-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-execute-normal-cycles | tail -1)"
for n in $(seq 100 199); do if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break; fi; done
[[ -n "${D:-}" ]] || { echo 'RAW_EXECUTE_NORMAL_CYCLES_FAIL no display' >&2; exit 1; }
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
run_case(){
  local name=$1 hex=$2 seed=$3 expect_before=$4 expect_after=$5
  local log="$RUN/$name.log" summary direct normal nostats recompile entries before after
  env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX="$hex" B2_TEST_INIT="$INIT" B2_TEST_DUMP=1 \
    B2_TEST_TWO_PASS=1 B2_TEST_REPLAY_COUNT=1 \
    B2_TEST_EXECUTE_NORMAL_CYCLES_SEED="$seed" \
    B2_JIT_RESTORE_BARRIERS=sr B2_TEST_FORCE_L2_RAM=1 \
    B2_JIT_DIAG=1 B2_TEST_DISPATCH_SUMMARY=1 \
    timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
  summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
  [[ -n "$summary" ]] || { echo "RAW_EXECUTE_NORMAL_CYCLES_FAIL $name missing summary" >&2; tail -30 "$log" >&2; exit 1; }
  direct=$(sed -n 's/.* direct_execute_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  normal=$(sed -n 's/.* exec_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  nostats=$(sed -n 's/.* exec_nostats=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  recompile=$(sed -n 's/.* recompile_block=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  entries=$(sed -n 's/.* execute_normal_cycles=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  before=$(sed -n 's/.* cycles_before=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  after=$(sed -n 's/.* cycles_after=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  [[ ${direct:-0} -eq 1 && ${normal:-0} -eq 2 && ${nostats:-0} -eq 0 && ${recompile:-0} -eq 0 &&
      ${entries:-0} -eq 1 && ${before:-0} -eq "$expect_before" && ${after:-0} -eq "$expect_after" ]] || {
    echo "RAW_EXECUTE_NORMAL_CYCLES_FAIL $name unexpected summary: $summary" >&2; exit 1; }
  grep -q '^REGDUMP: D0=00002700 D1=00000002 ' "$log" || { echo "RAW_EXECUTE_NORMAL_CYCLES_FAIL $name terminal REGDUMP" >&2; exit 1; }
  printf 'RAW_EXECUTE_NORMAL_CYCLES_PASS case=%s %s\n' "$name" "$summary"
}
run_case imm12 '46c0 7201 5281 2C7C A6E0 0001' 1000 1000 4294967272
run_case reg '4e71 4e71 4e71 4e71 46c0 7201 5281 2C7C A6E0 0001' 10000 10000 4880
printf 'METRIC raw_execute_normal_cycles_boundaries=1\nMETRIC raw_execute_normal_cycles_runtime_cases=2\nMETRIC raw_execute_normal_cycles_imm12=1\nMETRIC raw_execute_normal_cycles_register=1\n'
