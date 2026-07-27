#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-dispatch-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-dispatch | tail -1)"
for n in $(seq 100 199); do if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break; fi; done
[[ -n "${D:-}" ]] || { echo 'RAW_DISPATCH_FAIL no display' >&2; exit 1; }
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
run_case(){
  local name=$1 rewrite=$2 expect=$3
  local log="$RUN/$name.log"
  env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX='7001 5280 2C7C A6A0 0001' B2_TEST_REWRITE_HEX="$rewrite" \
    B2_TEST_DUMP=1 B2_TEST_TWO_PASS=1 B2_TEST_REPLAY_COUNT=1 \
    B2_JIT_FORCE_TRANSLATE=1 B2_TEST_FORCE_L2_RAM=1 \
    B2_JIT_PREFER_DIRECT_SUCCESSOR_HANDLER=1 B2_JIT_DIAG=1 B2_TEST_DISPATCH_SUMMARY=1 \
    B2_TEST_FORCE_DIRECT_CHECKSUM=1 \
    timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
  local summary; summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
  [[ -n "$summary" ]] || { echo "RAW_DISPATCH_FAIL $name missing summary" >&2; tail -30 "$log" >&2; return 1; }
  local direct calls good bad
  direct=$(sed -n 's/.*direct_checksum=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  calls=$(sed -n 's/.* check_checksum=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  good=$(sed -n 's/.* good=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  bad=$(sed -n 's/.* bad=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  [[ ${direct:-0} -eq 1 && ${calls:-0} -eq 1 ]] || { echo "RAW_DISPATCH_FAIL $name expected exactly one direct checksum call: $summary" >&2; return 1; }
  if [[ "$expect" == good ]]; then [[ ${good:-0} -eq 1 && ${bad:-0} -eq 0 ]]; else [[ ${good:-0} -eq 0 && ${bad:-0} -eq 1 ]]; fi || {
    echo "RAW_DISPATCH_FAIL $name unexpected summary: $summary" >&2; return 1; }
  grep -q '^REGDUMP:' "$log" || { echo "RAW_DISPATCH_FAIL $name missing REGDUMP" >&2; return 1; }
  printf 'RAW_DISPATCH_PASS case=%s %s\n' "$name" "$summary"
}
run_case unchanged '7001 5280 2C7C A6A0 0001' good
run_case changed   '7002 5280 2C7C A6A0 0001' bad
printf 'METRIC raw_checksum_boundaries=1\nMETRIC raw_checksum_runtime_cases=2\nMETRIC raw_checksum_good=1\nMETRIC raw_checksum_bad=1\n'
