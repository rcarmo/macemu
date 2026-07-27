#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-metadata-rmw-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-metadata-rmw | tail -1)"
for n in $(seq 100 199); do if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break; fi; done
[[ -n "${D:-}" ]] || { echo 'RAW_METADATA_RMW_FAIL no display' >&2; exit 1; }
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
run_valid(){
  local count=$1 expected_mask=$2 log="$RUN/valid-$1.log"
  env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX='707f 5380 66fc' B2_TEST_DUMP=1 B2_JIT_DIAG=1 \
    B2_TEST_DISPATCH_SUMMARY=1 B2_TEST_METADATA_RMW_COUNT="$count" \
    B2_JIT_ENABLE_STABLE_DIRECT_EDGES=1 B2_JIT_STABLE_DIRECT_ROM_ONLY=0 \
    B2_JIT_STABLE_EDGE_MIN_EXEC=1 B2_JIT_STABLE_EDGE_MIN_PCT=80 \
    timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
  local summary; summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
  [[ -n "$summary" ]] || { echo "RAW_METADATA_RMW_FAIL count=$count missing summary" >&2; tail -30 "$log" >&2; return 1; }
  local recomp rebuild edges mask
  recomp=$(sed -n 's/.* recompile_block=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  rebuild=$(sed -n 's/.* metadata_rebuild=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  edges=$(sed -n 's/.* metadata_edges=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  mask=$(sed -n 's/.* metadata_summary=\([0-9a-fA-F][0-9a-fA-F]*\).*/\1/p' <<<"$summary")
  [[ ${recomp:-0} -eq 1 && ${rebuild:-0} -eq 1 && ${edges:-0} -eq "$count" && ${mask:-} == "$expected_mask" ]] || {
    echo "RAW_METADATA_RMW_FAIL count=$count unexpected summary: $summary" >&2; return 1; }
  grep -q '^REGDUMP: D0=00000000 ' "$log" || { echo "RAW_METADATA_RMW_FAIL count=$count missing clean terminal REGDUMP" >&2; return 1; }
  printf 'RAW_METADATA_RMW_PASS count=%s %s\n' "$count" "$summary"
}
run_invalid(){
  local count=$1 log="$RUN/invalid-$1.log" rc=0
  env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX='707f 5380 66fc' B2_TEST_DUMP=1 B2_TEST_METADATA_RMW_COUNT="$count" \
    timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "RAW_METADATA_RMW_FAIL invalid count=$count accepted" >&2; return 1; }
  grep -q 'B2_TEST_METADATA_RMW_COUNT must be 1..64' "$log" || {
    echo "RAW_METADATA_RMW_FAIL invalid count=$count wrong failure rc=$rc" >&2; tail -30 "$log" >&2; return 1; }
  printf 'RAW_METADATA_RMW_REJECT count=%s rc=%s\n' "$count" "$rc"
}
run_valid 1 02
run_valid 64 02
run_invalid 0
run_invalid 65
printf 'METRIC raw_metadata_rmw_boundaries=2\nMETRIC raw_metadata_rmw_runtime_cases=2\nMETRIC raw_metadata_rmw_rejections=2\nMETRIC raw_metadata_rmw_max_edges=64\n'
