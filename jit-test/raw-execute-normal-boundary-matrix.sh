#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-execute-normal-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-execute-normal | tail -1)"
for n in $(seq 100 199); do if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break; fi; done
[[ -n "${D:-}" ]] || { echo 'RAW_EXECUTE_NORMAL_FAIL no display' >&2; exit 1; }
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
  local name=$1 force=$2 expect_direct=$3 expect_normal=$4 expect_nostats=$5 expect_direct_nostats=$6
  local log="$RUN/$name.log" summary direct normal nostats direct_nostats recompile checksum check good bad metadata cycles
  local -a force_env=()
  [[ "$force" == 0 ]] || force_env+=(B2_TEST_FORCE_DIRECT_EXECUTE_NORMAL=1)
  env -u B2_TEST_FORCE_DIRECT_EXECUTE_NORMAL SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
    B2_TEST_HEX='7001 5280 2C7C A6E0 0001' B2_TEST_DUMP=1 \
    B2_TEST_TWO_PASS=1 B2_TEST_REPLAY_COUNT=1 \
    B2_JIT_DIAG=1 B2_TEST_DISPATCH_SUMMARY=1 \
    ${force_env[@]+"${force_env[@]}"} timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
  summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
  [[ -n "$summary" ]] || { echo "RAW_EXECUTE_NORMAL_FAIL $name missing summary" >&2; tail -30 "$log" >&2; exit 1; }
  direct=$(sed -n 's/.* direct_execute_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  normal=$(sed -n 's/.* exec_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  nostats=$(sed -n 's/.* exec_nostats=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  direct_nostats=$(sed -n 's/.* direct_exec_nostats=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  recompile=$(sed -n 's/.* recompile_block=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  checksum=$(sed -n 's/.* direct_checksum=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  check=$(sed -n 's/.* check_checksum=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  good=$(sed -n 's/.* good=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  bad=$(sed -n 's/.* bad=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  metadata=$(sed -n 's/.* metadata_rebuild=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  cycles=$(sed -n 's/.* execute_normal_cycles=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
  [[ ${direct:-0} -eq "$expect_direct" && ${normal:-0} -eq "$expect_normal" &&
      ${nostats:-0} -eq "$expect_nostats" && ${direct_nostats:-0} -eq "$expect_direct_nostats" &&
      ${recompile:-0} -eq 0 && ${checksum:-0} -eq 0 && ${check:-0} -eq 0 &&
      ${good:-0} -eq 0 && ${bad:-0} -eq 0 && ${metadata:-0} -eq 0 && ${cycles:-0} -eq 0 ]] || {
    echo "RAW_EXECUTE_NORMAL_FAIL $name unexpected summary: $summary" >&2; tail -30 "$log" >&2; exit 1; }
  grep -q '^REGDUMP: D0=00000002 ' "$log" || { echo "RAW_EXECUTE_NORMAL_FAIL $name terminal REGDUMP" >&2; exit 1; }
  printf 'RAW_EXECUTE_NORMAL_PASS case=%s %s\n' "$name" "$summary"
}
run_case unforced 0 0 1 1 1
run_case forced 1 1 2 0 0
printf 'METRIC raw_execute_normal_boundaries=1\nMETRIC raw_execute_normal_runtime_cases=2\nMETRIC raw_execute_normal_unforced_direct=0\nMETRIC raw_execute_normal_direct_entries=1\n'
