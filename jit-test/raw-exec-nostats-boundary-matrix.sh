#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
COW_LIB="${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}"
source "$COW_LIB"
RUN="$(mktemp -d /tmp/b2-raw-exec-nostats-XXXXXX)"
XV=""; CLONE=""
cleanup(){ [[ -z "$XV" ]] || { kill "$XV" 2>/dev/null || true; wait "$XV" 2>/dev/null || true; }; [[ -z "$CLONE" ]] || cow_release "$CLONE"; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN/home"
CLONE="$(cow_clone "$DISK" "$RUN/disk.img" raw-exec-nostats | tail -1)"
for n in $(seq 100 199); do if [[ ! -e /tmp/.X$n-lock && ! -S /tmp/.X11-unix/X$n ]]; then DISPLAY=:$n Xvfb :$n -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; D=:$n; break; fi; done
[[ -n "${D:-}" ]] || { echo 'RAW_EXEC_NOSTATS_FAIL no display' >&2; exit 1; }
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
log="$RUN/run.log"
env SDL_VIDEODRIVER=x11 DISPLAY="$D" HOME="$RUN/home" \
  B2_TEST_HEX='7001 5280 2C7C A6E0 0001' B2_TEST_DUMP=1 \
  B2_TEST_TWO_PASS=1 B2_TEST_REPLAY_COUNT=2 \
  B2_JIT_FORCE_OPTLEV0=1 B2_JIT_DIAG=1 B2_TEST_DISPATCH_SUMMARY=1 \
  timeout -k 5s 30s "$BIN" --config "$RUN/prefs" >"$log" 2>&1
summary=$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)
[[ -n "$summary" ]] || { echo 'RAW_EXEC_NOSTATS_FAIL missing summary' >&2; tail -30 "$log" >&2; exit 1; }
direct=$(sed -n 's/.* direct_exec_nostats=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
calls=$(sed -n 's/.* exec_nostats=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
normal=$(sed -n 's/.* exec_normal=\([0-9][0-9]*\).*/\1/p' <<<"$summary")
[[ ${direct:-0} -eq 2 && ${calls:-0} -eq 2 && ${normal:-0} -eq 1 ]] || {
  echo "RAW_EXEC_NOSTATS_FAIL unexpected summary: $summary" >&2; exit 1; }
grep -q '^REGDUMP: D0=00000002 ' "$log" || { echo 'RAW_EXEC_NOSTATS_FAIL missing terminal D0/REGDUMP' >&2; exit 1; }
printf 'RAW_EXEC_NOSTATS_PASS %s\n' "$summary"
printf 'METRIC raw_exec_nostats_boundaries=1\nMETRIC raw_exec_nostats_runtime_cases=1\nMETRIC raw_exec_nostats_direct_entries=2\n'
