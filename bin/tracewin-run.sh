#!/bin/bash
# CONT.110 cont72: arm the EXISTING behavior-neutral exec_nostats value-logger
# (TRACEWINJ, compemu_legacy_arm64_compat.cpp:~898) via B2_TRACE_PC_START/END/LIMIT
# to catch the JIT's DYNAMIC dispatch entry into the 04002324 Slot-Mgr slot-scan
# (+ the computed a0=0xb7406 / a3 driving it). jit=true (forced-opt0 -> exec_nostats).
# fprintf-only: no register/flag/pc mutation -> does NOT perturb forced-opt0 control flow.
# In the current binary already -> NO BUILD NEEDED, just a run. Needs the shared slot.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"
SECS="${1:-45}"
WSTART="${2:-0x04002300}"
WEND="${3:-0x04002480}"
WLIMIT="${4:-600}"
OUT="/workspace/tmp/tracewin"
rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto "$BASE_DISK" "$OUT/disk.img"
DNUM=":35"
pkill -f "Xvfb $DNUM" 2>/dev/null || true
rm -f /tmp/.X35-lock /tmp/.X11-unix/X35 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 &
XV=$!; sleep 1
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit true
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
echo "[tracewin] jit=true, window [$WSTART-$WEND] limit=$WLIMIT, ${SECS}s"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  B2_TRACE_PC_START="$WSTART" B2_TRACE_PC_END="$WEND" B2_TRACE_LIMIT="$WLIMIT" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!
sleep "$SECS"
kill -9 "$EMU" 2>/dev/null || true
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XV" 2>/dev/null || true
echo "[tracewin] TRACEWINJ line count:"; grep -c "TRACEWINJ " "$OUT/emu.log" 2>/dev/null || echo 0
echo "[tracewin] first entry into 04002324 region (BEFORE lines):"
grep "TRACEWINJ BEFORE" "$OUT/emu.log" 2>/dev/null | head -20
echo "[tracewin] boot log tail:"; tail -4 "$OUT/emu.log"
