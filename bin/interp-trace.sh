#!/bin/bash
# CONT.110 cont70: @auditor's bound-immune check — does PURE INTERP (jit=false)
# execute the Slot-Mgr init range 040022xx-040024xx at all? If not -> control-flow
# fork (JIT wrongly branches into the scan). If yes -> data corruption.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"
SECS="${1:-40}"
RANGE="${2:-0x04002200-0x0400247f}"
JITMODE="${3:-false}"
OUT="/workspace/tmp/interp-trace-$JITMODE"
rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto "$BASE_DISK" "$OUT/disk.img"
DNUM=":34"
pkill -f "Xvfb $DNUM" 2>/dev/null || true
rm -f /tmp/.X34-lock /tmp/.X11-unix/X34 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 &
XV=$!; sleep 1
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit $JITMODE
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
echo "[interp] jit=$JITMODE, PCLOG=$RANGE, ${SECS}s"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" B2_INTERP_PCLOG="$RANGE" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!
for t in $(seq 1 "$SECS"); do
  sleep 1
  kill -0 "$EMU" 2>/dev/null || { echo "[interp] emu exited at ${t}s"; break; }
  [ $((t % 10)) -eq 0 ] && import -display "$DNUM" -window root "$OUT/shot-$t.png" 2>/dev/null && echo "[interp] shot ${t}s"
done
kill -9 "$EMU" 2>/dev/null || true
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XV" 2>/dev/null || true
echo "[interp] INTERP_PCLOG hit count:"; grep -c INTERP_PCLOG "$OUT/emu.log" 2>/dev/null || echo 0
echo "[interp] first 6 hits:"; grep INTERP_PCLOG "$OUT/emu.log" 2>/dev/null | head -6
echo "[interp] boot log tail:"; tail -4 "$OUT/emu.log"
