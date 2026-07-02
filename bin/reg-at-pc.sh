#!/bin/bash
# cont90h: capture guest regs at a guest PC via PCTRACE (JIT) / INTERP_PCLOG (interp).
# Usage: reg-at-pc.sh <L2|L0> <pc_hex> <outtag> [secs]
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
LEVEL="${1:-L2}"; PC="${2:-0x040b6c20}"; TAG="${3:-r}"; SECS="${4:-90}"
OUT=/workspace/tmp/regpc_${TAG}; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":4${RANDOM:0:1}"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X4*-lock 2>/dev/null
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
JIT=true; [ "$LEVEL" = "L0" ] && JIT=false
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit $JIT
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
# JIT: PCTRACE hook with TRACEWIN==PC. INTERP: B2_INTERP_PCLOG range==PC.
ENV=""
if [ "$LEVEL" = "L0" ]; then
  ENV="B2_INTERP_PCLOG=1 B2_INTERP_PCLOG_LO=$PC B2_INTERP_PCLOG_HI=$PC"
else
  ENV="B2_JIT_PCTRACE=2000000000 B2_TRACE_PC_START=$PC B2_TRACE_PC_END=$PC B2_JIT_PCTRACE_STACK=1 B2_JIT_PCTRACE_MEM=1"
fi
env $ENV SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
echo "=== $LEVEL @ $PC — first + last few trace hits ==="
grep -aE "PCTRACE|INTERP_PC|PCTSTACK|PCTMEM" "$OUT/emu.log" 2>/dev/null | head -6
echo "..."
grep -aE "PCTRACE|INTERP_PC" "$OUT/emu.log" 2>/dev/null | tail -3
echo "hit count: $(grep -acE 'PCTRACE|INTERP_PC' "$OUT/emu.log" 2>/dev/null)"
