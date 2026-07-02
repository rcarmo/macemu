#!/bin/bash
# CONT.110 cont90e: LUT-region dump at consumer entry 0403b0e0, one run.
# Usage: lut-dump.sh <L1|L2> <outpath> [lo] [hi] [secs]
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
LEVEL="${1:-L2}"; OUTP="${2:-/workspace/tmp/lut_${LEVEL}.bin}"
LO="${3:-0xe000}"; HI="${4:-0x14000}"; SECS="${5:-90}"
OUT=/workspace/tmp/lut_${LEVEL}_run; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":4${RANDOM:0:1}"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X4*-lock 2>/dev/null
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
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
EXTRA=""
[ "$LEVEL" = "L1" ] && EXTRA="B2_JIT_MAX_OPTLEV=1"
rm -f "$OUTP"
# TRACEWIN window == only the consumer entry so just that one block is perturbed;
# generator 0403bf00 runs native (corrupt in L2). PCTRACE enables the hook that fires the dump.
TRIG="${TRIG:-0x0403b0e0}"
env $EXTRA B2_TRACE_PC_START="$TRIG" B2_TRACE_PC_END="$TRIG" B2_JIT_PCTRACE=2000000000 \
  B2_LUT_DUMP_TRIG_PC="$TRIG" B2_LUT_DUMP_PATH="$OUTP" B2_LUT_DUMP_LO="$LO" B2_LUT_DUMP_HI="$HI" \
  SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!
# wait for dump or timeout
for i in $(seq 1 "$SECS"); do
  [ -f "$OUTP" ] && sleep 1 && break
  kill -0 "$EMU" 2>/dev/null || break
  sleep 1
done
grep -a "LUT_DUMP" "$OUT/emu.log" 2>/dev/null | tail -1
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
if [ -f "$OUTP" ]; then echo "OK $LEVEL dump -> $OUTP ($(stat -c %s "$OUTP") bytes)"; else echo "NO DUMP $LEVEL (log tail:)"; tail -5 "$OUT/emu.log"; fi
