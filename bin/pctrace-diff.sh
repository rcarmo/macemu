#!/bin/bash
# CONT.110 cont89: L1-vs-L2 block-entry PC differential (@auditor). Two independent
# NORMAL boots (no lockstep) with PCTRACE block-entry dumps; diff the PC streams to
# name the first divergent compiled block. arg1=optlev tag (l1|l2), arg2=start,
# arg3=end, arg4=limit, arg5=secs. L1 = B2_JIT_MAX_OPTLEV=1 (fixed fallback, boots);
# L2 = native (spins). Both reach the failing block.
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
TAG="${1:-l2}"; WSTART="${2:-0x04000000}"; WEND="${3:-0x040bffff}"; WLIM="${4:-9000}"; SECS="${5:-45}"
OUT="/workspace/tmp/pcd-$TAG"; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":44"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X44-lock /tmp/.X11-unix/X44 2>/dev/null
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
OPTENV=""
[ "$TAG" = "l1" ] && OPTENV="B2_JIT_MAX_OPTLEV=1"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  env $OPTENV B2_JIT_PCTRACE="$WLIM" B2_TRACE_PC_START="$WSTART" B2_TRACE_PC_END="$WEND" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
# extract ordered block-entry PC stream (PCTRACE step pc)
grep '^PCTRACE ' "$OUT/emu.log" | awk '{print $2, $3}' > "$OUT/pcstream.txt"
echo "[$TAG] PCTRACE lines: $(wc -l < "$OUT/pcstream.txt")"
