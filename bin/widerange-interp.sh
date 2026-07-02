#!/bin/bash
# cont92 cont15: wide interp path capture over [lo,hi] with a raised PCLOG cap.
# Proves the 400-op cap was arbitrary output-bounding: one wide run replaces the
# O(N) linear walk. Usage: widerange-interp.sh <lo> <hi> <cap> <secs> <tag>
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
LO="${1:-0x040b68c0}"; HI="${2:-0x040b98ff}"; CAP="${3:-4000}"; SECS="${4:-75}"; TAG="${5:-wide}"
OUT=/workspace/tmp/wide_${TAG}; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
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
jit false
jitfpu false
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
env B2_INTERP_PCLOG="${LO}-${HI}" B2_INTERP_PCLOG_CAP="$CAP" \
  SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
N=$(grep -acE 'INTERP_PCLOG' "$OUT/emu.log" 2>/dev/null)
echo "=== interp path [$LO,$HI] cap=$CAP — $N hits ==="
echo "--- first 20 ---"; grep -aE 'INTERP_PCLOG' "$OUT/emu.log" | head -20
echo "--- unique PCs (in order of first appearance) ---"
grep -aoE 'INTERP_PCLOG pc=[0-9a-f]+' "$OUT/emu.log" | awk '!seen[$0]++' | head -80
echo "log: $OUT/emu.log"
