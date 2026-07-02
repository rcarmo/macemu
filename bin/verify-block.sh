#!/bin/bash
# Arm the input-controlled block verifier on ONE block, natural boot, capture
# the JITBLOCKVERIFY line(s) to distinguish a natural loop exit from a
# forced-cut (countdown=-1) segmentation boundary. arg1=block hex, arg2=secs.
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
BLK="${1:-0x401b6d2}"; SECS="${2:-25}"
OUT=$(mktemp -d); mkdir -p "$OUT/home"
DNUM=":9$((RANDOM%90+10))"
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
cat > "$OUT/prefs" <<PREFS
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
PREFS
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  env B2_JIT_VERIFY_BLOCKS="$BLK" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
echo "=== JITBLOCKVERIFY lines for $BLK ==="
grep 'JITBLOCKVERIFY' "$OUT/emu.log" | head -40
echo "=== counts ==="
grep -c 'REACHED' "$OUT/emu.log" | sed 's/^/REACHED: /'
grep -c 'SKIP-NOREACH' "$OUT/emu.log" | sed 's/^/SKIP-NOREACH: /'
grep -c 'mismatch=1' "$OUT/emu.log" | sed 's/^/mismatch=1: /'
echo "OUT=$OUT"
