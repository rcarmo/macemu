#!/bin/bash
# CONT.110 cont31: hardened block-link verifier armed on the cont14 branch
# block 04037090. Capture JITBLOCKVERIFY REACHED/SKIP-NOREACH classification.
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
RES="$OUTD/lv37-$STAMP.txt"
exec > "$RES" 2>&1

echo "=== lv37 verify run $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :33" 2>/dev/null
sleep 2
rm -f /tmp/.X33-lock /tmp/.X11-unix/X33

ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"
BIN="/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII"
OUT="/workspace/tmp/lv37run"
rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto "$BASE_DISK" "$OUT/disk.img"

Xvfb :33 -screen 0 640x480x24 >/dev/null 2>&1 &
XPID=$!
sleep 1

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

SDL_VIDEODRIVER=x11 DISPLAY=:33 HOME="$OUT/home" \
  B2_JIT_VERIFY_PCS=0x04037090 \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!
sleep 22
kill -9 $EMU 2>/dev/null
kill -9 $XPID 2>/dev/null
pkill -9 BasiliskII 2>/dev/null

echo "--- emu.log size ---"; wc -l "$OUT/emu.log"
echo "--- JITBLOCKVERIFY for 04037090 (first 20) ---"
grep "JITBLOCKVERIFY block=04037090" "$OUT/emu.log" | head -20
echo "--- REACHED count ---"; grep -c "block=04037090.*REACHED" "$OUT/emu.log"
echo "--- SKIP-NOREACH count ---"; grep -c "block=04037090.*SKIP-NOREACH" "$OUT/emu.log"
echo "--- any MISMATCH lines ---"; grep "JITBLOCKVERIFY.*MISMATCH\|VERIFY.*mismatch" "$OUT/emu.log" | head -10
echo "--- unique native_stop_pc for 04037090 ---"
grep "block=04037090" "$OUT/emu.log" | grep -oE "native_stop_pc=[0-9a-f]+|native_pc=[0-9a-f]+" | sort | uniq -c
echo "=== done $STAMP ==="
cp "$RES" "$OUTD/lv37-latest.txt"
