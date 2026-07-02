#!/bin/bash
# CONT.110 cont77: dump guest RAM code around a given guest addr (host=addr+MEMBaseDiff)
# so we can disassemble the RAM-resident [0x2ba] setter. Attaches at steady state.
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
JITMODE="${1:-false}"; ADDR="${2:-0x02008c40}"; LEN="${3:-96}"; SECS="${4:-45}"
OUT=/workspace/tmp/ramdump; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":41"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X41-lock /tmp/.X11-unix/X41 2>/dev/null
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
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
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
if kill -0 "$EMU" 2>/dev/null; then
  sudo gdb -p "$EMU" -batch -ex 'set pagination off' \
    -ex "set \$a = (unsigned long)MEMBaseDiff + $ADDR" \
    -ex "dump binary memory $OUT/ram.bin \$a (\$a + $LEN)" 2>/dev/null
fi
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
if [ -f "$OUT/ram.bin" ]; then
  m68k-linux-gnu-objdump -D -b binary -m m68k:68040 --adjust-vma="$ADDR" "$OUT/ram.bin" 2>/dev/null | sed -n '7,60p'
else echo "no ram.bin"; fi
