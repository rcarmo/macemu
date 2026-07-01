#!/bin/bash
# CONT.110 cont75: read low-mem [0x120] (dispatch vector), [0x12f] (phase counter),
# [0xbff] (branch byte at 04002694) at the JIT wall. guest addr -> host = addr+MEMBaseDiff.
# Guest memory is big-endian; read 4/1 bytes and interpret.
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
OUT=/workspace/tmp/lowmem; rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
JITMODE="${1:-true}"; SECS="${2:-45}"
DNUM=":39"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X39-lock /tmp/.X11-unix/X39 2>/dev/null
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
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
if kill -0 "$EMU" 2>/dev/null; then
  sudo gdb -p "$EMU" -batch -ex 'set pagination off' \
    -ex 'printf "pc=%08x\n", ((unsigned long)regs.pc_p - MEMBaseDiff)' \
    -ex 'set $b = (unsigned char *)MEMBaseDiff' \
    -ex 'printf "[0x120]=%02x%02x%02x%02x  [0x12f]=%02x  [0xbff]=%02x  [0xcb3]=%02x  [0x2ba]=%02x%02x%02x%02x  [0xaf0]=%02x%02x\n", $b[0x120],$b[0x121],$b[0x122],$b[0x123], $b[0x12f], $b[0xbff], $b[0xcb3], $b[0x2ba],$b[0x2bb],$b[0x2bc],$b[0x2bd], $b[0xaf0],$b[0xaf1]' \
    2>/dev/null | grep -E 'pc=|0x120'
fi
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
echo "[lowmem jit=$JITMODE] log tail:"; tail -2 "$OUT/emu.log"
