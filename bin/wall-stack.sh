#!/bin/bash
# CONT.110 cont79: deep stack dump at the JIT wall -> full ROM return-address chain
# (caller chain of the sResource dispatch) to find the common point with interp.
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
SECS="${1:-46}"
OUT=/workspace/tmp/wallstk; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":43"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X43-lock /tmp/.X11-unix/X43 2>/dev/null
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
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
if kill -0 "$EMU" 2>/dev/null; then
  sudo gdb -p "$EMU" -batch -ex 'set pagination off' \
    -ex 'printf "pc=%08x a7=%08x a5=%08x a6=%08x\n", ((unsigned long)regs.pc_p - MEMBaseDiff), regs.regs[15], regs.regs[13], regs.regs[14]' \
    -ex 'set $sp = (unsigned long)regs.regs[15] + MEMBaseDiff' \
    -ex 'dump binary memory /workspace/tmp/wallstk/stk.bin $sp ($sp + 768)' 2>/dev/null | grep pc=
fi
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
python3 - <<'PY'
import struct
try: b=open('/workspace/tmp/wallstk/stk.bin','rb').read()
except FileNotFoundError: print("no stk.bin"); raise SystemExit
seen=[]
for off in range(0,len(b)-3,2):
    v=(b[off]<<24)|(b[off+1]<<16)|(b[off+2]<<8)|b[off+3]
    if 0x04000000<=v<=0x040fffff:
        seen.append((off,v))
print("ROM return-address candidates on the wall stack (offset -> guest):")
for off,v in seen[:40]:
    print(f"  a7+{off:03x} = {v:08x}")
PY
