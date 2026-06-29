#!/bin/bash
# Read m1ec/m1ee/m1e8 memory + key regs via gdb sample. Non-perturbing.
set -u
TAG="${1:-default}"
SECS="${2:-30}"
shift 2 || true
EXTRA_ENV=("$@")

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"

OUT="/workspace/tmp/bootprobe-$TAG"
rm -rf "$OUT"; mkdir -p "$OUT/home"
DISK="$OUT/disk.img"
cp --reflink=auto "$BASE_DISK" "$DISK"

DNUM=":31"
pkill -f "Xvfb $DNUM" 2>/dev/null || true
rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 &
XVFB_PID=$!
sleep 1

cat > "$OUT/prefs" <<EOF
rom $ROM
disk $DISK
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

echo "[probe:$TAG] starting (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  env "${EXTRA_ENV[@]}" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU_PID=$!

sleep "$SECS"

kill -0 "$EMU_PID" 2>/dev/null && {
  echo "[probe:$TAG] sampling EMU_PID=$EMU_PID"
  # Read memory at known framevar addresses. A6 is regs.regs[14] (D0..D7 = 0..7, A0..A7 = 8..15)
  for i in 1 2 3; do
    sudo gdb -p "$EMU_PID" -batch -ex 'set pagination off' \
      -ex 'printf "REGSAMP pc=%08x guest=%08x d0=%08x d1=%08x d3=%08x a0=%08x a1=%08x a6=%08x\n", regs.pc, ((unsigned long)regs.pc_p - MEMBaseDiff), regs.regs[0], regs.regs[1], regs.regs[3], regs.regs[8], regs.regs[9], regs.regs[14]' \
      -ex 'printf "MEMSAMP m1ec=%08x m1ee=%08x m1e8=%08x m20a=%08x m13e=%08x m100=%08x m2c=%08x\n", *(unsigned int*)((char*)RAMBaseHost + 0x0200f852), *(unsigned int*)((char*)RAMBaseHost + 0x0200f850), *(unsigned int*)((char*)RAMBaseHost + 0x0200f856), *(unsigned int*)((char*)RAMBaseHost + 0x0200f834), *(unsigned int*)((char*)RAMBaseHost + 0x0200f900), *(unsigned int*)((char*)RAMBaseHost + 0x0200f93e), *(unsigned int*)((char*)RAMBaseHost + 0x0200fa12)' \
      2>/dev/null | grep -E "REGSAMP|MEMSAMP"
    sleep 1
  done
}
kill -0 "$EMU_PID" 2>/dev/null && { kill -9 "$EMU_PID" 2>/dev/null; }
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XVFB_PID" 2>/dev/null || true
echo "[probe:$TAG] done"
