#!/bin/bash
# CONT.110 cont69: capture the RUNTIME scanner input at the 040ba0a8 NuBus
# slot-scanner wall — which sResource/slot the scan is stuck on and why it
# never exits. Adds a3/d2/d3 + the slot decl-ROM struct memory (a3@(2), a3@(6),
# a3@(2,d3)) to the boot-probe gdb sampling. Register map: regs.regs[0..7]=D0-D7,
# regs.regs[8..15]=A0-A7; guest addr -> host = addr + MEMBaseDiff.
# DO NOT run while another macemu emulator holds the shared slot (CPU-contends).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"
SECS="${1:-45}"
OUT="/workspace/tmp/wall-capture"
rm -rf "$OUT"; mkdir -p "$OUT/home"
DISK="$OUT/disk.img"; cp --reflink=auto "$BASE_DISK" "$DISK"

DNUM=":32"
pkill -f "Xvfb $DNUM" 2>/dev/null || true
rm -f /tmp/.X32-lock /tmp/.X11-unix/X32 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 &
XVFB_PID=$!; sleep 1

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

echo "[wall] starting (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU_PID=$!
sleep "$SECS"

if kill -0 "$EMU_PID" 2>/dev/null; then
  echo "[wall] sampling scanner state EMU_PID=$EMU_PID"
  for i in 1 2 3; do
    sudo gdb -p "$EMU_PID" -batch -ex 'set pagination off' \
      -ex 'printf "SCAN pc=%08x d0=%08x d2=%08x d3=%08x d7=%08x a0=%08x a1=%08x a3=%08x a6=%08x\n", ((unsigned long)regs.pc_p - MEMBaseDiff), regs.regs[0], regs.regs[2], regs.regs[3], regs.regs[7], regs.regs[8], regs.regs[9], regs.regs[11], regs.regs[14]' \
      -ex 'set $a3g = regs.regs[11]' \
      -ex 'set $a3h = (unsigned char *)((unsigned long)$a3g + MEMBaseDiff)' \
      -ex 'printf "SLOT a3=%08x  a3@0..7 = %02x %02x %02x %02x %02x %02x %02x %02x\n", (unsigned)$a3g, $a3h[0],$a3h[1],$a3h[2],$a3h[3],$a3h[4],$a3h[5],$a3h[6],$a3h[7]' \
      -ex 'set $d3v = regs.regs[3]' \
      -ex 'printf "SLOTD3 a3@(2,d3)=%02x  d3=%08x\n", $a3h[2 + ($d3v & 0xffffffff)], (unsigned)$d3v' \
      2>/dev/null | grep -E 'SCAN|SLOT'
    sleep 1
  done
fi
kill -9 "$EMU_PID" 2>/dev/null || true
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XVFB_PID" 2>/dev/null || true
echo "[wall] log tail:"; tail -6 "$OUT/emu.log"
