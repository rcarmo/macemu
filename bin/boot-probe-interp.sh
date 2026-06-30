#!/bin/bash
# Boot-progress probe: run BasiliskII JIT for N seconds on a headless Xvfb,
# screenshot the framebuffer at intervals. Usage: boot-probe.sh <tag> <seconds> [extra-env...]
set -u
TAG="${1:-default}"
SECS="${2:-60}"
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

DNUM=":32"
pkill -f "Xvfb $DNUM" 2>/dev/null || true
rm -f /tmp/.X32-lock /tmp/.X11-unix/X32 2>/dev/null || true
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
jit false
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF

echo "[probe:$TAG] starting (${SECS}s), env: ${EXTRA_ENV[*]}"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  env "${EXTRA_ENV[@]}" \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU_PID=$!

for t in $(seq 1 "$SECS"); do
  sleep 1
  if ! kill -0 "$EMU_PID" 2>/dev/null; then
    echo "[probe:$TAG] emulator EXITED after ${t}s (rc unknown)"
    break
  fi
  if [ $((t % 10)) -eq 0 ] || [ "$t" -eq "$SECS" ]; then
    import -display "$DNUM" -window root "$OUT/shot-$(printf %03d "$t").png" 2>/dev/null \
      && echo "[probe:$TAG] shot at ${t}s"
  fi
done

kill -0 "$EMU_PID" 2>/dev/null && {
  echo "[probe:$TAG] gdb-sampling EMU_PID=$EMU_PID"
  for i in 1 2 3 4 5; do
    sudo gdb -p "$EMU_PID" -batch -ex 'set pagination off' \
      -ex 'printf "PCSAMP pc=%08x d0=%08x d1=%08x d7=%08x a0=%08x a1=%08x a6=%08x a7=%08x sr=%04x\n", ((unsigned long)regs.pc_p - MEMBaseDiff), regs.regs[0], regs.regs[1], regs.regs[7], regs.regs[8], regs.regs[9], regs.regs[14], regs.regs[15], regs.sr' \
      2>/dev/null | grep PCSAMP
    sleep 1
  done
}
kill -0 "$EMU_PID" 2>/dev/null && { echo "[probe:$TAG] still running at ${SECS}s (kill)"; kill -9 "$EMU_PID" 2>/dev/null; }
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XVFB_PID" 2>/dev/null || true

echo "[probe:$TAG] log tail:"; tail -8 "$OUT/emu.log"
echo "[probe:$TAG] shots:"; ls -1 "$OUT"/shot-*.png 2>/dev/null
