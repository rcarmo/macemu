#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/v37bis3-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37-bisect3 (compile-length threshold, ops 17-36) $STAMP ==="
for brk in 0x040371d2 0x040371d8 0x040371de 0x040371e2 0x040371e8 0x04037200 0x04037234; do
  pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
  timeout 42 bin/boot-probe-gdb.sh v37d 18 B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 B2_FORCE_BLOCK_BREAK_BEFORE=$brk >/dev/null 2>&1
  L=$(grep "JITBLOCKVERIFY block=04037090" /workspace/tmp/bootprobe-v37d/emu.log 2>/dev/null | head -1)
  echo "BREAK=$brk :: ${L:-<no-line>}"
done
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== bisect3 done ==="
