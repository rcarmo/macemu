#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/v37bis4-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37-bisect4 (single-op isolate LSL/subq/lsr) $STAMP ==="
for brk in 0x040371da 0x040371dc; do
  pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
  timeout 42 bin/boot-probe-gdb.sh v37e 18 B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 B2_FORCE_BLOCK_BREAK_BEFORE=$brk >/dev/null 2>&1
  L=$(grep "JITBLOCKVERIFY block=04037090" /workspace/tmp/bootprobe-v37e/emu.log 2>/dev/null | head -1)
  echo "BREAK=$brk :: ${L:-<no-line>}"
  grep -A4 "block=04037090 len=.* mismatch=1" /workspace/tmp/bootprobe-v37e/emu.log 2>/dev/null | grep "reg\[" | head -3
done
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== bisect4 done ==="
