#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/v37bis2-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37-bisect2 $STAMP (break routed to verifier) ==="
# Walk break points backward from the 040371b4 stop; first mismatch=0 brackets the diverging op.
for brk in 0x040371b4 0x040371ac 0x04037170 0x04037130 0x04037100 0x040370d0 0x040370c0; do
  pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
  timeout 42 bin/boot-probe-gdb.sh v37c 18 B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 B2_FORCE_BLOCK_BREAK_BEFORE=$brk >/dev/null 2>&1
  if [ -f /workspace/tmp/bootprobe-v37c/emu.log ]; then
    L=$(grep "JITBLOCKVERIFY block=04037090" /workspace/tmp/bootprobe-v37c/emu.log | head -1)
    echo "BREAK=$brk :: ${L:-<no-verify-line>}"
    grep -A6 "block=04037090 len=.* mismatch=1" /workspace/tmp/bootprobe-v37c/emu.log | grep -E "reg\[|mem\[" | head -6
  else echo "BREAK=$brk emu.log MISSING"; fi
done
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== bisect2 done ==="
