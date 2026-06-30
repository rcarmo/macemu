#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/v37bisect-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37-bisect $STAMP ==="
# Bisect block 04037090 by ending it before candidate ops; find smallest segment still mismatch=1.
for brk in 0x040370c8 0x040370e8 0x04037124 0x040371a8 0x040371b4; do
  pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
  timeout 45 bin/boot-probe-gdb.sh v37b "20" B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 B2_FORCE_BLOCK_BREAK_BEFORE=$brk >/dev/null 2>&1
  if [ -f /workspace/tmp/bootprobe-v37b/emu.log ]; then
    L=$(grep "JITBLOCKVERIFY block=04037090" /workspace/tmp/bootprobe-v37b/emu.log | head -1)
    M1=$(grep -c "block=04037090 len=.* mismatch=1" /workspace/tmp/bootprobe-v37b/emu.log)
    echo "BREAK_BEFORE=$brk -> mismatch1=$M1 :: $L"
    [ "$M1" -gt 0 ] && grep -A8 "block=04037090 len=.* mismatch=1" /workspace/tmp/bootprobe-v37b/emu.log | head -9
  else echo "BREAK_BEFORE=$brk emu.log MISSING"; fi
done
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== bisect done ==="
