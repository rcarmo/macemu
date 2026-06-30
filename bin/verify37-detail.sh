#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/v37det-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37-detail (full mismatch at len21=0x371da, len23=0x371de) $STAMP ==="
for brk in 0x040371da 0x040371de; do
  pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
  timeout 42 bin/boot-probe-gdb.sh v37f 18 B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 B2_FORCE_BLOCK_BREAK_BEFORE=$brk >/dev/null 2>&1
  echo "===== BREAK=$brk ====="
  grep -A16 "JITBLOCKVERIFY block=04037090" /workspace/tmp/bootprobe-v37f/emu.log 2>/dev/null | head -17
done
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== detail done ==="
