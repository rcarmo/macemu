#!/bin/bash
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff; mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S); LOG="$OUTD/verify37-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== verify37 (hardened verifier on block 04037090) $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null
timeout 50 bin/boot-probe-gdb.sh v37 28 B2_JIT_VERIFY_BLOCKS=0x04037090-0x04037090 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-v37/emu.log ]; then
  echo "JITBLOCKVERIFY lines:"; grep "JITBLOCKVERIFY" /workspace/tmp/bootprobe-v37/emu.log | head -40
  echo "--- mismatch=1 count: $(grep -c 'mismatch=1' /workspace/tmp/bootprobe-v37/emu.log)"
  echo "--- mismatch=0 count: $(grep -c 'mismatch=0' /workspace/tmp/bootprobe-v37/emu.log)"
  echo "--- SKIP-NOREACH count: $(grep -c 'SKIP-NOREACH' /workspace/tmp/bootprobe-v37/emu.log)"
  echo "--- d3 reg diffs in mismatches ---"; grep -A18 "mismatch=1" /workspace/tmp/bootprobe-v37/emu.log | grep -E "reg\[3\]" | head
else echo "emu.log MISSING"; fi
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== verify37 done ==="
