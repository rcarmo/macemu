#!/bin/bash
# Out-of-band capture for the block-LINK-graph differential.
# 1. JIT run: PATHRING chain-entry trajectory into the 040ba0a8 wall.
# 2. Interp run: full visited block-entry PC set (oracle).
# Writes stable result files under /workspace/tmp/linkdiff/.
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/run-$STAMP.log"
exec > "$LOG" 2>&1

echo "=== linkdiff capture $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
sleep 2

echo "--- [1/2] JIT PATHRING into wall 040ba0a8 ---"
timeout 40 bin/boot-probe-gdb.sh ldjit 20 B2_PATH_RING_TARGET=0x040ba0a8 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-ldjit/emu.log ]; then
  grep "PATHRING" /workspace/tmp/bootprobe-ldjit/emu.log | tail -120 > "$OUTD/jit-pathring-tail.txt"
  echo "JIT PATHRING entries captured: $(wc -l < "$OUTD/jit-pathring-tail.txt")"
else
  echo "JIT emu.log MISSING"
fi

sleep 2
echo "--- [2/2] Interp visited-PC oracle (NOJIT_DIAG range + sampled PCs) ---"
timeout 90 bin/boot-probe-interp.sh ldint 70 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-ldint/emu.log ]; then
  grep "NOJIT_DIAG" /workspace/tmp/bootprobe-ldint/emu.log | tail -200 > "$OUTD/interp-nojitdiag.txt"
  # unique range-max values to bound interp's furthest reach
  grep -oE "range=\[0x[0-9a-f]+,0x[0-9a-f]+\]" /workspace/tmp/bootprobe-ldint/emu.log | sort -u > "$OUTD/interp-range-uniq.txt"
  echo "Interp NOJIT_DIAG captured: $(wc -l < "$OUTD/interp-nojitdiag.txt")"
else
  echo "Interp emu.log MISSING"
fi

pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
echo "=== linkdiff capture done $STAMP ==="
