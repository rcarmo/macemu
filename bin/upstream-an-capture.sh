#!/bin/bash
# Out-of-band: capture the JIT path INTO the slot-scan (target the slot-scan entry
# block, not the wall) to find the LAST shared block + the An value at entry.
# Then interp PCLOG over the upstream driver region to see interp's An there.
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/upstream-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== upstream-An capture $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
sleep 2

echo "--- [1] JIT PATHRING target 0x04045e0e (slot-scan entry) - full ring tail ---"
timeout 45 bin/boot-probe-gdb.sh upj 22 B2_PATH_RING_TARGET=0x04045e0e >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-upj/emu.log ]; then
  grep "PATHRING" /workspace/tmp/bootprobe-upj/emu.log > "$OUTD/jit-pathring-into-04045.txt"
  N=$(wc -l < "$OUTD/jit-pathring-into-04045.txt")
  echo "JIT PATHRING-into-04045 entries: $N"
  echo "--- first appearance of 04045/040bd in the ring + 30 preceding entries ---"
  FIRST=$(grep -nE "pc=04045|pc=040bd" "$OUTD/jit-pathring-into-04045.txt" | head -1 | cut -d: -f1)
  echo "first slot-scan PC at ring line: $FIRST"
  if [ -n "$FIRST" ]; then
    START=$((FIRST>30 ? FIRST-30 : 1))
    sed -n "${START},$((FIRST+3))p" "$OUTD/jit-pathring-into-04045.txt"
  fi
else
  echo "upj emu.log MISSING"
fi

sleep 2
echo "--- [2] interp PCLOG over upstream driver region 0x040b6c00-0x040b7040 (70s) ---"
timeout 95 bin/boot-probe-interp.sh upi 70 B2_INTERP_PCLOG=0x040b6c00-0x040b7040 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-upi/emu.log ]; then
  grep "INTERP_PCLOG" /workspace/tmp/bootprobe-upi/emu.log > "$OUTD/interp-pclog-040b6.txt"
  echo "interp PCLOG 040b6c00-040b7040 hits: $(wc -l < "$OUTD/interp-pclog-040b6.txt")"
  head -10 "$OUTD/interp-pclog-040b6.txt"
fi
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
echo "=== upstream-An capture done $STAMP ==="
