#!/bin/bash
# Out-of-band: discriminate single-block-codegen vs L2-coherence for the
# 0x0404xxxx compiled dispatch blocks (04045e2c/04047568/04045f36/04045e46)
# that load the scanner pointer A2=040b98e0 / super-slot d5=0xfe000000.
# JITVERIFY per-op reg/mem differential at L2 (force-opt0 disabled).
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/verify0404-$STAMP.log"
exec > "$LOG" 2>&1

echo "=== verify0404 $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
sleep 2

echo "--- JITVERIFY 0x04045000-0x04047600 (compiled dispatch blocks) at L2, 70s ---"
timeout 95 bin/boot-probe-gdb.sh v0404 70 \
  B2_JIT_NO_FORCE_OPT0=1 "B2_JIT_VERIFY_PCS=0x04045000-0x04047600" >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-v0404/emu.log ]; then
  grep "JITVERIFY" /workspace/tmp/bootprobe-v0404/emu.log > "$OUTD/jitverify-0404.txt"
  N=$(wc -l < "$OUTD/jitverify-0404.txt")
  echo "JITVERIFY mismatch lines: $N"
  head -20 "$OUTD/jitverify-0404.txt"
  echo "--- wall reached? (scanner BTST markers / PCSAMP at 040ba) ---"
  echo "BTST_D16AN count: $(grep -c BTST_D16AN /workspace/tmp/bootprobe-v0404/emu.log 2>/dev/null)"
  grep PCSAMP /workspace/tmp/bootprobe-v0404/emu.log 2>/dev/null | tail -2
  echo "--- did boot pass 04045xxx? (SEGV/JITMAP furthest guest) ---"
  grep -oE "guest=040[0-9a-f]{5}" /workspace/tmp/bootprobe-v0404/emu.log 2>/dev/null | sort -u | tail -8
else
  echo "v0404 emu.log MISSING"
fi

pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== verify0404 done $STAMP ==="
