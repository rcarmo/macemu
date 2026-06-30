#!/bin/bash
# Out-of-band interp oracle: does interp execute the 04045xxx dispatch / d5-construction
# blocks, and with what d5(slot)/d7(slot-mask)/a2(scanner-ptr)? Compare vs JIT's
# d5=0xfe000000 / a2=040b98e0 scanner entry.
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/interp-pclog-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== interp-pclog $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
sleep 2

# Target: the 04045xxx dispatch + d5-swap construction region (where JIT builds
# d5=0xfe000000 super-slot $E and a2=040b98e0 scanner ptr).
echo "--- interp run, B2_INTERP_PCLOG=0x04045dc0-0x04045f40 (70s) ---"
timeout 95 bin/boot-probe-interp.sh ipl 70 B2_INTERP_PCLOG=0x04045dc0-0x04045f40 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-ipl/emu.log ]; then
  grep "INTERP_PCLOG" /workspace/tmp/bootprobe-ipl/emu.log > "$OUTD/interp-pclog-04045.txt"
  N=$(wc -l < "$OUTD/interp-pclog-04045.txt")
  echo "INTERP_PCLOG hits in 04045dc0-04045f40: $N"
  echo "--- unique d5 values interp uses here ---"
  grep -oE "d5=[0-9a-f]+" "$OUTD/interp-pclog-04045.txt" | sort | uniq -c | sort -rn | head
  echo "--- first 15 + last 5 ---"
  head -15 "$OUTD/interp-pclog-04045.txt"
  echo "..."
  tail -5 "$OUTD/interp-pclog-04045.txt"
  echo "--- did interp EVER produce d5=fe000000 (super-slot \$E)? ---"
  grep -c "d5=fe000000" "$OUTD/interp-pclog-04045.txt"
else
  echo "ipl emu.log MISSING"
fi
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
echo "=== interp-pclog done $STAMP ==="
