#!/bin/bash
# Out-of-band interp oracle over the 04037xxx setup/skip fork:
# 04037234 (JSR block) / 04037278 (setup path: 0403727a/040372a8 set m1e8=SP) vs
# 04037302 (skip path) / 04037362 / loop2 04037562. Compare interp path+d0/d1/a-regs
# to the JIT ring (which goes 04037234->04038440->04037302, skipping setup).
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/fork37-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== fork37 interp oracle $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
sleep 2

echo "--- interp PCLOG 0x04037230-0x040373a0 (the setup/skip fork) 70s ---"
timeout 95 bin/boot-probe-interp.sh f37 70 B2_INTERP_PCLOG=0x04037230-0x040373a0 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-f37/emu.log ]; then
  grep "INTERP_PCLOG" /workspace/tmp/bootprobe-f37/emu.log > "$OUTD/interp-fork37.txt"
  echo "interp hits in 04037230-040373a0: $(wc -l < "$OUTD/interp-fork37.txt")"
  echo "--- does interp hit the SETUP path 04037278/0403727a/040372a8 or the SKIP 04037302? ---"
  echo "04037278 (setup entry):  $(grep -c 'pc=04037278' "$OUTD/interp-fork37.txt")"
  echo "0403727a (setup):        $(grep -c 'pc=0403727a' "$OUTD/interp-fork37.txt")"
  echo "040372a8 (m1e8=SP store): $(grep -c 'pc=040372a8' "$OUTD/interp-fork37.txt")"
  echo "04037302 (skip path):    $(grep -c 'pc=04037302' "$OUTD/interp-fork37.txt")"
  echo "--- first 12 interp entries (path + d0/d1) ---"
  head -12 "$OUTD/interp-fork37.txt"
else
  echo "f37 emu.log MISSING"
fi
# Also the decision block 04037090 region (cont14 branch 040370b6)
echo "--- interp PCLOG 0x04037088-0x040370c0 (the 040370b6 cmpl/beq decision) ---"
timeout 95 bin/boot-probe-interp.sh f37b 70 B2_INTERP_PCLOG=0x04037088-0x040370c0 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-f37b/emu.log ]; then
  grep "INTERP_PCLOG" /workspace/tmp/bootprobe-f37b/emu.log > "$OUTD/interp-fork37b.txt"
  echo "interp hits 04037088-040370c0: $(wc -l < "$OUTD/interp-fork37b.txt")"
  head -8 "$OUTD/interp-fork37b.txt"
fi
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :32" 2>/dev/null
echo "=== fork37 done $STAMP ==="
