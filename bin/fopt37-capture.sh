#!/bin/bash
# Localization test: force block 04037090 (the d3-corruption block) to interpret.
# If the wall clears / boot advances, the bug is in block 04037090's L2 compilation
# (d3 not preserved across its JSRs).
set -u
cd /workspace/projects/macemu
OUTD=/workspace/tmp/linkdiff
mkdir -p "$OUTD"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUTD/fopt37-$STAMP.log"
exec > "$LOG" 2>&1
echo "=== fopt37 localization $STAMP ==="
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
sleep 2; rm -f /tmp/.X31-lock /tmp/.X11-unix/X31 2>/dev/null

echo "--- boot with B2_JIT_FORCE_OPTLEV0_PCS=0x04037090-0x04037234 (block forced-interp) ---"
timeout 45 bin/boot-probe-gdb.sh fopt37 22 B2_JIT_FORCE_OPTLEV0_PCS=0x04037090-0x04037234 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-fopt37/emu.log ]; then
  echo "BTST_D16AN (scanner spin) count: $(grep -c BTST_D16AN /workspace/tmp/bootprobe-fopt37/emu.log 2>/dev/null)"
  echo "VideoDriverControl/SetEntries (PAST wall): $(grep -cE 'VideoDriverControl|mac_frame_base|SetEntries' /workspace/tmp/bootprobe-fopt37/emu.log 2>/dev/null)"
  echo "--- furthest guest PCs (SEGV/JITMAP) ---"
  grep -oE "guest=040[0-9a-f]{5}" /workspace/tmp/bootprobe-fopt37/emu.log 2>/dev/null | sort -u | tail -8
  echo "--- last emu.log lines ---"
  tail -6 /workspace/tmp/bootprobe-fopt37/emu.log
else
  echo "emu.log MISSING"
fi

echo ""
echo "--- BASELINE (no force) for comparison ---"
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null; sleep 2
timeout 45 bin/boot-probe-gdb.sh fopt37base 22 >/dev/null 2>&1
if [ -f /workspace/tmp/bootprobe-fopt37base/emu.log ]; then
  echo "BASELINE BTST_D16AN count: $(grep -c BTST_D16AN /workspace/tmp/bootprobe-fopt37base/emu.log 2>/dev/null)"
  echo "BASELINE VideoDriverControl: $(grep -cE 'VideoDriverControl|mac_frame_base|SetEntries' /workspace/tmp/bootprobe-fopt37base/emu.log 2>/dev/null)"
fi
pkill -9 BasiliskII 2>/dev/null; pkill -f "Xvfb :31" 2>/dev/null
echo "=== fopt37 done $STAMP ==="
