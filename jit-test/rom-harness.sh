#!/bin/bash
# Headless Mac — boots Quadra 800 ROM through JIT at optlev=2.
# NO interpreter fallback. All blocks compile to native ARM64 on first hit.
# No display server needed.
#
# Usage:
#   ./jit-test/rom-harness.sh                      # 2 min smoke test
#   B2_TIMEOUT=600 ./jit-test/rom-harness.sh       # 10 min full boot
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
SECS="${B2_TIMEOUT:-120}"

[ -f "$ROM" ] || { echo "ROM not found: $ROM" >&2; exit 1; }
[ -x "$BIN" ] || { echo "Binary not found: $BIN" >&2; exit 1; }

LOG_ROOT="${B2_LOG_ROOT:-/workspace/tmp/basiliskii-rom-harness}"
mkdir -p "$LOG_ROOT"
W=$(mktemp -d "$LOG_ROOT/headless-mac-XXXXXX")
if [ "${B2_KEEP_LOGS:-1}" = "1" ]; then
  trap 'echo "LOGDIR '$W'" >&2' EXIT
else
  trap 'rm -rf "$W"' EXIT
fi
cat >"$W/prefs" <<EOF
rom $ROM
ramsize 8388608
modelid 14
cpu 4
fpu false
jit true
jitfpu false
jitcachesize ${B2_JIT_CACHE_SIZE:-131072}
screen win/640/480
nosound true
nocdrom true
ignoresegv true
EOF

echo "Headless Mac: optlev=2, force-translate, cache=${B2_JIT_CACHE_SIZE:-131072}KB, timeout=${SECS}s" >&2
env HOME="$W" \
    B2_ROM_HARNESS=999999 \
    B2_JIT_FORCE_TRANSLATE=1 \
    B2_JIT_MAX_OPTLEV=2 \
    SDL_VIDEODRIVER=dummy \
    SDL_AUDIODRIVER=dummy \
  timeout -k5 "${SECS}" "$BIN" --config "$W/prefs" >"$W/out" 2>"$W/err"
RC=$?

# Parse
LAST=$(grep '^DC\[' "$W/err" | tail -1 || true)
DC_NUM=$(echo "$LAST" | sed -n 's/DC\[\([0-9]*\)\].*/\1/p')
PC=$(echo "$LAST" | sed -n 's/.* pc=\([0-9a-f]*\) .*/\1/p')
SR=$(echo "$LAST" | sed -n 's/.* sr=\([0-9a-f]*\) .*/\1/p')
SCSI=$(grep -c SCSIGet "$W/err" || true)
SEGV=$(grep -c SEGV_SKIP "$W/err" || true)
FALLBACK=$(grep -c JIT_FALLBACK "$W/err" || true)
VERIFY=$(grep -c JITBLOCKVERIFY "$W/err" || true)
BADPC=$(grep -c bad_pcp "$W/err" || true)
OP8C4C=$(grep -c 'op=8c4c' "$W/err" || true)
FATAL=$(grep -Ec 'SIGILL|SIGSEGV|SIGBUS|Illegal instruction|Bus error|Segmentation fault' "$W/err" || true)

IN_RAM=no
if [ -n "$PC" ]; then
  PCV=$((16#$PC))
  ! ([ "$PCV" -ge $((16#800000)) ] && [ "$PCV" -le $((16#8FFFFF)) ]) && IN_RAM=yes
fi

echo "" >&2
echo "=== Headless Mac ===" >&2
grep '^DC\[' "$W/err" | tail -5 >&2
for m in "FORCE_TRANSLATE" "max_optlev" "PatchROM ok" SCSIGet set_dsk_err DiskControl; do
  grep -q "$m" "$W/err" 2>/dev/null && echo "  ✅ $m" >&2 || echo "  ❌ $m" >&2
done
echo "pc=${PC:-?} sr=${SR:-?} dc=${DC_NUM:-0} in_ram=$IN_RAM scsi=$SCSI segv=$SEGV fallback=$FALLBACK verify=$VERIFY badpc=$BADPC op8c4c=$OP8C4C fatal=$FATAL rc=$RC" >&2
echo "raw logs: $W" >&2

echo "METRIC headless_pc=${PC:-?}"
echo "METRIC headless_dc=${DC_NUM:-0}"
echo "METRIC headless_in_ram=$IN_RAM"
echo "METRIC headless_scsi=$SCSI"
echo "METRIC headless_segv=$SEGV"
echo "METRIC headless_fallback=$FALLBACK"
echo "METRIC headless_verify=$VERIFY"
echo "METRIC headless_badpc=$BADPC"
echo "METRIC headless_op8c4c=$OP8C4C"
echo "METRIC headless_fatal=$FATAL"
echo "METRIC headless_rc=$RC"

# timeout(1) status 124 is the expected end of a bounded smoke run. Any other
# non-zero status is an emulator/runtime failure, and a timeout without even one
# progress record is not a valid smoke result.
if { [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; } || [ -z "$PC" ] || [ -z "$DC_NUM" ]; then
  echo "FAIL: ROM harness process/progress contract failed rc=$RC pc=${PC:-?} dc=${DC_NUM:-?}; inspect $W" >&2
  exit 1
fi
if [ "$FALLBACK" -ne 0 ] || [ "$SEGV" -ne 0 ] || [ "$VERIFY" -ne 0 ] || [ "$BADPC" -ne 0 ] || [ "$OP8C4C" -ne 0 ] || [ "$FATAL" -ne 0 ]; then
  echo "FAIL: full-JIT strict marker check failed; inspect raw logs in $W" >&2
  exit 1
fi
