#!/usr/bin/env bash
# lockstep.sh — JIT-vs-interp instruction-level lockstep comparator.
#
# Both engines start logging only after the single-visit boot ANCHOR PC
# (B2_TRACE_ANCHOR_PC) is executed, so the two instruction streams align at
# the same boot point. We then diff the (pc,op) streams forward to find the
# FIRST divergent successor PC — the mis-routing branch.
#
# Interp stream: TRACEWIN BEFORE lines  (B2_TRACE_PC_START/END window)
# JIT stream:    JITPCHIT lines         (B2_JIT_TRACE_PCS ranges)
#
# Usage: ./lockstep.sh [anchor_hex] [win_start_hex] [win_end_hex] [limit] [timeout_s]
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/../BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
MASTER_DISK="/workspace/fixtures/basilisk/images/HD200MB"

ANCHOR="${1:-0x04004b78}"
WIN_START="${2:-0x04004000}"
WIN_END="${3:-0x040bf000}"
LIMIT="${4:-3000}"
TIMEOUT="${5:-90}"

OUT="/workspace/basilisk-jit-runs"
mkdir -p "$OUT"
IT="$OUT/interp.trace"
JT="$OUT/jit.trace"

source /workspace/scripts/lib/cow-disk.sh

DISPLAY_NUM=":22"
if ! xdpyinfo -display "$DISPLAY_NUM" >/dev/null 2>&1; then
  Xvfb "$DISPLAY_NUM" -screen 0 800x600x24 &>/dev/null &
  sleep 1
fi

run_engine() {
  local mode="$1" outfile="$2"; shift 2
  local sess="/workspace/tmp/lk_${mode}_$$"
  mkdir -p "$sess/home" "$sess/xdg"
  local disk
  disk="$(cow_clone "$MASTER_DISK" "$sess/HD200MB" "lk-$mode")"
  cat > "$sess/prefs" <<EOF
rom $ROM
disk $disk
ramsize 67108864
modelid 14
cpu 4
fpu true
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui false
ignoresegv true
jit $( [ "$mode" = jit ] && echo true || echo false )
jitfpu false
jitcachesize 131072
EOF
  echo "[lockstep] $mode: disk=$disk -> $outfile" >&2
  SDL_VIDEODRIVER=x11 DISPLAY="$DISPLAY_NUM" \
    HOME="$sess/home" XDG_CONFIG_HOME="$sess/xdg" \
    B2_TRACE_ANCHOR_PC="$ANCHOR" \
    "$@" \
    timeout -s KILL "$TIMEOUT" "$BIN" --config "$sess/prefs" 2>"$outfile" >/dev/null
  cow_release "$disk"
  rm -rf "$sess"
}

echo "[lockstep] anchor=$ANCHOR window=$WIN_START..$WIN_END limit=$LIMIT timeout=${TIMEOUT}s"

run_engine nojit "$IT" \
  env B2_TRACE_PC_START="$WIN_START" B2_TRACE_PC_END="$WIN_END" B2_TRACE_LIMIT="$LIMIT"

run_engine jit "$JT" \
  env B2_JIT_TRACE_PCS="${WIN_START}-${WIN_END}" B2_JIT_TRACE_LIMIT="$LIMIT"

# Extract ordered (pc op) streams.
grep '^TRACEWIN BEFORE' "$IT" | sed -E 's/.* pc=([0-9a-f]+) op=([0-9a-f]+).*/\1 \2/' > "$OUT/i.seq"
grep '^JITPCHIT'        "$JT" | sed -E 's/.* pc=([0-9a-f]+) op=([0-9a-f]+).*/\1 \2/' > "$OUT/j.seq"

ic=$(wc -l < "$OUT/i.seq"); jc=$(wc -l < "$OUT/j.seq")
echo "[lockstep] interp steps=$ic  jit steps=$jc"
echo "[lockstep] first divergence (line N => branch at step N-1):"
diff <(nl -ba "$OUT/i.seq") <(nl -ba "$OUT/j.seq") | head -40
