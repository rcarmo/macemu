#!/bin/bash
# OPTLEV native-ratio (@auditor accounting): B2_JIT_DIAG dispatch vs exec_normal/
# exec_nostats at each optlev, + final screenshot. arg1=optlev arg2=secs
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
LV="${1:-2}"; SECS="${2:-40}"
OUT=$(mktemp -d); mkdir -p "$OUT/home"; DNUM=":9$((RANDOM%90+10))"
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
cat > "$OUT/prefs" <<PREFS
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit true
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
PREFS
OPTENV=""; [ "$LV" != "2" ] && OPTENV="B2_JIT_MAX_OPTLEV=$LV"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" env $OPTENV B2_JIT_DIAG=1 \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
DISPLAY="$DNUM" import -window root "/workspace/tmp/optlev-$LV-final.png" 2>/dev/null
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
echo "=== OPTLEV=$LV: max_optlev line ==="; grep 'max_optlev=' "$OUT/emu.log" | head -1
echo "=== last JIT_DIAG stats line ==="; grep -E '^JIT_DIAG t=[0-9]+s dispatch=' "$OUT/emu.log" | tail -1
echo "=== screenshot mean ==="; convert "/workspace/tmp/optlev-$LV-final.png" -format '%[mean]' info: 2>/dev/null; echo
rm -rf "$OUT"
