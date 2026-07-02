#!/bin/bash
# OPTLEV bisect (@previous shared-L1-opt-bug check): boot at MAX_OPTLEV 0/1/2,
# capture furthest video/desktop progress marker. arg1=optlev arg2=secs
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
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" env $OPTENV \
  "$BIN" --config "$OUT/prefs" > "$OUT/emu.log" 2>&1 &
EMU=$!; sleep "$SECS"
# screenshot to detect desktop
command -v import >/dev/null 2>&1 && DISPLAY="$DNUM" import -window root "$OUT/shot.png" 2>/dev/null
kill -9 "$EMU" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
echo "=== OPTLEV=$LV progress markers (tail) ==="
grep -iE 'SetEntries|VideoDriverControl|VideoDriverOpen|Finder|desktop|slot' "$OUT/emu.log" | tail -8
echo "=== last 5 log lines ==="; tail -5 "$OUT/emu.log"
[ -f "$OUT/shot.png" ] && cp "$OUT/shot.png" "/workspace/tmp/optlev-$LV-shot.png" && echo "shot: /workspace/tmp/optlev-$LV-shot.png"
rm -rf "$OUT"
