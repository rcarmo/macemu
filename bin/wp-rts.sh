#!/bin/bash
# cont90k: gdb HW-watchpoint on 040b7036 entry (moveb #1,0x8cd) — capture a7 + return
# address [a7] (the RTS target) to (a) confirm the 040b7036->040b9874 edge is a REAL rts
# return (not a re-dispatch artifact), (b) find the scanner-bound caller/pusher.
# Guest mem is big-endian; we dump 8 raw bytes at [a7] and swap in post.
set -u
LEVEL="${1:-L2}"; SECS="${2:-130}"; NHITS="${3:-60}"
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
OUT=/workspace/tmp/wprts_${LEVEL}; rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":39"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X39-lock /tmp/.X11-unix/X39 2>/dev/null
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
JIT=true; [ "$LEVEL" = "L0" ] && JIT=false
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit $JIT
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
cat > "$OUT/gdb.cmds" <<EOF
set pagination off
set confirm off
handle SIGSEGV nostop noprint pass
$(for s in $(seq 32 64); do echo "handle SIG$s nostop noprint pass"; done)
break compile_block
run --config $OUT/prefs
delete
set \$wp = (unsigned char *)((char*)MEMBaseDiff + 0x8cd)
set \$n = 0
watch *\$wp
commands
silent
if *\$wp == 1
set \$n = \$n + 1
printf "RTS#%d pc=%08x a7=%08x retLE=%08x nxtLE=%08x\n", (int)\$n, (unsigned)regs.pc, (unsigned)regs.regs[15], *(unsigned int*)((char*)MEMBaseDiff + (unsigned)regs.regs[15]), *(unsigned int*)((char*)MEMBaseDiff + (unsigned)regs.regs[15] + 4)
end
if \$n >= $NHITS
detach
kill
quit
end
cont
end
cont
EOF
echo "[$LEVEL] wp 0x8cd (040b7036 entry) capturing a7 + [a7] return target (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  timeout -s KILL "$SECS" gdb -batch -x "$OUT/gdb.cmds" "$BIN" > "$OUT/gdb.log" 2>&1
echo "=== RTS return targets (ret = big-endian guest return address) ==="
grep -E 'RTS#' "$OUT/gdb.log" | head -60
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
