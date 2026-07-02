#!/bin/bash
# cont90m: HW-watchpoint on guest 0x184 (04002304: clrw 0x184, immediately before
# 04002308 RTS). Captures return target [a7] plus loop state d1/a0 in JIT or interp.
# Usage: wp-rts2308.sh <L2|L0> [secs] [nhits]
set -u
LEVEL="${1:-L2}"; SECS="${2:-130}"; NHITS="${3:-80}"
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
OUT=/workspace/tmp/wp2308_${LEVEL}; rm -rf "$OUT"; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":3${RANDOM:0:1}"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X3*-lock /tmp/.X11-unix/X3* 2>/dev/null
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
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIGBUS nostop noprint pass
$(for s in $(seq 32 64); do echo "handle SIG$s nostop noprint pass"; done)
break m68k_do_execute
run --config $OUT/prefs
delete
set \$wp = (unsigned short *)((char*)MEMBaseDiff + 0x184)
printf "WP2308 armed host %p MEMBaseDiff=%p mode=$LEVEL\n", \$wp, MEMBaseDiff
set \$n = 0
watch *\$wp
commands
silent
if (unsigned)regs.pc == 0x04002304 || (unsigned)regs.pc == 0x04002308 || (unsigned)regs.pc == 0x0400230a
set \$n = \$n + 1
printf "RTS2308#%d pc=%08x a7=%08x retLE=%08x nxtLE=%08x d0=%08x d1=%08x d2=%08x d3=%08x a0=%08x a1=%08x a2=%08x sr=%04x\n", (int)\$n, (unsigned)regs.pc, (unsigned)regs.regs[15], *(unsigned int*)((char*)MEMBaseDiff + (unsigned)regs.regs[15]), *(unsigned int*)((char*)MEMBaseDiff + (unsigned)regs.regs[15] + 4), (unsigned)regs.regs[0], (unsigned)regs.regs[1], (unsigned)regs.regs[2], (unsigned)regs.regs[3], (unsigned)regs.regs[8], (unsigned)regs.regs[9], (unsigned)regs.regs[10], (unsigned)regs.sr
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
echo "[$LEVEL] wp guest 0x184 (04002304 before 04002308 RTS), capture ret+d1+a0 (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  timeout -s KILL "$SECS" gdb -batch -x "$OUT/gdb.cmds" "$BIN" > "$OUT/gdb.log" 2>&1
echo "=== RTS2308 hits ($LEVEL) ==="
grep -E 'WP2308|RTS2308#|Error|Cannot|No symbol' "$OUT/gdb.log" | head -120
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null; kill -9 "$XV" 2>/dev/null
