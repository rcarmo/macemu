#!/bin/bash
# cont90g: gdb HW-watchpoint to name the writer of the upstream color-table 0x24 seed.
# The 8-byte-record table 0x116ed-0x138fd has field +5 systematically 0x24(L2) vs 0x00(L1),
# present BEFORE the 0403bf00 generator. Watch the seed byte, log every write with value +
# guest PC, to name the producing routine. Usage: wp-colortable.sh <tag> <wp_guest_hex> <optenv> <secs>
set -u
TAG="${1:-ct}"
WPGUEST="${2:-0x000116ed}"
OPTENV="${3:-}"
SECS="${4:-120}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM"
BASE_DISK="/workspace/fixtures/basilisk/images/HD200MB"
OUT="/workspace/tmp/wpct-$TAG"
rm -rf "$OUT"; mkdir -p "$OUT/home"
DISK="$OUT/disk.img"; cp --reflink=auto "$BASE_DISK" "$DISK"
DNUM=":38"
pkill -f "Xvfb $DNUM" 2>/dev/null || true; rm -f /tmp/.X38-lock /tmp/.X11-unix/X38 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XVFB_PID=$!; sleep 1
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $DISK
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
EOF
cat > "$OUT/gdb.cmds" <<EOF
set pagination off
set confirm off
handle SIGSEGV nostop noprint pass
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIGBUS nostop noprint pass
$(for s in $(seq 32 64); do echo "handle SIG$s nostop noprint pass"; done)
break compile_block
run --config $OUT/prefs
delete
set \$wp = (unsigned char *)((char*)MEMBaseDiff + $WPGUEST)
printf "WP armed host %p (MEMBaseDiff=%p guest=$WPGUEST)\n", \$wp, MEMBaseDiff
set \$n = 0
watch *\$wp
commands
silent
set \$n = \$n + 1
if \$n <= 24
printf "CTWRITE#%d val=%02x guestpc=%08x d0=%08x d1=%08x d2=%08x a0=%08x a1=%08x a2=%08x\n", (int)\$n, *\$wp, regs.pc, regs.regs[0], regs.regs[1], regs.regs[2], regs.regs[8], regs.regs[9], regs.regs[10]
end
if \$n >= 24
detach
kill
quit
end
cont
end
cont
EOF
echo "[ct:$TAG] gdb HW-watchpoint on guest $WPGUEST optenv='$OPTENV' (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  env $OPTENV timeout -s KILL "$SECS" gdb -batch -x "$OUT/gdb.cmds" "$BIN" > "$OUT/gdb.log" 2>&1
echo "[ct:$TAG] CTWRITE hits:"
grep -E 'CTWRITE|WP armed' "$OUT/gdb.log" | head -30
pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null || true
kill -9 "$XVFB_PID" 2>/dev/null || true
