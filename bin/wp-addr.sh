#!/bin/bash
# CONT.110 cont78: HW watchpoint on an arbitrary guest low-mem address (host=addr+MEMBaseDiff)
# to catch its writer + guest PC in each mode. Usage: wp-addr.sh <jit true|false> <secs> <addr>
set -u
BIN=/workspace/projects/macemu/BasiliskII/src/Unix/BasiliskII
ROM=/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM
JITMODE="${1:-true}"; SECS="${2:-100}"; ADDR="${3:-0x904}"
OUT=/workspace/tmp/wpaddr; sudo rm -rf "$OUT" 2>/dev/null; rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT/home"
cp --reflink=auto /workspace/fixtures/basilisk/images/HD200MB "$OUT/disk.img"
DNUM=":42"; pkill -f "Xvfb $DNUM" 2>/dev/null; rm -f /tmp/.X42-lock /tmp/.X11-unix/X42 2>/dev/null
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!; sleep 1
cat > "$OUT/prefs" <<EOF
rom $ROM
disk $OUT/disk.img
ramsize 67108864
modelid 14
cpu 4
fpu true
jit $JITMODE
jitfpu false
jitcachesize 131072
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
cat > "$OUT/gdbcmds" <<GDB
set pagination off
set print address off
set breakpoint pending on
handle SIGSEGV nostop noprint pass
handle SIGUSR1 SIGUSR2 SIGPWR nostop noprint pass
handle SIG32 SIG33 SIG34 SIG35 SIG36 SIG37 SIG38 SIG39 SIG40 nostop noprint pass
handle SIG41 SIG42 SIG43 SIG44 SIG45 SIG46 SIG47 SIG48 SIG49 SIG50 nostop noprint pass
handle SIG51 SIG52 SIG53 SIG54 SIG55 SIG56 SIG57 SIG58 SIG59 SIG60 SIG61 SIG62 SIG63 SIG64 nostop noprint pass
tbreak execute_normal
tbreak m68k_do_execute
run
delete
set \$h = (char*)MEMBaseDiff + $ADDR
printf "WPADDR armed at guest $ADDR host %p\n", \$h
watch *(unsigned int*)\$h
commands
  silent
  printf "WPADDR $ADDR write -> %02x%02x%02x%02x  guest_pc=%08x\n", *(unsigned char*)\$h, *((unsigned char*)\$h+1), *((unsigned char*)\$h+2), *((unsigned char*)\$h+3), (unsigned)regs.pc
  continue
end
continue
GDB
echo "[wpaddr jit=$JITMODE addr=$ADDR] starting (${SECS}s)"
SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$OUT/home" \
  timeout "$SECS" sudo -E gdb -batch -x "$OUT/gdbcmds" --args "$BIN" --config "$OUT/prefs" > "$OUT/gdb.log" 2>&1
kill -9 "$XV" 2>/dev/null; pkill -9 -f "BasiliskII --config $OUT/prefs" 2>/dev/null
echo "=== WPADDR writes ($ADDR) ==="; grep 'WPADDR' "$OUT/gdb.log" | head -20
echo "=== furthest guest PC (wall check) ==="; grep -oE 'pc=0x[0-9a-f]+|040ba0|040b98' "$OUT/gdb.log" | tail -3
