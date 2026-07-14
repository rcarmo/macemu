#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/BasiliskII/src/Unix/BasiliskII"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_TEST_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
RUN_DIR="${B2_REGPRESSURE_RUN_DIR:-$(mktemp -d /tmp/b2-regpressure-XXXXXX)}"
KEEP="${B2_REGPRESSURE_KEEP:-}"
cleanup(){ [[ -n "$KEEP" ]] && echo "KEEP $RUN_DIR" || rm -rf "$RUN_DIR"; }
trap cleanup EXIT
mkdir -p "$RUN_DIR/home"
cp --reflink=auto "$DISK" "$RUN_DIR/disk.img"
DNUM=":8${RANDOM:0:1}"
rm -f /tmp/.X8*-lock /tmp/.X11-unix/X8* 2>/dev/null || true
Xvfb "$DNUM" -screen 0 640x480x24 >/dev/null 2>&1 & XV=$!
sleep 1
cat >"$RUN_DIR/prefs-jit" <<EOF
rom $ROM
disk $RUN_DIR/disk.img
ramsize 8388608
modelid 14
cpu 4
fpu false
jit true
jitfpu false
jitcachesize 8192
screen win/640/480
nosound true
nocdrom true
nogui true
ignoresegv true
EOF
sed 's/jit true/jit false/' "$RUN_DIR/prefs-jit" >"$RUN_DIR/prefs-int"
HEX="2042 20BC 1122 3344 43F9 0000 2040 337C 0005 0012 3E3C 003F 2042 2244 3005 C0E9 0012 2658 51CF FFF2 2C7C A6AA 55CC"
# Mask asynchronous guest interrupts: this vector proves allocator state, not
# host-timer scheduling, and interpreter/JIT runs otherwise race the first 60 Hz
# tick independently.
INIT="11110003 22220005 00002000 44440009 00002040 00000003 7777000f 0000003f 00002000 00002040 bbbb4000 cccc5000 dddd6000 eeee7000 a6a60000 007ef000 2700"
run_one(){
  local mode="$1"
  local pref="$RUN_DIR/prefs-$mode"
  local log="$RUN_DIR/$mode.log"
  local -a extra=(B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC=0x00001018)
  if [[ "$mode" == jit ]]; then
    extra+=(B2_JIT_FORCE_TRANSLATE=1 B2_TEST_FORCE_L2_RAM=1 B2_NATIVE_ASSERT_PC=0x00001018 B2_INTERPOP_PC=0x00001018)
    extra+=(B2_FORCE_SCRATCH_ALIAS_VREG="${B2_FORCE_SCRATCH_ALIAS_VREG:-8}")
    extra+=(B2_FORCE_SCRATCH_VREG="${B2_FORCE_SCRATCH_VREG:-22}")
  fi
  env SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$RUN_DIR/home" \
    B2_TEST_HEX="$HEX" B2_TEST_DUMP=1 B2_TEST_INIT="$INIT" "${extra[@]}" \
    timeout -k 5s 80s "$BIN" --config "$pref" >"$log" 2>&1 || true
}
run_one int
run_one jit
kill -9 "$XV" 2>/dev/null || true
wait "$XV" 2>/dev/null || true
PIN=$(grep -ac 'REGPRESSURE_PIN_HIT' "$RUN_DIR/jit.log" || true)
NAT=$(grep -ac 'NATEXEC pc=00001018' "$RUN_DIR/jit.log" || true)
INTERP=$(grep -ac 'INTERPOP pc=00001018' "$RUN_DIR/jit.log" || true)
INT_DUMP=$(grep -a '^REGDUMP:' "$RUN_DIR/int.log" | tail -1 || true)
JIT_DUMP=$(grep -a '^REGDUMP:' "$RUN_DIR/jit.log" | tail -1 || true)
STATUS=PASS
[[ "$INT_DUMP" == "$JIT_DUMP" ]] || STATUS=FAIL
printf 'REGPRESSURE cell=mulu_w_d16_a0_live_a0 status=%s pin=%s natexec=%s interpop=%s\n' "$STATUS" "$PIN" "$NAT" "$INTERP"
printf 'INTERP %s\n' "$INT_DUMP"
printf 'JIT    %s\n' "$JIT_DUMP"
[[ "$NAT" -gt 0 ]] || exit 2
if [[ "$STATUS" == FAIL ]]; then exit 1; fi
