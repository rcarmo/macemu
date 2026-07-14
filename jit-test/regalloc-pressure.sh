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
# Mask asynchronous guest interrupts: these vectors prove allocator state, not
# host-timer scheduling, and interpreter/JIT runs otherwise race the first 60 Hz
# tick independently.
INIT="11110003 22220005 00002000 44440009 00002040 00000003 7777000f 0000003f 00002000 00002040 bbbb4000 cccc5000 dddd6000 eeee7000 a6a60000 007ef000 2700"
declare -a CELLS=(mulu_w_d16_a0_live_a0 roxrw_mem_x_live_all mullu64_mem_source_locked_dl)
declare -A CELL_HEX=(
  [mulu_w_d16_a0_live_a0]="2042 20BC 1122 3344 43F9 0000 2040 337C 0005 0012 3E3C 003F 2042 2244 3005 C0E9 0012 2658 51CF FFF2 2C7C A6AA 55CC"
  # Establish X=1 and 0x8000 at (A0), then keep every non-SP source register
  # live through ROXR.W.  MOVE preserves X; the final ADDX consumes the new
  # X=0, distinguishing a correct in-place X write from a stale binding.  DBF
  # makes the pressure block hot enough that exact native execution is required.
  [roxrw_mem_x_live_all]="2042 30BC 8000 44FC 0010 E4D0 2001 2002 2003 2004 2005 2006 2007 2008 2009 200A 200B 200C 200D 200E DD85 51CF FFDE 3010 2C7C A6AA 55CD"
  # Attempt to force the MULL memory-source scratch S1 onto Dl's live host
  # register.  The generator's value lock must block that assignment while the
  # EA is fetched; the 64-bit result is then folded with the remaining live
  # D-registers and A0 before DBF repeats the exact native block.
  [mullu64_mem_source_locked_dl]="203C FFFF FFFF 3E3C 003F 2042 20BC 0000 0002 D082 4C10 0401 D081 D082 D083 D084 D085 D086 D087 D088 51CF FFE8 2C7C A6AA 55CE"
)
declare -A CELL_PC=(
  [mulu_w_d16_a0_live_a0]=0x00001018
  [roxrw_mem_x_live_all]=0x0000100a
  [mullu64_mem_source_locked_dl]=0x00001012
)
declare -A CELL_ALIAS_VREG=(
  [mulu_w_d16_a0_live_a0]=8
  [roxrw_mem_x_live_all]=8
  [mullu64_mem_source_locked_dl]=0
)
declare -A CELL_SCRATCH_VREG=(
  [mulu_w_d16_a0_live_a0]=22
  [roxrw_mem_x_live_all]=21
  [mullu64_mem_source_locked_dl]=20
)
declare -A CELL_REQUIRE_PIN=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=1
  [mullu64_mem_source_locked_dl]=0
)
declare -A CELL_REQUIRE_SKIP=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=0
  [mullu64_mem_source_locked_dl]=1
)
run_one(){
  local cell="$1"
  local mode="$2"
  local pref="$RUN_DIR/prefs-$mode"
  local log="$RUN_DIR/$cell-$mode.log"
  local pc="${CELL_PC[$cell]}"
  local -a extra=(B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC="$pc")
  if [[ "$mode" == jit ]]; then
    extra+=(B2_JIT_FORCE_TRANSLATE=1 B2_TEST_FORCE_L2_RAM=1 B2_NATIVE_ASSERT_PC="$pc" B2_INTERPOP_PC="$pc")
    extra+=(B2_FORCE_SCRATCH_ALIAS_VREG="${B2_FORCE_SCRATCH_ALIAS_VREG:-${CELL_ALIAS_VREG[$cell]}}")
    extra+=(B2_FORCE_SCRATCH_VREG="${B2_FORCE_SCRATCH_VREG:-${CELL_SCRATCH_VREG[$cell]}}")
  fi
  env SDL_VIDEODRIVER=x11 DISPLAY="$DNUM" HOME="$RUN_DIR/home" \
    B2_TEST_HEX="${CELL_HEX[$cell]}" B2_TEST_DUMP=1 B2_TEST_INIT="$INIT" "${extra[@]}" \
    timeout -k 5s 80s "$BIN" --config "$pref" >"$log" 2>&1 || true
}
RESULT=0
for cell in "${CELLS[@]}"; do
  run_one "$cell" int
  run_one "$cell" jit
  pc_hex="${CELL_PC[$cell]#0x0000}"
  PIN=$(grep -ac 'REGPRESSURE_PIN_HIT' "$RUN_DIR/$cell-jit.log" || true)
  SKIP=$(grep -ac 'REGPRESSURE_PIN_SKIP' "$RUN_DIR/$cell-jit.log" || true)
  NAT=$(grep -aci "NATEXEC pc=0000${pc_hex}" "$RUN_DIR/$cell-jit.log" || true)
  INTERP=$(grep -aci "INTERPOP pc=0000${pc_hex}" "$RUN_DIR/$cell-jit.log" || true)
  INT_DUMP=$(grep -a '^REGDUMP:' "$RUN_DIR/$cell-int.log" | tail -1 || true)
  JIT_DUMP=$(grep -a '^REGDUMP:' "$RUN_DIR/$cell-jit.log" | tail -1 || true)
  STATUS=PASS
  [[ -n "$INT_DUMP" && "$INT_DUMP" == "$JIT_DUMP" ]] || STATUS=FAIL
  printf 'REGPRESSURE cell=%s status=%s pin=%s skip=%s natexec=%s interpop=%s\n' "$cell" "$STATUS" "$PIN" "$SKIP" "$NAT" "$INTERP"
  printf 'INTERP %s\n' "$INT_DUMP"
  printf 'JIT    %s\n' "$JIT_DUMP"
  [[ "$NAT" -gt 0 ]] || RESULT=2
  [[ "${CELL_REQUIRE_PIN[$cell]}" == 0 || "$PIN" -gt 0 ]] || RESULT=3
  [[ "${CELL_REQUIRE_SKIP[$cell]}" == 0 || "$SKIP" -gt 0 ]] || RESULT=4
  [[ "$STATUS" == PASS ]] || RESULT=1
done
kill -9 "$XV" 2>/dev/null || true
wait "$XV" 2>/dev/null || true
exit "$RESULT"
