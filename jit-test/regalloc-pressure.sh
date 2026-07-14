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
MOVEM_INIT="01010101 02020202 03030303 04040404 05050505 06060606 07070707 08080808 11111111 12121212 13131313 14141414 15151515 00003400 17171717 007ef000 2700"
declare -a CELLS=(mulu_w_d16_a0_live_a0 roxrw_mem_x_live_all mullu64_mem_source_locked_dl movem_predec_cursor_base_locked negx_b_source_dst_collision negx_w_source_dst_collision negx_l_source_dst_collision tas_b_ea_value_collision move_b_mem_source_dst_collision scc_b_ea_value_collision dbcc_w_counter_copy_collision)
if [[ -n "${B2_REGPRESSURE_CELLS:-}" ]]; then
  read -r -a CELLS <<<"${B2_REGPRESSURE_CELLS//,/ }"
fi
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
  # Every non-SP architectural register is live. Force the private cursor v22
  # toward its A5 base v13 while mov_l_rr copies the original base; the source
  # lock must reject that collision before predecrement transfer begins.
  [movem_predec_cursor_base_locked]="48E5 FFFE 4CDD 7FFF 2C7C A6AA 55CF"
  # TST first materialises D0 in a host register. Force NEGX's zero-valued S1
  # destination scratch toward that still-live source mapping; each shared
  # sbb_b/w/l MIDFUNC must pin the original source while acquiring its RMW dst.
  [negx_b_source_dst_collision]="4A00 4000 40C2 2C7C A6AA 55D0"
  [negx_w_source_dst_collision]="4A40 4040 40C2 2C7C A6AA 55D1"
  [negx_l_source_dst_collision]="4A80 4080 40C2 2C7C A6AA 55D2"
  # Force TAS.B (A0)'s S1 byte-value destination toward A0's host register
  # while readbyte still owns the live EA; the allocator must reject the alias
  # before the RMW and store.
  [tas_b_ea_value_collision]="4AD0 40C2 1010 2C7C A6AA 55D3"
  # MOVE.B (A1),D0 keeps its fetched S1 value live while flag generation first
  # performs a low-lane RMW of D0. Force D0 toward that S1 host mapping: a
  # complete MOVE ownership contract must reject the collision before zero/OR
  # lowering can clobber src or D0's preserved upper lane.
  [move_b_mem_source_dst_collision]="1011 40C2 1239 0000 1000 2C7C A6AA 55D4"
  # SHI.B (A0)+ computes its S2 result after the private S1 effective address
  # and architectural A0 writeback are live. Force S2 toward S1's host mapping:
  # Scc must normalize carry, preserve CCR, and own the preincrement EA through
  # the ordered byte store.
  [scc_b_ea_value_collision]="52D8 40C2 1028 FFFF 2C7C A6AA 55D5"
  # DBHI with C=0,Z=0 must leave D0 untouched and fall through. Force its
  # private pre-decrement copy S2 toward D0 while mov_l_rr owns the source; the
  # copy allocation must be rejected without disturbing condition/counter state.
  [dbcc_w_counter_copy_collision]="52C8 0002 7207 7408 2C7C A6AA 55D6"
)
declare -A CELL_MEMORY_BYTES=(
  [tas_b_ea_value_collision]="A000 00"
  [scc_b_ea_value_collision]="A000 00"
)
declare -A CELL_INIT=(
  [mulu_w_d16_a0_live_a0]="$INIT"
  [roxrw_mem_x_live_all]="$INIT"
  [mullu64_mem_source_locked_dl]="$INIT"
  [movem_predec_cursor_base_locked]="$MOVEM_INIT"
  [negx_b_source_dst_collision]="A5A50080 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [negx_w_source_dst_collision]="A5A58000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [negx_l_source_dst_collision]="80000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [tas_b_ea_value_collision]="A5A50000 11111111 00000000 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [move_b_mem_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00001000 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [scc_b_ea_value_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
  [dbcc_w_counter_copy_collision]="A5A50002 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
)
declare -A CELL_PC=(
  [mulu_w_d16_a0_live_a0]=0x00001018
  [roxrw_mem_x_live_all]=0x0000100a
  [mullu64_mem_source_locked_dl]=0x00001012
  [movem_predec_cursor_base_locked]=0x00001000
  [negx_b_source_dst_collision]=0x00001000
  [negx_w_source_dst_collision]=0x00001000
  [negx_l_source_dst_collision]=0x00001000
  [tas_b_ea_value_collision]=0x00001000
  [move_b_mem_source_dst_collision]=0x00001000
  [scc_b_ea_value_collision]=0x00001000
  [dbcc_w_counter_copy_collision]=0x00001000
)
declare -A CELL_ALIAS_VREG=(
  [mulu_w_d16_a0_live_a0]=8
  [roxrw_mem_x_live_all]=8
  [mullu64_mem_source_locked_dl]=0
  [movem_predec_cursor_base_locked]=13
  [negx_b_source_dst_collision]=0
  [negx_w_source_dst_collision]=0
  [negx_l_source_dst_collision]=0
  [tas_b_ea_value_collision]=8
  [move_b_mem_source_dst_collision]=20
  [scc_b_ea_value_collision]=20
  [dbcc_w_counter_copy_collision]=0
)
declare -A CELL_SCRATCH_VREG=(
  [mulu_w_d16_a0_live_a0]=22
  [roxrw_mem_x_live_all]=21
  [mullu64_mem_source_locked_dl]=20
  [movem_predec_cursor_base_locked]=22
  [negx_b_source_dst_collision]=20
  [negx_w_source_dst_collision]=20
  [negx_l_source_dst_collision]=20
  [tas_b_ea_value_collision]=20
  [move_b_mem_source_dst_collision]=0
  [scc_b_ea_value_collision]=21
  [dbcc_w_counter_copy_collision]=21
)
declare -A CELL_REQUIRE_PIN=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=1
  [mullu64_mem_source_locked_dl]=0
  [movem_predec_cursor_base_locked]=1
  [negx_b_source_dst_collision]=0
  [negx_w_source_dst_collision]=0
  [negx_l_source_dst_collision]=0
  [tas_b_ea_value_collision]=0
  [move_b_mem_source_dst_collision]=0
  [scc_b_ea_value_collision]=0
  [dbcc_w_counter_copy_collision]=0
)
declare -A CELL_REQUIRE_SKIP=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=0
  [mullu64_mem_source_locked_dl]=1
  [movem_predec_cursor_base_locked]=1
  [negx_b_source_dst_collision]=1
  [negx_w_source_dst_collision]=1
  [negx_l_source_dst_collision]=1
  [tas_b_ea_value_collision]=1
  [move_b_mem_source_dst_collision]=1
  [scc_b_ea_value_collision]=1
  [dbcc_w_counter_copy_collision]=1
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
    B2_TEST_HEX="${CELL_HEX[$cell]}" B2_TEST_DUMP=1 B2_TEST_INIT="${CELL_INIT[$cell]}" \
    B2_TEST_MEMORY_BYTES="${CELL_MEMORY_BYTES[$cell]:-}" "${extra[@]}" \
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
