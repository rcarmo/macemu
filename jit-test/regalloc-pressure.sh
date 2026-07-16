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
declare -a CELLS=(mulu_w_d16_a0_live_a0 roxrw_mem_x_live_all mullu64_mem_source_locked_dl movem_predec_cursor_base_locked negx_b_source_dst_collision negx_w_source_dst_collision negx_l_source_dst_collision neg_b_postinc_result_ea_collision negx_b_postinc_result_ea_collision tas_b_ea_value_collision clr_b_postinc_zero_ea_collision exg_l_tmp_source_collision ext_w_scratch_source_collision move_b_mem_source_dst_collision scc_b_ea_value_collision dbcc_w_counter_copy_collision bitop_b_ea_value_collision cmpm_b_source_dst_collision cmpa_w_postinc_source_dst_collision adda_w_postinc_source_dst_collision adda_l_postinc_source_dst_collision add_b_postinc_source_dreg_collision add_b_postinc_x_ea_collision and_b_postinc_source_dreg_collision and_b_postinc_ea_source_collision eor_b_postinc_source_dest_collision eor_b_postinc_ea_dest_collision or_b_postinc_source_dreg_collision or_b_postinc_ea_source_collision sub_b_postinc_source_dreg_collision sub_b_postinc_x_ea_collision)
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
  # NEG/NEGX.B (A0)+ retain the private S1 preincrement EA across their S3
  # result allocation, CCR publication, and final store. Force S3 toward S1;
  # explicit generator ownership must reject both collisions.
  [neg_b_postinc_result_ea_collision]="4418 40C2 1028 FFFF 2C7C A6AA 55DA"
  [negx_b_postinc_result_ea_collision]="4018 40C2 1028 FFFF 2C7C A6AA 55DB"
  # Force TAS.B (A0)'s S1 byte-value destination toward A0's host register
  # while readbyte still owns the live EA; the allocator must reject the alias
  # before the RMW and store.
  [tas_b_ea_value_collision]="4AD0 40C2 1010 2C7C A6AA 55D3"
  # CLR.B (A0)+ retains private S1 as its pre-write EA while S2 receives zero.
  # Force S2 toward S1: the generator must own the original EA through the
  # write, then materialise CLR's fixed flags only after storage.
  [clr_b_postinc_zero_ea_collision]="4218 40C2 1028 FFFF 2C7C A6AA 55E7"
  # EXG D0,D1 copies D0 into private S1 before overwriting D0 with D1. Force
  # S1 toward D0's host mapping: mov_l_rr must keep the copied original live
  # until the second architectural write completes the simultaneous exchange.
  [exg_l_tmp_source_collision]="C141 40C2 2C7C A6AA 55E8"
  # EXT.W D0 allocates private S1 for the sign-extended low byte before writing
  # D0.W. Force S1 toward D0's live host mapping; sign_extend_8_rr must retain
  # the source until the widened word is complete.
  [ext_w_scratch_source_collision]="4880 40C2 2C7C A6AA 55E9"
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
  # BSET D0,(A0)+ keeps the private S1 preincrement EA live after loading its
  # S2 byte. Force the S2 RMW destination toward S1: the generator must own
  # that EA through original-bit Z publication and the ordered byte store.
  [bitop_b_ea_value_collision]="01D8 40C2 1028 FFFF 2C7C A6AA 55D7"
  # CMPM.B (A0)+,(A1)+ keeps the first fetched byte (S2) live while the
  # second read acquires S4. Force S4 toward S2 to prove that the generator
  # owns the first operand across the second EA/read and flag publication.
  [cmpm_b_source_dst_collision]="B308 40C2 2C7C A6AA 55D8"
  # CMPA.W (A0)+,A0 fetches S2, updates A0, then copies that updated
  # destination into S3 before widening the source. Force S3 toward S2; the
  # fetched word must remain owned until the shared long compare consumes it.
  [cmpa_w_postinc_source_dst_collision]="B0D8 40C2 2C7C A6AA 55D9"
  # ADDA.W/L (A0)+,A0 fetch S2 and commit the architectural postincrement
  # before INIT_REGS acquires A0 as the arithmetic destination. Force A0 toward
  # the still-live S2 mapping; both widths must reject the collision and add the
  # fetched source to the already-updated address register.
  [adda_w_postinc_source_dst_collision]="D0D8 40C2 2C7C A6AA 55E5"
  [adda_l_postinc_source_dst_collision]="D1D8 40C2 2C7C A6AA 55E6"
  # ADD.B (A0)+,D0 fetches a private S1 source before acquiring architectural
  # destination D0. Force D0 toward S1: the source must remain owned until the
  # arithmetic consumes it, rather than becoming the destination allocation.
  [add_b_postinc_source_dreg_collision]="D018 40C2 2C7C A6AA 55DB"
  # ADD.B D0,(A0)+ retains private S1 as its pre-write EA while flag-live
  # lowering publishes X through FLAGX. Force FLAGX toward S1: the ADD
  # lifecycle must own the EA through carry duplication and the ordered store.
  [add_b_postinc_x_ea_collision]="D118 40C2 1028 FFFF 2C7C A6AA 55DC"
  # AND.B (A0)+,D0 uses the same source-first MIDFUNC acquisition contract as
  # ADD. Force D0 toward the fetched S2 value to prove the source stays owned.
  [and_b_postinc_source_dreg_collision]="C018 40C2 2C7C A6AA 55DD"
  # AND.B D6,(A0)+ retains private S1 as its pre-write EA while fetched value
  # S2 is promoted to an RMW destination and the logical result/flags are
  # emitted. Force S2 toward S1: the shared logical generator must own the
  # original EA through the final store.
  [and_b_postinc_ea_source_collision]="CD18 40C2 1028 FFFF 2C7C A6AA 55DE"
  # EOR.B D6,(A0)+ promotes fetched S2 to the writable destination while D6
  # remains a live source. Force S2 toward D6: INIT_REGS_b must own the source
  # before the low-byte RMW destination is acquired.
  [eor_b_postinc_source_dest_collision]="BD18 40C2 1028 FFFF 2C7C A6AA 55DF"
  # The same EOR route retains private S1 as its pre-write EA while S2 becomes
  # the RMW destination. Force S2 toward S1: generator ownership must preserve
  # the original address through flags and the ordered store.
  [eor_b_postinc_ea_dest_collision]="BD18 40C2 1028 FFFF 2C7C A6AA 55E0"
  # OR.B (A0)+,D0 fetches private S1 before acquiring architectural D0. Force
  # D0 toward S1: source-first ownership must retain the byte through OR.
  [or_b_postinc_source_dreg_collision]="8018 40C2 2C7C A6AA 55E1"
  # OR.B D6,(A0)+ retains private S1 as the pre-write EA while fetched S2 is
  # promoted to the RMW destination. Force S2 toward S1 through the final store.
  [or_b_postinc_ea_source_collision]="8D18 40C2 1028 FFFF 2C7C A6AA 55E2"
  # SUB.B (A0)+,D0 fetches a private S1 source before acquiring architectural
  # destination D0. Force D0 toward S1 to prove source-before-RMW ownership.
  [sub_b_postinc_source_dreg_collision]="9018 40C2 2C7C A6AA 55E3"
  # SUB.B D0,(A0)+ retains private S1 as its pre-write EA while flag-live
  # lowering publishes X through FLAGX. Force FLAGX toward S1 through storage.
  [sub_b_postinc_x_ea_collision]="9118 40C2 1028 FFFF 2C7C A6AA 55E4"
)
declare -A CELL_MEMORY_BYTES=(
  [neg_b_postinc_result_ea_collision]="A000 01"
  [negx_b_postinc_result_ea_collision]="A000 01"
  [tas_b_ea_value_collision]="A000 00"
  [clr_b_postinc_zero_ea_collision]="A000 FF"
  [scc_b_ea_value_collision]="A000 00"
  [bitop_b_ea_value_collision]="A000 00"
  [cmpm_b_source_dst_collision]="A000 01 A100 02"
  [cmpa_w_postinc_source_dst_collision]="A000 00 A001 01"
  [adda_w_postinc_source_dst_collision]="A000 00 A001 01"
  [adda_l_postinc_source_dst_collision]="A000 00 A001 00 A002 00 A003 01"
  [add_b_postinc_source_dreg_collision]="A000 01"
  [add_b_postinc_x_ea_collision]="A000 FF"
  [and_b_postinc_source_dreg_collision]="A000 0F"
  [and_b_postinc_ea_source_collision]="A000 FF"
  [eor_b_postinc_source_dest_collision]="A000 FF"
  [eor_b_postinc_ea_dest_collision]="A000 FF"
  [or_b_postinc_source_dreg_collision]="A000 0F"
  [or_b_postinc_ea_source_collision]="A000 F0"
  [sub_b_postinc_source_dreg_collision]="A000 01"
  [sub_b_postinc_x_ea_collision]="A000 00"
)
declare -A CELL_INIT=(
  [mulu_w_d16_a0_live_a0]="$INIT"
  [roxrw_mem_x_live_all]="$INIT"
  [mullu64_mem_source_locked_dl]="$INIT"
  [movem_predec_cursor_base_locked]="$MOVEM_INIT"
  [negx_b_source_dst_collision]="A5A50080 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [negx_w_source_dst_collision]="A5A58000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [negx_l_source_dst_collision]="80000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2704"
  [neg_b_postinc_result_ea_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [negx_b_postinc_result_ea_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [tas_b_ea_value_collision]="A5A50000 11111111 00000000 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [clr_b_postinc_zero_ea_collision]="A5A500FF 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [exg_l_tmp_source_collision]="11223344 AABBCCDD 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [ext_w_scratch_source_collision]="A5A50080 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [move_b_mem_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00001000 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [scc_b_ea_value_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
  [dbcc_w_counter_copy_collision]="A5A50002 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
  [bitop_b_ea_value_collision]="00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [cmpm_b_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 0000A100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [cmpa_w_postinc_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 0000A100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [adda_w_postinc_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [adda_l_postinc_source_dst_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [add_b_postinc_source_dreg_collision]="A5A5007F 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
  [add_b_postinc_x_ea_collision]="A5A50001 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 2700"
  [and_b_postinc_source_dreg_collision]="A5A500F0 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [and_b_postinc_ea_source_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 0000000F 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [eor_b_postinc_source_dest_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 0000000F 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [eor_b_postinc_ea_dest_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 0000000F 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [or_b_postinc_source_dreg_collision]="A5A500F0 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [or_b_postinc_ea_source_collision]="A5A50000 11111111 22222222 33333333 44444444 55555555 0000000F 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [sub_b_postinc_source_dreg_collision]="A5A50080 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
  [sub_b_postinc_x_ea_collision]="A5A50001 11111111 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 00002100 00002200 00002300 00002400 00002500 00002600 007ef000 271F"
)
declare -A CELL_PC=(
  [mulu_w_d16_a0_live_a0]=0x00001018
  [roxrw_mem_x_live_all]=0x0000100a
  [mullu64_mem_source_locked_dl]=0x00001012
  [movem_predec_cursor_base_locked]=0x00001000
  [negx_b_source_dst_collision]=0x00001000
  [negx_w_source_dst_collision]=0x00001000
  [negx_l_source_dst_collision]=0x00001000
  [neg_b_postinc_result_ea_collision]=0x00001000
  [negx_b_postinc_result_ea_collision]=0x00001000
  [tas_b_ea_value_collision]=0x00001000
  [clr_b_postinc_zero_ea_collision]=0x00001000
  [exg_l_tmp_source_collision]=0x00001000
  [ext_w_scratch_source_collision]=0x00001000
  [move_b_mem_source_dst_collision]=0x00001000
  [scc_b_ea_value_collision]=0x00001000
  [dbcc_w_counter_copy_collision]=0x00001000
  [bitop_b_ea_value_collision]=0x00001000
  [cmpm_b_source_dst_collision]=0x00001000
  [cmpa_w_postinc_source_dst_collision]=0x00001000
  [adda_w_postinc_source_dst_collision]=0x00001000
  [adda_l_postinc_source_dst_collision]=0x00001000
  [add_b_postinc_source_dreg_collision]=0x00001000
  [add_b_postinc_x_ea_collision]=0x00001000
  [and_b_postinc_source_dreg_collision]=0x00001000
  [and_b_postinc_ea_source_collision]=0x00001000
  [eor_b_postinc_source_dest_collision]=0x00001000
  [eor_b_postinc_ea_dest_collision]=0x00001000
  [or_b_postinc_source_dreg_collision]=0x00001000
  [or_b_postinc_ea_source_collision]=0x00001000
  [sub_b_postinc_source_dreg_collision]=0x00001000
  [sub_b_postinc_x_ea_collision]=0x00001000
)
declare -A CELL_ALIAS_VREG=(
  [mulu_w_d16_a0_live_a0]=8
  [roxrw_mem_x_live_all]=8
  [mullu64_mem_source_locked_dl]=0
  [movem_predec_cursor_base_locked]=13
  [negx_b_source_dst_collision]=0
  [negx_w_source_dst_collision]=0
  [negx_l_source_dst_collision]=0
  [neg_b_postinc_result_ea_collision]=20
  [negx_b_postinc_result_ea_collision]=20
  [tas_b_ea_value_collision]=8
  [clr_b_postinc_zero_ea_collision]=20
  [exg_l_tmp_source_collision]=0
  [ext_w_scratch_source_collision]=0
  [move_b_mem_source_dst_collision]=20
  [scc_b_ea_value_collision]=20
  [dbcc_w_counter_copy_collision]=0
  [bitop_b_ea_value_collision]=20
  [cmpm_b_source_dst_collision]=21
  [cmpa_w_postinc_source_dst_collision]=21
  [adda_w_postinc_source_dst_collision]=21
  [adda_l_postinc_source_dst_collision]=21
  [add_b_postinc_source_dreg_collision]=21
  [add_b_postinc_x_ea_collision]=20
  [and_b_postinc_source_dreg_collision]=21
  [and_b_postinc_ea_source_collision]=20
  [eor_b_postinc_source_dest_collision]=6
  [eor_b_postinc_ea_dest_collision]=20
  [or_b_postinc_source_dreg_collision]=21
  [or_b_postinc_ea_source_collision]=20
  [sub_b_postinc_source_dreg_collision]=21
  [sub_b_postinc_x_ea_collision]=20
)
declare -A CELL_SCRATCH_VREG=(
  [mulu_w_d16_a0_live_a0]=22
  [roxrw_mem_x_live_all]=21
  [mullu64_mem_source_locked_dl]=20
  [movem_predec_cursor_base_locked]=22
  [negx_b_source_dst_collision]=20
  [negx_w_source_dst_collision]=20
  [negx_l_source_dst_collision]=20
  [neg_b_postinc_result_ea_collision]=22
  [negx_b_postinc_result_ea_collision]=22
  [tas_b_ea_value_collision]=20
  [clr_b_postinc_zero_ea_collision]=21
  [exg_l_tmp_source_collision]=20
  [ext_w_scratch_source_collision]=20
  [move_b_mem_source_dst_collision]=0
  [scc_b_ea_value_collision]=21
  [dbcc_w_counter_copy_collision]=21
  [bitop_b_ea_value_collision]=21
  [cmpm_b_source_dst_collision]=23
  [cmpa_w_postinc_source_dst_collision]=22
  [adda_w_postinc_source_dst_collision]=8
  [adda_l_postinc_source_dst_collision]=8
  [add_b_postinc_source_dreg_collision]=0
  [add_b_postinc_x_ea_collision]=17
  [and_b_postinc_source_dreg_collision]=0
  [and_b_postinc_ea_source_collision]=21
  [eor_b_postinc_source_dest_collision]=21
  [eor_b_postinc_ea_dest_collision]=21
  [or_b_postinc_source_dreg_collision]=0
  [or_b_postinc_ea_source_collision]=21
  [sub_b_postinc_source_dreg_collision]=0
  [sub_b_postinc_x_ea_collision]=17
)
declare -A CELL_REQUIRE_PIN=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=1
  [mullu64_mem_source_locked_dl]=0
  [movem_predec_cursor_base_locked]=1
  [negx_b_source_dst_collision]=0
  [negx_w_source_dst_collision]=0
  [negx_l_source_dst_collision]=0
  [neg_b_postinc_result_ea_collision]=0
  [negx_b_postinc_result_ea_collision]=0
  [tas_b_ea_value_collision]=0
  [clr_b_postinc_zero_ea_collision]=0
  [exg_l_tmp_source_collision]=0
  [ext_w_scratch_source_collision]=0
  [move_b_mem_source_dst_collision]=0
  [scc_b_ea_value_collision]=0
  [dbcc_w_counter_copy_collision]=0
  [bitop_b_ea_value_collision]=0
  [cmpm_b_source_dst_collision]=0
  [cmpa_w_postinc_source_dst_collision]=0
  [adda_w_postinc_source_dst_collision]=0
  [adda_l_postinc_source_dst_collision]=0
  [add_b_postinc_source_dreg_collision]=0
  [add_b_postinc_x_ea_collision]=0
  [and_b_postinc_source_dreg_collision]=0
  [and_b_postinc_ea_source_collision]=0
  [eor_b_postinc_source_dest_collision]=0
  [eor_b_postinc_ea_dest_collision]=0
  [or_b_postinc_source_dreg_collision]=0
  [or_b_postinc_ea_source_collision]=0
  [sub_b_postinc_source_dreg_collision]=0
  [sub_b_postinc_x_ea_collision]=0
)
declare -A CELL_REQUIRE_SKIP=(
  [mulu_w_d16_a0_live_a0]=0
  [roxrw_mem_x_live_all]=0
  [mullu64_mem_source_locked_dl]=1
  [movem_predec_cursor_base_locked]=1
  [negx_b_source_dst_collision]=1
  [negx_w_source_dst_collision]=1
  [negx_l_source_dst_collision]=1
  [neg_b_postinc_result_ea_collision]=1
  [negx_b_postinc_result_ea_collision]=1
  [tas_b_ea_value_collision]=1
  [clr_b_postinc_zero_ea_collision]=1
  [exg_l_tmp_source_collision]=1
  [ext_w_scratch_source_collision]=1
  [move_b_mem_source_dst_collision]=1
  [scc_b_ea_value_collision]=1
  [dbcc_w_counter_copy_collision]=1
  [bitop_b_ea_value_collision]=1
  [cmpm_b_source_dst_collision]=1
  [cmpa_w_postinc_source_dst_collision]=1
  [adda_w_postinc_source_dst_collision]=1
  [adda_l_postinc_source_dst_collision]=1
  [add_b_postinc_source_dreg_collision]=1
  [add_b_postinc_x_ea_collision]=1
  [and_b_postinc_source_dreg_collision]=1
  [and_b_postinc_ea_source_collision]=1
  [eor_b_postinc_source_dest_collision]=1
  [eor_b_postinc_ea_dest_collision]=1
  [or_b_postinc_source_dreg_collision]=1
  [or_b_postinc_ea_source_collision]=1
  [sub_b_postinc_source_dreg_collision]=1
  [sub_b_postinc_x_ea_collision]=1
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
