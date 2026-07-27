#!/bin/bash
# Focus mov_b_ri's two reachable allocator states, then compose the accepted
# MOVE.B source-EA matrix and forced source/destination collision witness.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

focused=$(./jit-test/run.sh --phases vectors --build-mode skip \
  --test-names move_b_preserve_flags,move_core_b_reg_negative_native)
printf '%s\n' "$focused"
grep -q '^METRIC pass=2$' <<<"$focused"
grep -q '^METRIC fail=0$' <<<"$focused"
grep -q '^METRIC validation_complete=1$' <<<"$focused"

move_names=(
  move_core_b_reg_negative_native move_core_b_reg_zero_native
  move_core_b_self_alias_native move_core_b_imm_negative_native
  move_core_b_aind_to_dn_special_native move_core_b_d16_to_dn_native
  move_core_b_absl_to_dn_special_native move_core_b_dn_to_aind_special_native
  move_core_b_dn_to_d16_native move_core_b_dn_to_absl_special_native
  move_core_b_a7_postinc_dst_native move_core_b_a7_postinc_src_native
)
selected=$(IFS=,; echo "${move_names[*]}")
source_eas=$(./jit-test/run.sh --phases vectors --build-mode skip --test-names "$selected")
printf '%s\n' "$source_eas"
grep -q '^METRIC pass=12$' <<<"$source_eas"
grep -q '^METRIC fail=0$' <<<"$source_eas"
grep -q '^METRIC validation_complete=1$' <<<"$source_eas"

pressure=$(./jit-test/regalloc-pressure.sh --cells move_b_mem_source_dst_collision)
printf '%s\n' "$pressure"
grep -q '^REGPRESSURE_SUMMARY selected=1 pass=1 fail=0$' <<<"$pressure"
printf 'MOV_B_RI_LIFECYCLE focused=2 source_ea=12 pressure=1 fail=0 total=15\n'
