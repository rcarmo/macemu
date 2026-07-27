#!/bin/bash
# Audit mov_l_ri's guest constant path, PC_P pointer exception, and raw U32 seam.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

conformance=$(./jit-test/mov-l-ri-conformance.sh)
printf '%s\n' "$conformance"
grep -q '^METRIC mov_l_ri_exact_words=12$' <<<"$conformance"
grep -q '^METRIC mov_l_ri_native_vectors=7$' <<<"$conformance"
grep -q '^METRIC mov_l_ri_guest_width32=1$' <<<"$conformance"
grep -q '^METRIC mov_l_ri_pc_p_width64=1$' <<<"$conformance"

focused=$(./jit-test/run.sh --phases vectors --build-mode skip \
  --test-names move_b_preserve_flags,indexed_full_neg_base)
printf '%s\n' "$focused"
grep -q '^METRIC pass=2$' <<<"$focused"
grep -q '^METRIC fail=0$' <<<"$focused"
grep -q '^METRIC validation_complete=1$' <<<"$focused"

move_names=(
  move_core_l_reg_negative_native move_core_l_reg_zero_native
  move_core_l_imm_zero_native move_core_l_predec_to_dn_native
  move_core_l_absw_to_dn_native move_core_l_pcindex_to_dn_native
  move_core_l_dn_to_predec_native move_core_l_dn_to_absw_native
  move_core_l_areg_postinc_alias_native move_core_l_memmem_postinc_alias_native
)
selected=$(IFS=,; echo "${move_names[*]}")
move=$(./jit-test/run.sh --phases vectors --build-mode skip --test-names "$selected")
printf '%s\n' "$move"
grep -q '^METRIC pass=10$' <<<"$move"
grep -q '^METRIC fail=0$' <<<"$move"
grep -q '^METRIC validation_complete=1$' <<<"$move"
printf 'MOV_L_RI_LIFECYCLE conformance=7 focused=2 move_l=10 fail=0 total=19\n'
