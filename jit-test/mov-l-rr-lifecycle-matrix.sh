#!/bin/bash
# Audit mov_l_rr self/constant/materialised states and the PC_P pointer route.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

conformance=$(./jit-test/mov-l-rr-conformance.sh)
printf '%s\n' "$conformance"
grep -q '^METRIC mov_l_rr_exact_words=4$' <<<"$conformance"
grep -q '^METRIC mov_l_rr_native_vectors=7$' <<<"$conformance"
grep -q '^METRIC mov_l_rr_full_width64=1$' <<<"$conformance"
grep -q '^METRIC mov_l_rr_self_alias=1$' <<<"$conformance"

focused=$(./jit-test/run.sh --phases vectors --build-mode skip \
  --test-names mov_l_rr_self_native,mov_l_rr_const_movea_native,move_core_l_reg_negative_native,bcc_core_bra_l_forward_native)
printf '%s\n' "$focused"
grep -q '^METRIC pass=4$' <<<"$focused"
grep -q '^METRIC fail=0$' <<<"$focused"
grep -q '^METRIC validation_complete=1$' <<<"$focused"

controls=$(./jit-test/run.sh --phases vectors --build-mode skip \
  --test-names move_core_l_reg_zero_native,movea_core_l_dreg_native,move_core_l_areg_postinc_alias_native,move_core_l_memmem_postinc_alias_native)
printf '%s\n' "$controls"
grep -q '^METRIC pass=4$' <<<"$controls"
grep -q '^METRIC fail=0$' <<<"$controls"
grep -q '^METRIC validation_complete=1$' <<<"$controls"
printf 'MOV_L_RR_LIFECYCLE conformance=7 focused=4 controls=4 fail=0 total=15\n'
