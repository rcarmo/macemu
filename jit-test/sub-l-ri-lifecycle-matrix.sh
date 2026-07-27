#!/bin/bash
# Audit sub_l_ri's guest-only zero/constant/dynamic and cursor caller classes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

conformance=$(./jit-test/sub-l-ri-conformance.sh)
printf '%s\n' "$conformance"
grep -q '^METRIC sub_l_ri_exact_words=1$' <<<"$conformance"
grep -q '^METRIC sub_l_ri_native_vectors=6$' <<<"$conformance"
grep -q '^METRIC sub_l_ri_modulo32=1$' <<<"$conformance"

branches=$(./jit-test/run.sh --phases vectors --build-mode skip --test-names \
  bcc_core_bra_b_forward_native,bcc_core_bra_w_forward_native,bcc_core_bra_l_forward_native,bcc_core_bne_w_backward_native)
printf '%s\n' "$branches"
grep -q '^METRIC pass=4$' <<<"$branches"
grep -q '^METRIC fail=0$' <<<"$branches"
grep -q '^METRIC validation_complete=1$' <<<"$branches"

stack=$(CASE=link_w_a7_snapshot bun jit-test/control-address-native-matrix.ts)
printf '%s\n' "$stack"
grep -q '^CONTROL_ADDRESS_NATIVE_MATRIX pass=1 fail=0 total=1$' <<<"$stack"

movem=$(./jit-test/run.sh --phases vectors --build-mode skip --test-names \
  movem_l_predec_base_alias_native,movem_w_predec_base_alias_native)
printf '%s\n' "$movem"
grep -q '^METRIC pass=2$' <<<"$movem"
grep -q '^METRIC fail=0$' <<<"$movem"
grep -q '^METRIC validation_complete=1$' <<<"$movem"

fpu=$(CASE=static_to_predec_all_direct_mask bun jit-test/fpp-fmovem-static-service-matrix.ts)
printf '%s\n' "$fpu"
grep -q '^FPP_FMOVEM_STATIC_MATRIX service_pass=1 strict_pass=0 fail=0 total=1$' <<<"$fpu"
printf 'SUB_L_RI_LIFECYCLE conformance=6 branches=4 stack=1 movem=2 fpu_service=1 fail=0 total=14\n'
