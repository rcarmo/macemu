#!/bin/bash
# Exercise both configured ordinary-single roots and every existing strict
# exact-native standard EA case that uses fmov_s_rr -> raw_fmov_s_rr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

source_output="$(GROUP=single bun jit-test/fpp-fmove-source-matrix.ts)"
grep -Fxq 'FPP_FMOVE_SOURCE_MATRIX pass=8 fail=0 total=8' <<<"$source_output"

basic_output="$(GROUP=single bun jit-test/fpp-fmove-memory-basic-matrix.ts)"
grep -Fxq 'FPP_FMOVE_MEMORY_BASIC_MATRIX pass=3 fail=0 total=3' <<<"$basic_output"

extended=(
    single_d16_a0_positive
    single_indexed_a0_d1_long_scale2_negative_disp
    single_absolute_short
    single_absolute_long
    single_pc_d16_forward
    single_pc_d16_backward
    single_pc_indexed_brief_d1_long
)

pass=11
for case_name in "${extended[@]}"; do
    output="$(CASE="$case_name" bun jit-test/fpp-fmove-memory-extended-ea-matrix.ts)"
    grep -Fxq 'FPP_FMOVE_EXTENDED_EA_MATRIX pass=1 fail=0 total=1' <<<"$output"
    pass=$((pass + 1))
done

printf 'FMOV_S_RR_NATIVE_MATRIX pass=%d fail=0 total=%d\n' "$pass" "$pass"
test "$pass" -eq 18
