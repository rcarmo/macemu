#!/bin/bash
# Exercise every existing strict exact-native IEEE-double source case that uses
# the live fmov_rm -> raw_fmov_d_rm host-assembly/load chain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

basic=(
    double_aind_a0
    double_postinc_a0
    double_predec_a0
)
extended=(
    double_d16_a0_positive
    double_indexed_a0_d1_long_scale2_negative_disp
    double_absolute_short
    double_absolute_long
    double_pc_d16_forward
    double_absolute_long_to_fp7_max_field
    double_pc_indexed_brief_d1_long
)

pass=0
for case_name in "${basic[@]}"; do
    output="$(CASE="$case_name" bun jit-test/fpp-fmove-memory-basic-matrix.ts)"
    grep -Fxq 'FPP_FMOVE_MEMORY_BASIC_MATRIX pass=1 fail=0 total=1' <<<"$output"
    pass=$((pass + 1))
done
for case_name in "${extended[@]}"; do
    output="$(CASE="$case_name" bun jit-test/fpp-fmove-memory-extended-ea-matrix.ts)"
    grep -Fxq 'FPP_FMOVE_EXTENDED_EA_MATRIX pass=1 fail=0 total=1' <<<"$output"
    pass=$((pass + 1))
done

printf 'FMOV_RM_NATIVE_MATRIX pass=%d fail=0 total=%d\n' "$pass" "$pass"
test "$pass" -eq 10
