#!/bin/bash
# Prove the unused fmov_d_rm synonym is not needed for configured double-memory
# FMOVE: the live fmov_rm -> raw_fmov_d_rm path remains strict exact-native.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
output="$(CASE=double_aind_a0 bun jit-test/fpp-fmove-memory-basic-matrix.ts)"
grep -Fxq 'FPP_FMOVE_MEMORY_BASIC_MATRIX pass=1 fail=0 total=1' <<<"$output"
printf 'FMOV_D_RM_RETIREMENT_FOCUSED live_double=1 fail=0 total=1\n'
