#!/bin/bash
# Exact-native lifecycle evidence for fmov_to_{b,w,l}_rr and raw_fmov_to_{b,w,l}_rr.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

basic_output=$(GROUP=integer bun jit-test/fpp-fmove-destination-basic-matrix.ts)
printf '%s\n' "$basic_output"
grep -q '^FPP_FMOVE_DEST_BASIC_MATRIX pass=36 fail=0 total=36$' <<<"$basic_output"

extended_output=$(GROUP=integer bun jit-test/fpp-fmove-destination-extended-ea-matrix.ts)
printf '%s\n' "$extended_output"
grep -q '^FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=18 fail=0 total=18$' <<<"$extended_output"

pass=54
printf 'FMOV_TO_INT_NATIVE_MATRIX pass=%d fail=0 total=%d\n' "$pass" "$pass"
