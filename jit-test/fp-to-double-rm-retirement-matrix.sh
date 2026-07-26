#!/bin/bash
# Prove the unused fp_to_double_rm -> raw_fp_to_double_rm guest-address
# compatibility chain is not needed by configured binary64 imports.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

output=$(bash jit-test/fmov-rm-native-matrix.sh)
printf '%s\n' "$output"
grep -q '^FMOV_RM_NATIVE_MATRIX pass=10 fail=0 total=10$' <<<"$output"
printf 'FP_TO_DOUBLE_RM_RETIREMENT live_sibling=10 fail=0 total=10\n'
