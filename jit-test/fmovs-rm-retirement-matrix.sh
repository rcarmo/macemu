#!/bin/bash
# Prove configured AArch64 single sources use fmov_s_rr/raw_fmov_s_rr rather
# than the retained non-AArch64 fmovs_rm/raw_fmovs_rm memory wrapper.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

output=$(bash jit-test/fmov-s-rr-native-matrix.sh)
printf '%s\n' "$output"
grep -q '^FMOV_S_RR_NATIVE_MATRIX pass=18 fail=0 total=18$' <<<"$output"
printf 'FMOVS_RM_RETIREMENT live_replacement=18 fail=0 total=18\n'
