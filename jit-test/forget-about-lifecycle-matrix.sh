#!/bin/bash
# Exact-native controls around active integer forget_about() callers plus the
# configured-false kill_rodent branch that retains dormant private-scratch calls.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

names=(
    movea_core_w_postinc_alias_native
    adda_core_w_postinc_alias_native
    move16_core_postpost_same_native
    and_core_b_aind_source_special_native
)
focused=$(IFS=,; echo "${names[*]}")
generated_output=$(DISPLAY="${DISPLAY:-:99}" bash jit-test/run.sh \
    --phases vectors --build-mode skip --test-names "$focused")
printf '%s\n' "$generated_output"
grep -q '^METRIC pass=4$' <<<"$generated_output"
grep -q '^METRIC fail=0$' <<<"$generated_output"
grep -q '^METRIC infra_fail=0$' <<<"$generated_output"
grep -q '^METRIC score=100$' <<<"$generated_output"

clobber_output=$(DISPLAY="${DISPLAY:-:99}" GROUP=integer bun jit-test/fpp-fmove-destination-basic-matrix.ts)
printf '%s\n' "$clobber_output"
grep -q '^FPP_FMOVE_DEST_BASIC_MATRIX pass=36 fail=0 total=36$' <<<"$clobber_output"

printf 'FORGET_ABOUT_LIFECYCLE_MATRIX active=39 dormant_control=1 pass=40 fail=0 total=40\n'
