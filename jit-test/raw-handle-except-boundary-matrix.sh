#!/bin/bash
# Exercise compemu_raw_handle_except through existing strict-native CHK vectors:
# one no-request fall-through and one deferred vector-6 exit.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
RUN="$(mktemp -d /tmp/b2-raw-handle-except-XXXXXX)"
INNER=""
cleanup(){ [[ -z "$INNER" ]] || rm -rf "$INNER"; rm -rf "$RUN"; }
trap cleanup EXIT

B2_KEEP_TEST_RUN_DIR=1 B2_TEST_DISPATCH_SUMMARY=1 \
  "$D/run.sh" --phases vectors --build-mode skip \
  --test-names chk_w_in_range,chk_w_negative_trap_n >"$RUN/run.log" 2>&1
INNER="$(sed -n 's/^JIT_TEST_RUN_DIR=//p' "$RUN/run.log" | tail -1)"
[[ -n "$INNER" && -d "$INNER" ]] || {
  echo 'RAW_HANDLE_EXCEPT_FAIL missing preserved inner run directory' >&2
  tail -40 "$RUN/run.log" >&2
  exit 1
}

audit_case(){
  local name=$1 expect_taken=$2 expect_cycles=$3 expect_dump=$4
  local log="$INNER/test-$name-jittrue/emu.log" summary checks taken cycles received
  [[ -r "$log" ]] || { echo "RAW_HANDLE_EXCEPT_FAIL $name missing JIT log" >&2; exit 1; }
  summary="$(grep '^JIT_TEST_DISPATCH ' "$log" | tail -1 || true)"
  [[ -n "$summary" ]] || { echo "RAW_HANDLE_EXCEPT_FAIL $name missing summary" >&2; exit 1; }
  checks="$(sed -n 's/.* handle_except_checks=\([0-9][0-9]*\).*/\1/p' <<<"$summary")"
  taken="$(sed -n 's/.* handle_except_taken=\([0-9][0-9]*\).*/\1/p' <<<"$summary")"
  cycles="$(sed -n 's/.* handle_except_cycles=\([0-9][0-9]*\).*/\1/p' <<<"$summary")"
  received="$(sed -n 's/.* handle_except_received_cycles=\([0-9][0-9]*\).*/\1/p' <<<"$summary")"
  [[ ${checks:-0} -eq 1 && ${taken:-0} -eq "$expect_taken" && ${cycles:-0} -eq "$expect_cycles" &&
      ${received:-0} -eq "$expect_cycles" ]] || {
    echo "RAW_HANDLE_EXCEPT_FAIL $name unexpected boundary summary: $summary" >&2; exit 1; }
  for zero in direct_checksum check_checksum good bad exec_normal exec_nostats recompile_block \
      metadata_rebuild metadata_edges direct_exec_nostats direct_execute_normal execute_normal_cycles; do
    [[ "$summary" == *" $zero=0"* ]] || {
      echo "RAW_HANDLE_EXCEPT_FAIL $name neighbouring counter $zero not zero: $summary" >&2; exit 1; }
  done
  grep -Eq "$expect_dump" "$log" || {
    echo "RAW_HANDLE_EXCEPT_FAIL $name terminal state mismatch" >&2
    grep '^REGDUMP:' "$log" >&2 || true
    exit 1
  }
  printf 'RAW_HANDLE_EXCEPT_PASS case=%s %s\n' "$name" "$summary"
}

audit_case chk_w_in_range 0 0 \
  '^REGDUMP: D0=00000008 D1=00000014 .* A6=a6f03200 A7=007eff00 SR=2700 FPSR=00000000$'
audit_case chk_w_negative_trap_n 1 1024 \
  '^REGDUMP: D0=ffffffff D1=00000014 .* D4=00001018 D5=00001018 D6=0000271d D7=00000066 .* A6=a6c6e001 A7=007efef4 SR=2710 FPSR=00000000$'

grep -q '^METRIC pass=2$' "$RUN/run.log"
grep -q '^METRIC fail=0$' "$RUN/run.log"
grep -q '^METRIC validation_complete=1$' "$RUN/run.log"
printf 'METRIC raw_handle_except_boundaries=1\n'
printf 'METRIC raw_handle_except_runtime_cases=2\n'
printf 'METRIC raw_handle_except_fallthrough=1\n'
printf 'METRIC raw_handle_except_taken=1\n'
printf 'METRIC raw_handle_except_cycle_argument=1024\n'
printf 'METRIC raw_handle_except_received_cycle_argument=1024\n'
