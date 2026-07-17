#!/bin/bash
# Efficient composable validation driver. Builds at most once, then reuses the
# configured binary for selected focused, structural, vector, and pressure gates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_MODE="incremental"
DO_BUILD=1
WORK_SELECTED=0
DO_STRUCTURAL=0
DO_EMITTERS=0
DO_STRICT=0
FOCUSED=""
TESTS=""
TEST_NAMES=""
PRESSURE=""

usage() {
  cat <<'EOF'
usage: jit-test/validate.sh [options]
  --build-mode MODE    full, incremental (default), or skip
  --structural         run source structural audit
  --emitters           run generic emitter conformance suites
  --strict             run strict full-JIT negative contracts
  --focused LIST       comma-separated matrix stems, optionally stem:CASE
  --tests GLOBS        comma-separated risky-vector shell globs
  --test-names LIST    comma-separated exact risky-vector names
  --pressure GLOBS     comma-separated allocator-cell shell globs
  --full               full build + structural + emitters + all vectors + pressure

Examples:
  ./jit-test/validate.sh --focused fpp-integral-rounding-fallback-matrix
  ./jit-test/validate.sh --build-mode skip --tests 'opcode_fpp_*' --pressure 'adda_*'
  ./jit-test/validate.sh --structural --focused fpp-sqrt-fallback-matrix,fpp-sign-fallback-matrix
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-mode) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; BUILD_MODE="$2"; shift 2 ;;
    --structural) DO_STRUCTURAL=1; WORK_SELECTED=1; shift ;;
    --emitters) DO_EMITTERS=1; WORK_SELECTED=1; shift ;;
    --strict) DO_STRICT=1; WORK_SELECTED=1; shift ;;
    --focused) [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || { echo "--focused requires a non-empty value" >&2; exit 2; }; FOCUSED="$2"; WORK_SELECTED=1; shift 2 ;;
    --tests) [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || { echo "--tests requires a non-empty value" >&2; exit 2; }; TESTS="$2"; WORK_SELECTED=1; shift 2 ;;
    --test-names) [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || { echo "--test-names requires a non-empty value" >&2; exit 2; }; TEST_NAMES="$2"; WORK_SELECTED=1; shift 2 ;;
    --pressure) [[ $# -ge 2 && -n "${2//[[:space:]]/}" ]] || { echo "--pressure requires a non-empty value" >&2; exit 2; }; PRESSURE="$2"; WORK_SELECTED=1; shift 2 ;;
    --full) BUILD_MODE=full; DO_STRUCTURAL=1; DO_EMITTERS=1; DO_STRICT=1; TESTS='*'; PRESSURE='*'; WORK_SELECTED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$BUILD_MODE" in full|incremental) ;; skip) DO_BUILD=0 ;; *) echo "invalid build mode: $BUILD_MODE" >&2; exit 2 ;; esac
[[ -z "$TESTS" || -z "$TEST_NAMES" ]] || { echo "--tests and --test-names are mutually exclusive" >&2; exit 2; }
if [[ $WORK_SELECTED -eq 0 ]]; then
  echo "no non-build validation work selected" >&2; usage >&2; exit 2
fi

START=$SECONDS
PHASES=0
run_phase() {
  local label="$1"; shift
  echo "VALIDATION_PHASE_BEGIN name=$label" >&2
  "$@"
  echo "VALIDATION_PHASE_END name=$label status=PASS" >&2
  PHASES=$((PHASES + 1))
}

if [[ $DO_BUILD -eq 1 ]]; then
  run_phase build "$SCRIPT_DIR/run.sh" --phases build --build-mode "$BUILD_MODE"
fi
if [[ $DO_STRUCTURAL -eq 1 ]]; then
  run_phase structural "$SCRIPT_DIR/run.sh" --phases structural --build-mode skip
fi
if [[ $DO_EMITTERS -eq 1 ]]; then
  run_phase emitters "$SCRIPT_DIR/run.sh" --phases emitters --build-mode skip
fi
if [[ $DO_STRICT -eq 1 ]]; then
  run_phase strict "$SCRIPT_DIR/run.sh" --phases strict --build-mode skip
fi
if [[ -n "$FOCUSED" ]]; then
  IFS=',' read -r -a matrices <<<"$FOCUSED"
  for spec in "${matrices[@]}"; do
    matrix="${spec%%:*}"; case_name=""
    [[ "$spec" == *:* ]] && case_name="${spec#*:}"
    matrix="${matrix#jit-test/}"; matrix="${matrix%.ts}"
    path="$SCRIPT_DIR/$matrix.ts"
    [[ -f "$path" ]] || { echo "unknown focused matrix: $matrix" >&2; exit 2; }
    if [[ -n "$case_name" ]]; then
      run_phase "focused:$matrix:$case_name" env CASE="$case_name" bun "$path"
    else
      run_phase "focused:$matrix" bun "$path"
    fi
  done
fi
if [[ -n "$TESTS" ]]; then
  run_phase vectors "$SCRIPT_DIR/run.sh" --phases vectors --build-mode skip --tests "$TESTS"
elif [[ -n "$TEST_NAMES" ]]; then
  run_phase vectors "$SCRIPT_DIR/run.sh" --phases vectors --build-mode skip --test-names "$TEST_NAMES"
fi
if [[ -n "$PRESSURE" ]]; then
  run_phase pressure "$SCRIPT_DIR/regalloc-pressure.sh" --pattern "$PRESSURE"
fi

printf 'VALIDATION_BATCH status=PASS phases=%s elapsed_sec=%s\n' "$PHASES" "$((SECONDS - START))"
printf 'METRIC validation_batch_phases=%s\n' "$PHASES"
printf 'METRIC validation_batch_elapsed_sec=%s\n' "$((SECONDS - START))"
