#!/bin/bash
# Negative contract probes for B2_JIT_STRICT_FULL.
# Each forbidden path must abort before REGDUMP can make the run look valid.
set -euo pipefail

UNIX_DIR=${1:?usage: strict-full-jit.sh UNIX_DIR ROM DISK}
ROM=${2:?usage: strict-full-jit.sh UNIX_DIR ROM DISK}
DISK=${3:?usage: strict-full-jit.sh UNIX_DIR ROM DISK}
BINARY="$UNIX_DIR/BasiliskII"
RUN_DIR=$(mktemp -d /tmp/b2-strict-contract-XXXXXX)
trap 'rm -rf "$RUN_DIR"' EXIT
ulimit -c 0

make_prefs() {
    local dir=$1
    mkdir -p "$dir"
    cat >"$dir/prefs" <<EOF
rom $ROM
disk $DISK
ramsize 8388608
modelid 14
cpu 4
fpu false
jit true
jitfpu false
jitcachesize 8192
screen win/640/480
nosound true
nocdrom true
ignoresegv true
EOF
}

run_expected_abort() {
    local name=$1
    local expected=$2
    shift 2
    local td="$RUN_DIR/$name"
    make_prefs "$td"
    local rc=0
    set +e
    env SDL_VIDEODRIVER=x11 DISPLAY=:99 HOME="$td" \
        B2_TEST_HEX='4E71 2C7C a601 03ff' \
        B2_TEST_DUMP=1 B2_JIT_FORCE_TRANSLATE=1 B2_JIT_STRICT_FULL=1 \
        "$@" timeout -k 2s 15s "$BINARY" --config "$td/prefs" \
        >"$td/emu.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "STRICT_CONTRACT_FAIL $name: forbidden path returned success" >&2
        return 1
    fi
    if ! grep -Fq "$expected" "$td/emu.log"; then
        echo "STRICT_CONTRACT_FAIL $name: missing '$expected' (rc=$rc)" >&2
        tail -30 "$td/emu.log" >&2 || true
        return 1
    fi
    if grep -q '^REGDUMP:' "$td/emu.log"; then
        echo "STRICT_CONTRACT_FAIL $name: emitted REGDUMP after strict abort" >&2
        return 1
    fi
    echo "METRIC strict_${name}=1"
}

run_expected_fallback() {
    local name=$1
    local expected=$2
    shift 2
    local td="$RUN_DIR/$name"
    make_prefs "$td"
    local rc=0
    set +e
    env -u B2_JIT_STRICT_FULL SDL_VIDEODRIVER=x11 DISPLAY=:99 HOME="$td" \
        B2_TEST_HEX='4E71 2C7C a601 03fe' \
        B2_TEST_DUMP=1 B2_JIT_FORCE_TRANSLATE=1 \
        "$@" timeout -k 2s 15s "$BINARY" --config "$td/prefs" \
        >"$td/emu.log" 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "STRICT_CONTRACT_FAIL $name: ordinary fallback exited rc=$rc" >&2
        tail -30 "$td/emu.log" >&2 || true
        return 1
    fi
    if ! grep -Fq "$expected" "$td/emu.log" ||
       ! grep -q '^REGDUMP:' "$td/emu.log"; then
        echo "STRICT_CONTRACT_FAIL $name: missing clean ordinary fallback evidence" >&2
        tail -30 "$td/emu.log" >&2 || true
        return 1
    fi
    if grep -q 'strict full-JIT:' "$td/emu.log"; then
        echo "STRICT_CONTRACT_FAIL $name: ordinary fallback entered strict policy" >&2
        return 1
    fi
    echo "METRIC strict_${name}=1"
}

run_expected_fallback allocation_fallback \
    'JIT disabled: failed to initialize JIT dispatcher stubs (popallspace)' \
    B2_JIT_PROBE_CODE_ALLOC_FAIL=all
run_expected_abort allocation_abort \
    'strict full-JIT: failed to initialize JIT dispatcher stubs (popallspace)' \
    B2_JIT_PROBE_CODE_ALLOC_FAIL=all
run_expected_abort optlev0 \
    'strict full-JIT: optlev-0 block' \
    B2_JIT_FORCE_OPTLEV0=1
run_expected_abort opcode_fallback \
    'strict full-JIT: opcode fallback' \
    B2_JIT_STRICT_PROBE_OPCODE_FALLBACK=1
run_expected_abort verifier_reference \
    'strict full-JIT: verifier interpreter reference' \
    B2_JIT_VERIFY_BLOCKS=0x1000

echo 'METRIC strict_full_jit_negative_gate=1'
