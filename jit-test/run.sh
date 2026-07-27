#!/bin/bash
# BasiliskII AArch64 JIT Opcode Correctness Test
# Autoresearch harness: compare interpreter vs JIT register state for each opcode class
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIX_DIR="$(cd "$SCRIPT_DIR/../BasiliskII/src/Unix" && pwd)"
ROM="${B2_TEST_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DEFAULT_DISK="/workspace/fixtures/basilisk/images/HD200MB"
DISK="${B2_TEST_DISK:-$DEFAULT_DISK}"
VALIDATION_PHASES="${B2_VALIDATION_PHASES:-build,structural,emitters,strict,vectors}"
BUILD_MODE="${B2_BUILD_MODE:-full}"
TEST_PATTERNS="${B2_TEST_PATTERN:-}"
TEST_PATTERNS_SET=0
TEST_NAMES_SET=0

valid_csv() {
    local label="$1" raw="$2" compact="${2//[[:space:]]/}" component
    local -A seen=()
    if [ -z "$compact" ] || [[ "$compact" == ,* || "$compact" == *, || "$compact" == *,,* ]]; then
        echo "$label contains an empty comma-separated component" >&2
        return 1
    fi
    IFS=',' read -r -a _csv_components <<<"$compact"
    for component in "${_csv_components[@]}"; do
        if [ -n "${seen[$component]+x}" ]; then
            echo "$label contains duplicate component: $component" >&2
            return 1
        fi
        seen["$component"]=1
    done
}

usage() {
    cat <<'EOF'
usage: jit-test/run.sh [options]
  --phases LIST       comma list: build,structural,emitters,strict,vectors
  --build-mode MODE   full (default), incremental, or skip
  --tests GLOBS       comma-separated shell globs over risky vector names
  --test-names NAMES  comma-separated exact risky vector names

Examples:
  ./jit-test/run.sh --phases build,vectors --build-mode incremental --tests 'opcode_fpp_*'
  ./jit-test/run.sh --phases vectors --build-mode skip --test-names opcode_add,opcode_sub
EOF
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --phases) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; VALIDATION_PHASES="$2"; shift 2 ;;
        --build-mode) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; BUILD_MODE="$2"; shift 2 ;;
        --tests) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TEST_PATTERNS="$2"; TEST_PATTERNS_SET=1; shift 2 ;;
        --test-names) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; B2_TEST_NAMES="$2"; TEST_NAMES_SET=1; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
valid_csv "validation phase list" "$VALIDATION_PHASES" || exit 2
if [ "$TEST_PATTERNS_SET" -eq 1 ]; then valid_csv "--tests" "$TEST_PATTERNS" || exit 2; fi
if [ "$TEST_NAMES_SET" -eq 1 ]; then valid_csv "--test-names" "${B2_TEST_NAMES:-}" || exit 2; fi
if [ -n "$TEST_PATTERNS" ]; then valid_csv "B2_TEST_PATTERN" "$TEST_PATTERNS" || exit 2; fi
if [ -n "${B2_TEST_NAMES:-}" ]; then valid_csv "B2_TEST_NAMES" "$B2_TEST_NAMES" || exit 2; fi

phase_enabled() {
    local wanted="$1" normalized=",${VALIDATION_PHASES//[[:space:]]/},"
    [[ "$normalized" == *",$wanted,"* ]]
}
_phase_count=0
for _phase in ${VALIDATION_PHASES//,/ }; do
    case "$_phase" in build|structural|emitters|strict|vectors) ;; *) echo "unknown validation phase: $_phase" >&2; exit 2 ;; esac
    _phase_count=$((_phase_count + 1))
done
[ "$_phase_count" -gt 0 ] || { echo "validation phase list is empty" >&2; exit 2; }
case "$BUILD_MODE" in full|incremental|skip) ;; *) echo "invalid build mode: $BUILD_MODE" >&2; exit 2 ;; esac
if [ -n "${B2_TEST_NAMES:-}" ] && [ -n "$TEST_PATTERNS" ]; then
    echo "--tests/B2_TEST_PATTERN and --test-names/B2_TEST_NAMES are mutually exclusive" >&2
    exit 2
fi
RUN_DIR="$(mktemp -d /tmp/ar-jit-opcodes-XXXXXX)"

# Copy-on-write disk clone (real CoW via btrfs scratch; avoids full-image copies
# and keeps every harness run isolated from the shared base fixture).
COW_LIB=${COW_LIB:-/workspace/scripts/lib/cow-disk.sh}
[ -r "$COW_LIB" ] && source "$COW_LIB"
DISK_CLONE=""

cleanup() {
    [ -n "$DISK_CLONE" ] && command -v cow_release >/dev/null 2>&1 && cow_release "$DISK_CLONE"
    if [ "${B2_KEEP_TEST_RUN_DIR:-0}" = "1" ]; then
        echo "JIT_TEST_RUN_DIR=$RUN_DIR" >&2
    else
        rm -rf "$RUN_DIR"
    fi
}
trap cleanup EXIT

emit_zero_vector_metrics() {
    echo "METRIC vectors_skipped=1"
    echo "METRIC pass=0"
    echo "METRIC fail=0"
    echo "METRIC total=0"
    echo "METRIC infra_fail=0"
    echo "METRIC fail_equiv=0"
    echo "METRIC infra_timeout=0"
    echo "METRIC infra_emu_exit=0"
    echo "METRIC infra_no_regdump=0"
    echo "METRIC infra_multi_regdump=0"
    echo "METRIC infra_sentinel=0"
    echo "METRIC infra_other=0"
    echo "METRIC risky_total=0"
    echo "METRIC risky_pass=0"
    echo "METRIC risky_fail=0"
    echo "METRIC risky_fail_equiv=0"
    echo "METRIC risky_infra_fail=0"
    echo "METRIC score=0"
    echo "METRIC selected_vectors=0"
    echo "METRIC validation_complete=1"
}

emit_failure_metrics() {
    local build_ok="$1"
    local reason="$2"
    local infra_fail="${3:-$(( build_ok == 1 ? 0 : 1 ))}"
    echo "METRIC build_ok=$build_ok"
    echo "METRIC build_skipped=$([ "$build_ok" -eq 1 ] && echo 1 || echo 0)"
    echo "METRIC pass=0"
    echo "METRIC fail=0"
    echo "METRIC total=0"
    echo "METRIC infra_fail=$infra_fail"
    echo "METRIC fail_equiv=0"
    echo "METRIC infra_timeout=0"
    echo "METRIC infra_emu_exit=0"
    echo "METRIC infra_no_regdump=0"
    echo "METRIC infra_multi_regdump=0"
    echo "METRIC infra_sentinel=0"
    echo "METRIC infra_other=0"
    echo "METRIC risky_total=0"
    echo "METRIC risky_pass=0"
    echo "METRIC risky_fail=0"
    echo "METRIC risky_fail_equiv=0"
    echo "METRIC risky_infra_fail=0"
    echo "METRIC score=0"
    echo "METRIC selected_vectors=0"
    echo "METRIC validation_complete=0"
    echo "$reason" >&2
    exit 1
}

# ---- Selective build and engine gates ----------------------------------------
if ! cd "$UNIX_DIR"; then
    emit_failure_metrics 0 "missing Unix build directory: $UNIX_DIR"
fi
if phase_enabled vectors || phase_enabled strict; then
    [ -r "$ROM" ] || emit_failure_metrics 0 "missing ROM: $ROM"
    [ -r "$DISK" ] || emit_failure_metrics 0 "missing disk image: $DISK"
fi

if phase_enabled build; then
    # Fresh worktrees may be missing generated configure/config.h state.
    if [ ! -x ./configure ] && [ -x ./autogen.sh ]; then
        NO_CONFIGURE=1 ./autogen.sh >"$RUN_DIR/autogen.log" 2>&1 || true
    fi
    if [ ! -f config.h ] || [ ! -f Makefile ]; then
        if [ ! -x ./configure ]; then
            tail -20 "$RUN_DIR/autogen.log" >&2 || true
            emit_failure_metrics 0 "missing ./configure after autogen"
        fi
        if ! ac_cv_have_asm_extended_signals=yes \
          ./configure --with-uae-core=2021 --enable-aarch64-jit-experimental --disable-vosf \
          >"$RUN_DIR/configure.log" 2>&1; then
            tail -20 "$RUN_DIR/configure.log" >&2 || true
            emit_failure_metrics 0 "configure failed"
        fi
    fi
    if [ "$BUILD_MODE" = "full" ]; then
        # Full acceptance forbids a mixed generated-object ABI epoch.
        rm -f obj/compemu*.o
    fi
    if [ "$BUILD_MODE" != "skip" ] && ! make -j12 >"$RUN_DIR/build.log" 2>&1; then
        tail -20 "$RUN_DIR/build.log" >&2 || true
        emit_failure_metrics 0 "build failed"
    fi
    echo "METRIC build_ok=1"
    echo "METRIC build_skipped=$([ "$BUILD_MODE" = skip ] && echo 1 || echo 0)"
else
    if { phase_enabled vectors || phase_enabled strict; } && [ ! -x ./BasiliskII ]; then
        emit_failure_metrics 0 "runtime phase requested without a prebuilt BasiliskII"
    fi
    echo "METRIC build_ok=1"
    echo "METRIC build_skipped=1"
fi

if phase_enabled structural && ! bun "$SCRIPT_DIR/structural-audit.ts"; then
    emit_failure_metrics 1 "ARM64 JIT structural audit failed" 0
fi
if phase_enabled emitters; then
    # Keep explicit bounded calls: structural-audit.ts pins each accepted gate
    # by literal path so a dynamic loop cannot silently omit a suite.
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-word-conformance.sh" || emit_failure_metrics 1 "ARM64 word-emission conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-carry-conformance.sh" || emit_failure_metrics 1 "ARM64 carry-arithmetic emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-adds-conformance.sh" || emit_failure_metrics 1 "ARM64 ADD-with-flags emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-compare-conformance.sh" || emit_failure_metrics 1 "ARM64 CMP emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-add-conformance.sh" || emit_failure_metrics 1 "ARM64 ADD emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-sub-conformance.sh" || emit_failure_metrics 1 "ARM64 SUB emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-and-conformance.sh" || emit_failure_metrics 1 "ARM64 AND emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-eor-conformance.sh" || emit_failure_metrics 1 "ARM64 EOR emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-neg-conformance.sh" || emit_failure_metrics 1 "ARM64 NEG emitter conformance failed" 0
    timeout -k 5s 60s "$SCRIPT_DIR/emitter-branch-conformance.sh" || emit_failure_metrics 1 "ARM64 branch emitter conformance failed" 0
    timeout -k 5s 90s "$SCRIPT_DIR/emitter-fmov-conformance.sh" || emit_failure_metrics 1 "ARM64 FMOV emitter conformance failed" 0
    timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcmp-conformance.sh" || emit_failure_metrics 1 "ARM64 FCMP emitter conformance failed" 0
    timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcvtas-conformance.sh" || emit_failure_metrics 1 "ARM64 FCVTAS emitter conformance failed" 0
    timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcvt-conformance.sh" || emit_failure_metrics 1 "ARM64 FCVT emitter conformance failed" 0
    timeout -k 5s 180s "$SCRIPT_DIR/emitter-fmov-sw-ws-conformance.sh" || emit_failure_metrics 1 "ARM64 FMOV W/S emitter conformance failed" 0
    timeout -k 5s 180s "$SCRIPT_DIR/emitter-fmov-dx-xd-conformance.sh" || emit_failure_metrics 1 "ARM64 FMOV X/D emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-scvtf-conformance.sh" || emit_failure_metrics 1 "ARM64 SCVTF emitter conformance failed" 0
    timeout -k 5s 600s "$SCRIPT_DIR/emitter-frint-conformance.sh" || emit_failure_metrics 1 "ARM64 FRINT emitter conformance failed" 0
    timeout -k 5s 900s "$SCRIPT_DIR/emitter-fmov-di-conformance.sh" || emit_failure_metrics 1 "ARM64 FMOV immediate emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fsqrt-conformance.sh" || emit_failure_metrics 1 "ARM64 FSQRT emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fsub-conformance.sh" || emit_failure_metrics 1 "ARM64 FSUB emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fmul-conformance.sh" || emit_failure_metrics 1 "ARM64 FMUL emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fmul-s-conformance.sh" || emit_failure_metrics 1 "ARM64 FMUL single emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fdiv-d-conformance.sh" || emit_failure_metrics 1 "ARM64 FDIV binary64 emitter conformance failed" 0
    timeout -k 5s 300s "$SCRIPT_DIR/emitter-fdiv-s-conformance.sh" || emit_failure_metrics 1 "ARM64 FDIV binary32 emitter conformance failed" 0
    timeout -k 5s 600s "$SCRIPT_DIR/emitter-fmsub-conformance.sh" || emit_failure_metrics 1 "ARM64 FMSUB emitter conformance failed" 0
fi

# Runtime phases must never fall through to the shared fixture. Callers may
# reuse only an explicitly supplied non-default isolated disk; otherwise make a
# private CoW clone or a local reflink/copy fallback.
if phase_enabled vectors || phase_enabled strict; then
    if [ "${B2_REUSE_TEST_DISK:-0}" = "1" ]; then
        _disk_real="$(readlink -f -- "$DISK" 2>/dev/null || true)"
        _default_disk_real="$(readlink -f -- "$DEFAULT_DISK" 2>/dev/null || true)"
        if [ -z "${B2_TEST_DISK:-}" ] || [ -z "$_disk_real" ] || [ "$_disk_real" = "$_default_disk_real" ] || [ "$DISK" -ef "$DEFAULT_DISK" ]; then
            emit_failure_metrics 0 "B2_REUSE_TEST_DISK requires an explicit non-default isolated B2_TEST_DISK"
        fi
    elif command -v cow_clone >/dev/null 2>&1; then
        if ! DISK_CLONE="$(cow_clone "$DISK" "$RUN_DIR/disk.img" "jit-opc")"; then
            emit_failure_metrics 0 "unable to create private CoW test disk"
        fi
        DISK="$DISK_CLONE"
    else
        if ! cp --reflink=auto "$DISK" "$RUN_DIR/disk.img"; then
            emit_failure_metrics 0 "unable to create private test disk copy"
        fi
        DISK="$RUN_DIR/disk.img"
    fi
fi

# Source-only phase batches stop before Xvfb startup or the 900+ vector maps.
if ! phase_enabled vectors && ! phase_enabled strict; then
    emit_zero_vector_metrics
    exit 0
fi

# ---- Test harness ------------------------------------------------------------
# Each test case is a hex sequence of M68K instructions.
# The emulator runs until it hits STOP #0x2700 (4e72 2700), then dumps registers.
# We run in both interpreter (jit false) and JIT (jit true) and compare.

# Register dump is extracted from stderr: lines matching "REGDUMP D0=..."
# We inject EMUL_OP_DUMP_REGS (if present) or parse from DC log at STOP.

run_test() {
    local name="$1"
    local hex_code="$2"      # hex M68K bytecode, space-separated words
    local use_jit="$3"       # "true" or "false"
    local sentinel_a6="$4"   # 8-hex-digit value expected in A6
    local outfile="$5"
    local init_regs="${6:-}"  # optional: D0-D7 A0-A7 [SR] space-separated hex

    local td="$RUN_DIR/test-${name}-jit${use_jit}"
    local reason_file="${outfile}.reason"
    mkdir -p "$td"
    echo "ok" > "$reason_file"

    # Append a non-CCR-clobbering sentinel write (MOVEA.L #imm, A6).
    # Opcode: 2C7C <imm_hi16> <imm_lo16>
    local full_hex="$hex_code 2C7C ${sentinel_a6:0:4} ${sentinel_a6:4:4}"

    # Write prefs
    cat > "$td/prefs" <<EOF
rom $ROM
disk $DISK
ramsize 8388608
modelid 14
cpu 4
fpu false
jit $use_jit
jitfpu false
jitcachesize 8192
screen win/640/480
nosound true
nocdrom true
nogui true
ignoresegv true
EOF

    # Ensure stale emulator processes from prior tests do not survive.
    pkill -f '/tmp/ar-jit-opcodes-.*BasiliskII' 2>/dev/null || true
    pkill -f "$UNIX_DIR/BasiliskII --config $td/prefs" 2>/dev/null || true

    # Hard timeout: terminate after 30s, kill after 5s grace.
    # Some BasiliskII runs ignore TERM or survive in a separate process group,
    # so follow with a targeted pkill sweep.
    local emu_rc=0
    local -a env_vars=(
        SDL_VIDEODRIVER=x11
        DISPLAY=:99
        HOME="$td"
        B2_TEST_HEX="$full_hex"
        B2_TEST_DUMP=1
    )
    if [ "$use_jit" = "true" ]; then
        env_vars+=(B2_JIT_FORCE_TRANSLATE=1)
        if [ -n "${SPECIAL_MEMORY_TESTS[$name]+x}" ]; then
            env_vars+=(B2_JIT_ALL_SPECIAL_MEM=1)
        fi
    fi
    if [ -n "${NATIVE_REPLAY_TESTS[$name]+x}" ]; then
        local replay_pc="${NATIVE_REPLAY_PC[$name]:-0x1000}"
        env_vars+=(B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC="$replay_pc")
        if [ "$name" = "host_code_reuse_coherence" ]; then
            # Reuse the same host-injected address with a different MOVEQ,
            # preserving the harness sentinel after the replacement opcode.
            env_vars+=(B2_TEST_REWRITE_HEX="7002 2C7C ${sentinel_a6:0:4} ${sentinel_a6:4:4}")
        fi
        local replay_bytes="${NATIVE_REPLAY_BYTES[$name]:-}"
        if [ -n "$replay_bytes" ]; then
            env_vars+=(B2_TEST_REPLAY_BYTES="$replay_bytes")
        fi
        local replay_count="${NATIVE_REPLAY_COUNT[$name]:-1}"
        if [ "$replay_count" -gt 1 ]; then
            # Some alternate-PC or coherency vectors must first trace their
            # replay anchor before a later pass can prove its native entry.
            env_vars+=(B2_TEST_REPLAY_COUNT="$replay_count")
        fi
        if [ "$use_jit" = "true" ]; then
            env_vars+=(B2_TEST_FORCE_L2_RAM=1 B2_JIT_STRICT_FULL=1 B2_NATIVE_ASSERT_PC="$replay_pc")
        fi
    fi
    if [ -n "$init_regs" ]; then
        env_vars+=(B2_TEST_INIT="$init_regs")
    fi
    local memory_bytes="${TEST_MEMORY_BYTES[$name]:-}"
    if [ -n "$memory_bytes" ]; then
        env_vars+=(B2_TEST_MEMORY_BYTES="$memory_bytes")
    fi
    if ! env "${env_vars[@]}" \
      timeout -k 5s 30s "$UNIX_DIR/BasiliskII" --config "$td/prefs" \
      > "$td/emu.log" 2>&1; then
        emu_rc=$?
    fi

    pkill -f "$UNIX_DIR/BasiliskII --config $td/prefs" 2>/dev/null || true
    sleep 0.2

    if [ "$emu_rc" -eq 124 ] || [ "$emu_rc" -eq 137 ]; then
        echo "timeout" > "$reason_file"
        echo "INFRA $name jit=$use_jit: timeout (rc=$emu_rc)" >&2
        return 1
    fi
    if [ "$emu_rc" -ne 0 ]; then
        echo "emu_exit_$emu_rc" > "$reason_file"
        echo "INFRA $name jit=$use_jit: emulator exited non-zero (rc=$emu_rc)" >&2
        return 1
    fi

    if [ "$use_jit" = "true" ] && [ -n "${NATIVE_REPLAY_TESTS[$name]+x}" ]; then
        if ! grep -q '^JIT_STRICT_SUMMARY ' "$td/emu.log" ||
           grep -qE 'strict full-JIT:|JIT_FALLBACK' "$td/emu.log"; then
            echo "strict_native_evidence" > "$reason_file"
            echo "INFRA $name jit=$use_jit: missing clean strict native summary" >&2
            return 1
        fi
        local replay_pc_hex
        replay_pc_hex=$(printf '%08x' "$((replay_pc))")
        if ! grep -q "^NATEXEC pc=$replay_pc_hex " "$td/emu.log"; then
            echo "strict_native_entry_evidence" > "$reason_file"
            echo "INFRA $name jit=$use_jit: test block did not enter native L2 code at PC $replay_pc_hex" >&2
            return 1
        fi
    fi

    local dump_count
    dump_count=$(grep -c "^REGDUMP:" "$td/emu.log" 2>/dev/null || true)
    if [ "$dump_count" -eq 0 ]; then
        echo "no_regdump" > "$reason_file"
        echo "INFRA $name jit=$use_jit: missing REGDUMP" >&2
        return 1
    fi
    if [ "$dump_count" -gt 1 ]; then
        echo "multi_regdump" > "$reason_file"
        echo "INFRA $name jit=$use_jit: expected 1 REGDUMP, got $dump_count" >&2
        return 1
    fi

    grep "^REGDUMP:" "$td/emu.log" > "$outfile"
    if ! grep -qi "A6=$sentinel_a6" "$outfile"; then
        echo "sentinel_mismatch" > "$reason_file"
        echo "INFRA $name jit=$use_jit: sentinel A6 mismatch (expected $sentinel_a6)" >&2
        return 1
    fi
    local expected_d0="${EXPECTED_D0[$name]:-}"
    if [ -n "$expected_d0" ] && ! grep -qi "D0=$expected_d0" "$outfile"; then
        echo "semantic_d0_mismatch" > "$reason_file"
        echo "INFRA $name jit=$use_jit: D0 mismatch (expected $expected_d0)" >&2
        return 1
    fi
    local expected_field
    for expected_field in ${EXPECTED_REG_FIELDS[$name]:-}; do
        if ! grep -qi " $expected_field\( \|$\)" "$outfile"; then
            echo "semantic_reg_mismatch" > "$reason_file"
            echo "INFRA $name jit=$use_jit: register dump missing $expected_field" >&2
            return 1
        fi
    done

    return 0
}

# Start Xvfb on the specific display we use if needed.
# Another Xvfb on a different display (e.g. :165) must not suppress startup
# of the harness display :99.
if ! DISPLAY=:99 xdpyinfo >/dev/null 2>&1; then
    rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
    Xvfb :99 -screen 0 640x480x24 >/dev/null 2>&1 &
    for _ in $(seq 1 20); do
        if DISPLAY=:99 xdpyinfo >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
fi
if ! DISPLAY=:99 xdpyinfo >/dev/null 2>&1; then
    emit_failure_metrics 0 "failed to start Xvfb on :99"
fi

# Strict mode is a separately selectable phase. Full/default validation retains
# it; focused vector loops avoid four unrelated expected-abort emulator starts.
if phase_enabled strict; then
    if ! "$SCRIPT_DIR/strict-full-jit.sh" "$UNIX_DIR" "$ROM" "$DISK"; then
        emit_failure_metrics 1 "strict full-JIT negative contract gate failed" 0
    fi
fi

# A strict-only invocation succeeds here, before parsing the 900+ vector
# declarations and preflight maps.
if ! phase_enabled vectors; then
    emit_zero_vector_metrics
    exit 0
fi

# ---- Define test cases -------------------------------------------------------
# Format: name|hex_words (M68K big-endian, STOP #0x2700 appended automatically)
# Each test sets up known state and exercises one opcode class.

declare -a TEST_ORDER=(nop move moveq_signext alu alu_overflow addi_subi_long addi_subi_long_wrap addi_subi_word addi_subi_word_wrap addi_subi_byte addi_subi_byte_wrap shift bitops bitops_chg bitops_highbit bitops_chg_highbit btst_b_d16_highbit branch branch_chain compare compare_negative cmpi_sizes cmpi_sizes_zero cmpi_byte_negative cmpi_word_negative cmpi_long_negative cmpi_beq_taken muldiv movem misc clr_sizes clr_byte_preserve_upper clr_word_preserve_upper neg_sizes neg_zero_sizes swap_roundtrip flags flags_eori_ccr exg exg_roundtrip imm_logic imm_logic_alt imm_logic_byte_highbit imm_logic_word imm_logic_long imm_logic_long_alt tst_sizes tst_zero tst_positive bra_taken bra_w_taken bne_not_taken bne_taken bne_w_not_taken bne_w_taken beq_taken beq_not_taken beq_w_taken beq_w_not_taken bpl_taken bpl_not_taken bpl_w_taken bpl_w_not_taken bmi_taken bmi_not_taken bmi_w_taken bmi_w_not_taken bvc_taken bvc_not_taken_overflow bvc_w_taken bvc_w_not_taken_overflow bvs_taken_overflow bvs_not_taken bvs_w_taken_overflow bvs_w_not_taken bge_taken bge_not_taken bge_w_taken bge_w_not_taken blt_taken blt_not_taken blt_w_taken blt_w_not_taken bgt_taken bgt_not_taken bgt_w_taken bgt_w_not_taken ble_taken ble_not_taken ble_w_taken ble_w_not_taken bcc_taken bcc_not_taken bcc_w_taken bcc_w_not_taken bcs_taken bcs_not_taken bcs_w_taken bcs_w_not_taken bhi_taken bhi_not_taken bhi_w_taken bhi_w_not_taken bls_taken bls_not_taken bls_w_taken bls_w_not_taken scc_basic scc_eq_ne scc_carry scc_hi_ls scc_hi_ls_z scc_vc_vs scc_pl_mi scc_ge_lt scc_gt_le scc_ccr_preserve_blt scc_ccr_preserve_bcs scc_ccr_preserve_bne_not_taken scc_ccr_preserve_beq_taken quick_ops quick_ops_long_neg_roundtrip quick_ops_word quick_ops_word_wrap quick_ops_long_wrap quick_ops_byte quick_ops_byte_wrap quick_ops_addr dbra dbra_not_taken dbra_start_minus1_branch dbra_start_8000_branch dbt_true_not_taken dbra_three_iter dbcc_loop_c_set dbcs_not_taken_c_set dbpl_loop_n_set dbmi_not_taken_n_set dbhi_not_taken_hi_set dbls_not_taken_ls_set dbge_not_taken_n_eq_v dblt_not_taken_n_ne_v dbgt_not_taken_gt_set dble_not_taken_le_set dbhi_false_dec_terminal_ls_set dbls_false_dec_terminal_hi_set dbge_false_dec_terminal_n_ne_v dblt_false_dec_terminal_n_eq_v dbgt_false_dec_terminal_z_set dble_false_dec_terminal_gt_set dbcc_ccr_preserve_beq_taken dbra_ccr_preserve_z_clear dbra_ccr_preserve_z_set dbcc_ccr_preserve_bne_taken dbcc_ccr_preserve_bcs_taken dbcc_ccr_preserve_bvc_taken dbcc_ccr_preserve_bvs_taken dbcc_ccr_preserve_bhi_taken dbcc_ccr_preserve_bls_taken dbcc_ccr_preserve_bge_taken dbcc_ccr_preserve_blt_taken dbcc_ccr_preserve_bgt_taken dbcc_ccr_preserve_ble_taken dbvc_loop_v_set dbvs_loop_v_clear dbvc_not_taken_v_clear dbvs_not_taken_v_set dbne_loop_z_set dbeq_loop_z_clear dbeq_x_clobber moveq_edges alu_negative_roundtrip imm_logic_word_highbit branch_chain_z_clear branch_chain_carry_set branch_chain_overflow_set scc_ccr_preserve_bvs_taken dbra_four_iter scc_ccr_preserve_bvc_taken scc_ccr_preserve_bhi_taken scc_ccr_preserve_bls_taken dbra_five_iter branch_chain_eq_then_ne branch_chain_carry_clear branch_flush_bgt_zero imm_logic_long_highbit dbra_six_iter not_sizes not_word_preserve_upper not_byte_preserve_upper scc_ccr_preserve_bpl_taken scc_ccr_preserve_bmi_taken scc_ccr_preserve_bge_taken scc_ccr_preserve_bgt_taken scc_ccr_preserve_ble_taken nop_triplet roxl_x_propagation roxr_x_propagation roxl_count_2 asl_overflow lsr_count_32 asr_count_0 ror_word rol_word btst_reg_high_bit muls_neg_neg muls_zero divs_neg_neg divs_overflow abcd_basic sbcd_basic negx_with_x negx_zero addx_basic subx_basic ext_word ext_long move_to_mem_and_back movem_predec_postinc movem_no_writeback movem_predec_mixed_order addx_chain flag_chain_xzn shift_chain roxl_reg_count_32 roxl_reg_count_33 roxr_reg_count_33 roxr_reg_count_32 roxr_reg_count_0 roxl_reg_count_63 roxr_reg_count_63 roxr_roxl_chain_x roxl_lsr_chain_x mulu_large divu_remainder abcd_with_carry nbcd_basic bsr_rts link_unlk indexed_addr_mode indexed_full_neg_base io_byte_write_roundtrip strict_zero_ram_native host_code_reuse_coherence cache_disabled_selfmod_replay byte_postinc cmpm_equal move_sr_roundtrip dbra_loop_100 dbne_loop_cmpi bsr_in_dbra_loop table_lookup dbra_loop_1000 swap_pack lea_scaled_index multi_branch andi_l_dn eor_self asl_w_vflag asl_b_overflow lsr_w_regcount asr_w_preserve movem_w_signext cmpm_l_equal cmpm_b_unequal addx_64bit subx_64bit muls_boundary divu_max_quotient move_b_preserve_flags byte_logic_chain bchg_imm_high neg_w_partial clr_b_tst all_regs_alive scaled_index_word byte_indexed_load indexed_store_load addq_subq_sizes x_flag_chain sub_w_subx_chain exg_dn_an push_pop_a0 dbeq_loop_50 dbmi_loop_neg lsl_l_count0 asr_l_8_neg rol_l_16 lsl_b_7 asr_b_1_sign move_b_flags move_w_zero add_l_an_dn sub_w_dn_an cmp_b cmp_w ori_w_mem andi_b_mem link_neg16 mulu_max divs_neg_rem negx_64bit cmpi_l_abs_short_eq cmpi_l_abs_short_ne cmpi_bne_w_not_taken cmpi_bne_w_taken cmpi_b_abs_short_blt movem_save_modify_restore bsr_l_long jmp_d8_pc_dn_w pea_movem_stack subq_sp_movea_write tst_bne_after_bsr_rts tst_bne_after_jsr_an save_clear_slot_restore_tst movea_l_sp_postinc_cov movea_l_postinc_alias movec_cacr_roundtrip cache_init_sequence move_l_neg_disp_a5 sr_barrier_cache_init divs_word_hardfail divu_word_hardfail mull_32_hardfail divl_32_hardfail aslw_mem_hardfail lsrw_mem_hardfail rolw_mem_hardfail ori_sr_hardfail andi_sr_hardfail eori_sr_hardfail move_from_sr_hardfail move_to_sr_hardfail divs_neg_by_neg_edge divs_by_minus_one_edge divs_zero_dividend_edge divs_overflow_edge divu_exact_edge divu_with_remainder_edge divu_overflow_edge mull_unsigned_32 mull_signed_32 divl_unsigned_32 divl_signed_32 asrw_mem_edge roxlw_mem_edge roxrw_mem_edge abcd_99_plus_01_edge sbcd_with_x_edge nbcd_99_edge bfextu_reg_edge bfexts_reg_edge bfffo_reg_edge bfset_reg_edge bfclr_reg_edge bfchg_reg_edge bftst_reg_edge bfins_reg_edge pack_dn_edge pack_predec_a7_alias unpk_dn_edge unpk_predec_a7_alias chk2_w_equal_preserve_ccr chk2_b_areg_fullwidth_d16 chk2_l_wrapped_absl chk2_w_trap_vector6 chk2_w_indexed_inrange chk2_l_fullindexed_inrange chk2_w_pcrel_inrange movep_l_roundtrip sr_ops_combo moves_write_read moves_b_postinc_areg_alias moves_privilege_vector8 fdbcc_false_decrement_branch ftrapcc_true_vector7 ftrapcc_false_operand_lengths cas2_w_success cas2_w_fail_first cas2_w_fail_second cas2_l_success cas2_l_fail_second cas2_l_alias_compare adda_w_cov adda_l_cov adda_w_neg_cov eori_ccr_cov rtr_cov mvr2usp_cov move_b_d16_an_cov move_w_d16_an_cov move_l_d16_an_cov move_l_idx_absw_native move_b_idx_cov move_l_idx_scale_cov move_l_pc_rel_cov move_l_abs_w_cov move_l_abs_l_cov predec_postinc_cov imm_to_mem_b_cov imm_to_mem_w_cov imm_to_mem_l_cov add_b_overflow_cov sub_w_borrow_cov cmp_l_equal_cov and_l_zero_cov or_l_allones_cov eor_self_cov neg_b_overflow_cov not_b_cov odd_addr_cov a7_byte_postinc_cov fuzz_alu_0 fuzz_shift_0 fuzz_bitops_0 fuzz_muldiv_0 fuzz_extswap_0 fuzz_addxsubx_0 fuzz_memrt_0 fuzz_exg_0 fuzz_mixed_0 fuzz_flags_0 fuzz_alu_1 fuzz_shift_1 fuzz_bitops_1 fuzz_muldiv_1 fuzz_extswap_1 fuzz_addxsubx_1 fuzz_memrt_1 fuzz_exg_1 fuzz_mixed_1 fuzz_flags_1 fuzz_alu_2 fuzz_shift_2 fuzz_bitops_2 fuzz_muldiv_2 fuzz_extswap_2 fuzz_addxsubx_2 fuzz_memrt_2 fuzz_exg_2 fuzz_mixed_2 fuzz_flags_2 fuzz_alu_3 fuzz_shift_3 fuzz_bitops_3 fuzz_muldiv_3 fuzz_extswap_3 fuzz_addxsubx_3 fuzz_memrt_3 fuzz_exg_3 fuzz_mixed_3 fuzz_flags_3 fuzz_alu_4 fuzz_shift_4 fuzz_bitops_4 fuzz_muldiv_4 fuzz_extswap_4 fuzz_addxsubx_4 fuzz_memrt_4 fuzz_exg_4 fuzz_mixed_4 fuzz_flags_4 chk_w_in_range chk_w_zero chk_w_equal sbcd_borrow_chain sbcd_zero_zero nbcd_zero_no_x nbcd_with_x bfins_low8 bfins_mid8 movec_vbr_roundtrip movec_sfc_roundtrip movec_dfc_roundtrip mull_u64 mull_s32_neg divl_u32_rem divl_s32_neg divl_u32_max divl_s32_neg_divisor mull_s64_neg divl_same_dq_dr divl_u64 divl_s64 bfins_dreg_imm bfins_dreg_narrow bfins_dreg_wrap bfins_dreg_dyn bfins_dreg_dyn_width32 bfins_mem_span32 bfins_mem_dyn_negative bfins_dreg_boot_alias bfins_mem_dyn_neg_width32 bfins_mem_dyn_pos_width32 oracle_zf_moveq_z1_take oracle_zf_moveq_z0_notake oracle_zf_moveq_z0_take oracle_zf_moveq_z1_notake oracle_zf_tst_z1_take oracle_zf_tst_z0_notake oracle_zf_move_z1_take oracle_zf_move_z0_notake oracle_zf_and_z1_take oracle_zf_and_z0_notake oracle_zf_sub_z1_take oracle_zf_sub_z0_notake oracle_zf_bne_z1_take oracle_zf_bne_z0_notake oracle_zf_mem_take oracle_zf_mem_notake oracle_zf_dbf_preserve_take)
# FPU semantic-service vectors are appended independently so additions remain
# reviewable without rewriting the generated-style master ordering above.
TEST_ORDER+=(fpp_semantic_successor fscc_false_byte fbcc_false_operand_lengths)
# CHK exception-state vectors are kept beside the family audit rather than
# rewriting the generated-style master ordering above.
TEST_ORDER+=(chk_w_negative_trap_n chk_w_upper_trap_n_clear chk_l_negative_trap_n chk_l_upper_trap_n_clear chk_l_in_range_preserve_ccr)
# Deferred arithmetic-exception and DIVL result-alias audit vectors.
TEST_ORDER+=(divu_w_zero_frame divs_w_zero_frame divs_w_overflow_preserve_z divs_w_imm_overflow_preserve_z divu_l_zero_frame divs_l_zero_frame divu_l32_zero_distinct divs_l32_zero_distinct divu_l32_success_nf divs_l32_success_nf divu_l32_same_dq_dr_nf divs_l32_same_dq_dr_nf divu_l32_src_dr_alias_nf divs_l32_src_dr_alias_nf divu_l64_zero_frame divs_l64_zero_frame divu_l64_same_dq_dr divs_l64_same_dq_dr divu_l64_same_dq_dr_nf divs_l64_same_dq_dr_nf divu_l64_overflow divu_l64_overflow_nf divs_l64_overflow divs_l64_overflow_nf divs_l32_overflow divs_l32_overflow_nf trapv_taken_frame trapv_not_taken_preserve)
# Shared SR/control/cache semantic-service coverage.
TEST_ORDER+=(fullsr_orsr_privilege_vector8 fullsr_andsr_privilege_vector8 fullsr_eorsr_privilege_vector8 fullsr_mv2sr_privilege_vector8 fullsr_mvsr_privilege_vector8 system_usp_roundtrip reset_privilege_vector8 usp_privilege_vector8 stop_clear_s_vector8 stop_privilege_vector8 movec_privilege_vector8 rte_privilege_vector8 cache_privilege_vector8 cache_supervisor_successors)
# Exact-PC bitfield service coverage spans every operation and each legal EA decoder.
TEST_ORDER+=(bitfield_mem_an_family bitfield_d16_an bitfield_indexed_an bitfield_absw bitfield_absl bitfield_pc_d16 bitfield_pc_indexed)
TEST_ORDER+=(cas_b_success cas_b_fail cas_b_predec cas_w_postinc cas_l_d16 moves_predec_store_alias moves_predec_read_alias moves_l_indexed_store)
# Register-count ROX must copy unchanged X into C when the effective ring count is zero.
# Cover both directions and all widths, including each width's deepest low-six-bit
# modulo-reduction path, the unreduced source-count-zero path, and both directions
# with the remaining guest register mappings populated before the rotate.
TEST_ORDER+=(roxl_b_reg_count_63_copies_x roxr_b_reg_count_63_copies_x roxl_w_reg_count_51_copies_x roxr_w_reg_count_51_copies_x roxl_l_reg_count_33_copies_x roxr_l_reg_count_33_copies_x roxl_l_reg_count_0_copies_x roxr_reg_count_0_copies_x roxl_l_reg_count_33_pressure roxr_l_reg_count_33_pressure)
# Register-count AS/LS effective-zero paths must preserve X while clearing C/V
# and deriving N/Z from the unchanged size-specific result.
TEST_ORDER+=(asl_b_reg_count_0_preserves_x asl_w_reg_count_0_preserves_x asl_l_reg_count_0_preserves_x asr_b_reg_count_0_preserves_x asr_w_reg_count_0_preserves_x asr_l_reg_count_0_preserves_x asr_l_reg_count0_pressure_preserves_x lsl_b_reg_count_0_preserves_x lsl_w_reg_count_0_preserves_x lsl_l_reg_count_0_preserves_x lsr_b_reg_count_0_preserves_x lsr_w_reg_count_0_preserves_x lsr_l_reg_count_0_preserves_x)
# Register-count shift boundaries must use the guest low-six-bit count without
# wrapping count 32 through AArch64 W-form variable shifts.
TEST_ORDER+=(asl_b_reg_count32_boundary asl_w_reg_count32_boundary asl_l_reg_count32_boundary asl_l_reg_zero_count32_v_clear asl_l_reg_zero_count32_const_v_clear asl_b_reg_zero_count63_v_clear asl_w_reg_zero_count33_v_clear asr_b_reg_count32_boundary asr_w_reg_count32_boundary asr_l_reg_count32_boundary lsl_b_reg_count32_boundary lsl_w_reg_count32_boundary lsl_l_reg_count32_boundary lsr_b_reg_count32_boundary lsr_w_reg_count32_boundary lsr_l_reg_count32_boundary lsr_l_reg_count33_boundary lsr_l_reg_const_count32)
# ROL/ROR use the low six register-count bits even though the rotation result
# itself is periodic at the operand width. Cover zero, both sides of 32, the
# maximal six-bit count, both flag lifecycles, and legal count/data aliasing.
declare -a ROTATE_REGISTER_MATRIX_NAMES=()
for _rotate_op in rol ror; do
    for _rotate_width in b w l; do
        for _rotate_count in 0 31 32 33 63; do
            _rotate_name="${_rotate_op}_${_rotate_width}_reg_count${_rotate_count}_boundary"
            ROTATE_REGISTER_MATRIX_NAMES+=("$_rotate_name" "${_rotate_name}_nf")
            TEST_ORDER+=("$_rotate_name" "${_rotate_name}_nf")
        done
        _rotate_alias_name="${_rotate_op}_${_rotate_width}_reg_same_count_data"
        ROTATE_REGISTER_MATRIX_NAMES+=("$_rotate_alias_name" "${_rotate_alias_name}_nf")
        TEST_ORDER+=("$_rotate_alias_name" "${_rotate_alias_name}_nf")
    done
done
unset _rotate_op _rotate_width _rotate_count _rotate_name _rotate_alias_name
TEST_ORDER+=(rol_l_reg_const_count64 rol_l_reg_const_count64_nf ror_l_reg_const_count64 ror_l_reg_const_count64_nf)
TEST_ORDER+=(rol_b_imm_count8 rol_b_imm_count8_nf rol_w_imm_count8 rol_w_imm_count8_nf rol_l_imm_count8 rol_l_imm_count8_nf)
TEST_ORDER+=(ror_b_imm_count8 ror_b_imm_count8_nf ror_w_imm_count8 ror_w_imm_count8_nf ror_l_imm_count8 ror_l_imm_count8_nf)
TEST_ORDER+=(rolw_mem_native rolw_mem_native_nf rorw_mem_native rorw_mem_native_nf)
TEST_ORDER+=(aslw_mem_native aslw_mem_native_nf asrw_mem_native asrw_mem_native_nf lslw_mem_native lslw_mem_native_nf lsrw_mem_native lsrw_mem_native_nf)
TEST_ORDER+=(roxlw_mem_x_native roxrw_mem_x_native)
TEST_ORDER+=(asl_b_reg_count32_nf asl_w_reg_count32_nf asl_l_reg_count32_nf asr_b_reg_count32_nf asr_w_reg_count32_nf asr_l_reg_count32_nf lsl_b_reg_count32_nf lsl_w_reg_count32_nf lsl_l_reg_count32_nf lsr_b_reg_count32_nf lsr_w_reg_count32_nf lsr_l_reg_count32_nf)
TEST_ORDER+=(asl_b_reg_same_count_data asl_w_reg_same_count_data asl_l_reg_same_count_data asr_b_reg_same_count_data asr_w_reg_same_count_data asr_l_reg_same_count_data lsl_b_reg_same_count_data lsl_w_reg_same_count_data lsl_l_reg_same_count_data lsr_b_reg_same_count_data lsr_w_reg_same_count_data lsr_l_reg_same_count_data)
TEST_ORDER+=(asl_b_reg_same_count_data_nf asl_w_reg_same_count_data_nf asl_l_reg_same_count_data_nf asr_b_reg_same_count_data_nf asr_w_reg_same_count_data_nf asr_l_reg_same_count_data_nf lsl_b_reg_same_count_data_nf lsl_w_reg_same_count_data_nf lsl_l_reg_same_count_data_nf lsr_b_reg_same_count_data_nf lsr_w_reg_same_count_data_nf lsr_l_reg_same_count_data_nf)
# Adjacent and maximal low-six-bit counts close both sides of the count-32
# boundary.  Generate the regular/no-flags family matrix from one inventory so
# an opcode or width cannot silently drop out of one lifecycle.
declare -a SHIFT_BOUNDARY_MATRIX_NAMES=()
for _shift_op in asl asr lsl lsr; do
    for _shift_width in b w l; do
        for _shift_count in 31 33 63; do
            _shift_name="${_shift_op}_${_shift_width}_reg_count${_shift_count}_boundary"
            SHIFT_BOUNDARY_MATRIX_NAMES+=("$_shift_name" "${_shift_name}_nf")
            if [ "$_shift_name" != "lsr_l_reg_count33_boundary" ]; then
                TEST_ORDER+=("$_shift_name")
            fi
            TEST_ORDER+=("${_shift_name}_nf")
        done
    done
done
unset _shift_op _shift_width _shift_count _shift_name
TEST_ORDER+=(addx_b_same_reg_consumes_x addx_w_same_reg_consumes_x addx_l_same_reg_consumes_x subx_b_same_reg_consumes_x subx_w_same_reg_consumes_x subx_l_same_reg_consumes_x)
TEST_ORDER+=(addx_b_distinct_reg_consumes_x addx_w_distinct_reg_consumes_x addx_l_distinct_reg_consumes_x subx_b_distinct_reg_consumes_x subx_w_distinct_reg_consumes_x subx_l_distinct_reg_consumes_x)
TEST_ORDER+=(addx_b_zero_sticky_z_set addx_w_zero_sticky_z_set addx_l_zero_sticky_z_set addx_b_zero_without_x_sticky_z_set addx_w_zero_without_x_sticky_z_set addx_l_zero_without_x_sticky_z_set roxl_l_zero_count_copies_cleared_x subx_b_zero_sticky_z_set subx_w_zero_sticky_z_set subx_l_zero_sticky_z_set)
TEST_ORDER+=(addx_b_zero_sticky_z_clear addx_w_zero_sticky_z_clear addx_l_zero_sticky_z_clear subx_b_zero_sticky_z_clear subx_w_zero_sticky_z_clear subx_l_zero_sticky_z_clear)
TEST_ORDER+=(addx_b_overflow_with_x addx_w_overflow_with_x addx_l_overflow_with_x subx_b_overflow_with_x subx_w_overflow_with_x subx_l_overflow_with_x subx_b_without_x subx_w_without_x subx_l_without_x)
# ADD is a two-operand arithmetic/RMW family. Audit width-edge NZVCX, constant
# and register lowering, self aliases, nominal no-flags handlers, every readable
# source and writable destination EA, A7 byte geometry, special memory, and exact
# native entry. MIDFUNC operand ownership spans arithmetic; memory destinations
# additionally retain their private pre-write EA through X publication/store.
declare -a ADD_NATIVE_MATRIX_NAMES=(
    add_core_b_reg_zero_native add_core_w_reg_overflow_native add_core_l_reg_carry_native
    add_core_b_self_alias_native add_core_w_self_alias_native add_core_l_self_alias_native
    add_core_b_imm_overflow_native add_core_w_imm_carry_native
    add_core_l_imm_large_native add_core_l_imm_negative_native
    add_core_b_reg_noflags_native add_core_w_reg_noflags_native add_core_l_reg_noflags_native
    add_core_b_aind_source_special_native add_core_w_postinc_source_native
    add_core_l_predec_source_native add_core_b_d16_source_native
    add_core_w_index_source_special_native add_core_l_absw_source_native
    add_core_b_absl_source_special_native add_core_w_pc16_source_native
    add_core_l_pcindex_source_native
    add_core_b_aind_dest_special_native add_core_w_postinc_dest_native
    add_core_l_predec_dest_native add_core_b_d16_dest_native
    add_core_w_index_dest_special_native add_core_l_absw_dest_native
    add_core_b_absl_dest_special_native add_core_b_a7_postinc_dest_native
    add_core_b_a7_predec_dest_native add_core_b_addi_postinc_dest_native
    add_core_b_postinc_dest_native add_core_b_postinc_dest_noflags_native
)
TEST_ORDER+=("${ADD_NATIVE_MATRIX_NAMES[@]}")
# AND is a width-sensitive logical/RMW family. Audit N/Z, mandatory V/C clear,
# X preservation, constant and register routes, self aliases, no-flags handlers,
# every readable source and writable destination EA, special memory, exact PC,
# and ownership of the original memory destination through the ordered store.
declare -a AND_NATIVE_MATRIX_NAMES=(
    and_core_b_reg_zero_native and_core_w_reg_negative_native and_core_l_reg_positive_native
    and_core_b_self_alias_native and_core_w_self_alias_native and_core_l_self_alias_native
    and_core_b_imm_zero_native and_core_w_imm_negative_native
    and_core_l_imm_pattern_native and_core_l_imm_negative_native
    and_core_b_reg_noflags_native and_core_w_reg_noflags_native and_core_l_reg_noflags_native
    and_core_b_aind_source_special_native and_core_w_postinc_source_native
    and_core_l_predec_source_native and_core_b_d16_source_native
    and_core_w_index_source_special_native and_core_l_absw_source_native
    and_core_b_absl_source_special_native and_core_w_pc16_source_native
    and_core_l_pcindex_source_native
    and_core_b_aind_dest_special_native and_core_w_postinc_dest_native
    and_core_l_predec_dest_native and_core_b_d16_dest_native
    and_core_w_index_dest_special_native and_core_l_absw_dest_native
    and_core_b_absl_dest_special_native and_core_b_a7_postinc_dest_native
    and_core_b_a7_predec_dest_native and_core_b_andi_postinc_dest_native
    and_core_b_postinc_dest_native and_core_b_postinc_dest_noflags_native
)
TEST_ORDER+=("${AND_NATIVE_MATRIX_NAMES[@]}")
# EOR is a width-sensitive logical/RMW family with Dn or immediate sources.
# Audit N/Z, mandatory V/C clear, X preservation, all twelve flag-live/no-flags
# MIDFUNC routes, source/destination aliases, every writable destination EA,
# special memory, A7 byte geometry, and pre-write EA ownership.
declare -a EOR_NATIVE_MATRIX_NAMES=(
    eor_core_b_reg_zero_native eor_core_w_reg_negative_native eor_core_l_reg_positive_native
    eor_core_b_self_alias_native eor_core_w_self_alias_native eor_core_l_self_alias_native
    eor_core_b_imm_zero_native eor_core_w_imm_negative_native
    eor_core_l_imm_pattern_native eor_core_l_imm_negative_native
    eor_core_b_reg_noflags_native eor_core_w_reg_noflags_native eor_core_l_reg_noflags_native
    eor_core_b_imm_noflags_native eor_core_w_imm_noflags_native eor_core_l_imm_noflags_native
    eor_core_b_aind_dest_special_native eor_core_w_postinc_dest_native
    eor_core_l_predec_dest_native eor_core_b_d16_dest_native
    eor_core_w_index_dest_special_native eor_core_l_absw_dest_native
    eor_core_b_absl_dest_special_native eor_core_b_a7_postinc_dest_native
    eor_core_b_a7_predec_dest_native eor_core_b_eori_postinc_dest_native
    eor_core_b_postinc_dest_native eor_core_b_postinc_dest_noflags_native
)
TEST_ORDER+=("${EOR_NATIVE_MATRIX_NAMES[@]}")
# OR is the complete two-direction logical/RMW family. Audit N/Z, mandatory
# V/C clear, X preservation, all twelve flag-live/no-flags MIDFUNC routes,
# aliases, every readable source and writable destination EA, special memory,
# A7 byte geometry, and source/pre-write-EA allocator ownership.
declare -a OR_NATIVE_MATRIX_NAMES=(
    or_core_b_reg_zero_native or_core_w_reg_negative_native or_core_l_reg_positive_native
    or_core_b_self_alias_native or_core_w_self_alias_native or_core_l_self_alias_native
    or_core_b_imm_zero_native or_core_w_imm_negative_native
    or_core_l_imm_pattern_native or_core_l_imm_negative_native
    or_core_b_reg_noflags_native or_core_w_reg_noflags_native or_core_l_reg_noflags_native
    or_core_b_imm_noflags_native or_core_w_imm_noflags_native or_core_l_imm_noflags_native
    or_core_b_aind_source_special_native or_core_w_postinc_source_native
    or_core_l_predec_source_native or_core_b_d16_source_native
    or_core_w_index_source_special_native or_core_l_absw_source_native
    or_core_b_absl_source_special_native or_core_w_pc16_source_native
    or_core_l_pcindex_source_native
    or_core_b_aind_dest_special_native or_core_w_postinc_dest_native
    or_core_l_predec_dest_native or_core_b_d16_dest_native
    or_core_w_index_dest_special_native or_core_l_absw_dest_native
    or_core_b_absl_dest_special_native or_core_b_a7_postinc_dest_native
    or_core_b_a7_predec_dest_native or_core_b_ori_postinc_dest_native
    or_core_b_postinc_dest_native or_core_b_postinc_dest_noflags_native
)
TEST_ORDER+=("${OR_NATIVE_MATRIX_NAMES[@]}")
# SUB is a two-operand arithmetic/RMW family. Audit width-edge NZVCX, all
# twelve register/immediate flag-live/no-flags routes, aliases, every readable
# source and writable destination EA, special memory, A7 byte geometry, and
# source/pre-write-EA allocator ownership.
declare -a SUB_NATIVE_MATRIX_NAMES=(
    sub_core_b_reg_zero_native sub_core_w_reg_overflow_native sub_core_l_reg_borrow_native
    sub_core_b_self_alias_native sub_core_w_self_alias_native sub_core_l_self_alias_native
    sub_core_b_imm_overflow_native sub_core_w_imm_borrow_native
    sub_core_l_imm_large_native sub_core_l_imm_negative_native
    sub_core_b_reg_noflags_native sub_core_w_reg_noflags_native sub_core_l_reg_noflags_native
    sub_core_b_imm_noflags_native sub_core_w_imm_noflags_native sub_core_l_imm_noflags_native
    sub_core_b_aind_source_special_native sub_core_w_postinc_source_native
    sub_core_l_predec_source_native sub_core_b_d16_source_native
    sub_core_w_index_source_special_native sub_core_l_absw_source_native
    sub_core_b_absl_source_special_native sub_core_w_pc16_source_native
    sub_core_l_pcindex_source_native
    sub_core_b_aind_dest_special_native sub_core_w_postinc_dest_native
    sub_core_l_predec_dest_native sub_core_b_d16_dest_native
    sub_core_w_index_dest_special_native sub_core_l_absw_dest_native
    sub_core_b_absl_dest_special_native sub_core_b_a7_postinc_dest_native
    sub_core_b_a7_predec_dest_native sub_core_b_subi_postinc_dest_native
    sub_core_b_postinc_dest_native sub_core_b_postinc_dest_noflags_native
)
TEST_ORDER+=("${SUB_NATIVE_MATRIX_NAMES[@]}")
# ADDA consumes a word (sign-extended) or long source, updates a full 32-bit
# address register modulo 2^32, and preserves XNZVC. Audit dynamic and constant
# source/destination lowering, all source EAs, same-register/update aliases,
# nominal no-flags selection, maximum register fields, and exact native entry.
declare -a ADDA_NATIVE_MATRIX_NAMES=(
    adda_core_w_dreg_positive_native adda_core_w_dreg_negative_native
    adda_core_l_dreg_wrap_native adda_core_w_areg_alias_native
    adda_core_l_areg_alias_native adda_core_w_max_fields_native
    adda_core_w_imm_small_positive_native adda_core_w_imm_small_negative_native
    adda_core_w_imm_large_positive_native adda_core_w_imm_large_negative_native
    adda_core_l_imm_small_positive_native adda_core_l_imm_small_negative_native
    adda_core_l_imm_large_positive_native adda_core_l_imm_large_negative_native
    adda_core_w_const_dst_wrap adda_core_l_const_dst_wrap
    adda_core_w_aind_alias_native adda_core_w_postinc_alias_native
    adda_core_w_predec_alias_native adda_core_l_postinc_alias_native
    adda_core_l_predec_alias_native adda_core_w_d16_source_native
    adda_core_w_index_source_special_native adda_core_l_absw_source_native
    adda_core_w_absl_source_special_native adda_core_w_pc16_source_native
    adda_core_l_pcindex_source_native adda_core_w_dreg_noflags_native
    adda_core_l_dreg_noflags_native
)
TEST_ORDER+=("${ADDA_NATIVE_MATRIX_NAMES[@]}")
# NEG is lowered through shared SUB flags plus an explicit zero destination.
# Audit every width and arithmetic edge, no-flags selection, each writable EA,
# A7 byte geometry, normal/special memory, and exact native entry.
declare -a NEG_NATIVE_MATRIX_NAMES=(
    neg_b_zero_native neg_w_zero_native neg_l_zero_native
    neg_b_one_native neg_w_one_native neg_l_one_native
    neg_b_min_overflow_native neg_w_min_overflow_native neg_l_min_overflow_native
    neg_b_minus_one_native neg_w_minus_one_native neg_l_minus_one_native
    neg_b_min_nf_native neg_w_min_nf_native neg_l_min_nf_native
    neg_b_aind_special_native neg_w_postinc_native neg_l_predec_native
    neg_b_d16_native neg_w_indexed_special_native neg_l_absw_native
    neg_b_absl_special_native neg_b_a7_postinc_native neg_b_a7_predec_native
)
TEST_ORDER+=("${NEG_NATIVE_MATRIX_NAMES[@]}")
# NEGX is generated through the shared SUBX flag lifecycle, not through the
# unreachable jff_/jnf_NEGX_* legacy MIDFUNC names.  Audit every width across
# incoming X/sticky-Z quadrants, signed-overflow minima, each memory-EA class,
# A7 byte geometry, forced special-memory helpers, and exact native entry.
declare -a NEGX_NATIVE_MATRIX_NAMES=(
    negx_b_zero_x0_z1_native negx_w_zero_x0_z1_native negx_l_zero_x0_z1_native
    negx_b_zero_x0_z0_native negx_w_zero_x0_z0_native negx_l_zero_x0_z0_native
    negx_b_zero_x1_z1_native negx_w_zero_x1_z1_native negx_l_zero_x1_z1_native
    negx_b_min_x0_overflow_native negx_w_min_x0_overflow_native negx_l_min_x0_overflow_native
    negx_b_min_x1_native negx_w_min_x1_native negx_l_min_x1_native
    negx_b_min_x1_nf_native negx_w_min_x1_nf_native negx_l_min_x1_nf_native
    negx_b_aind_special_native negx_w_postinc_native negx_l_predec_native
    negx_b_d16_native negx_w_indexed_special_native negx_l_absw_native
    negx_b_absl_special_native negx_b_a7_postinc_native negx_b_a7_predec_native
)
TEST_ORDER+=("${NEGX_NATIVE_MATRIX_NAMES[@]}")
# TAS is a mandatory flag-live byte RMW family.  Sample flags from the original
# byte before setting bit 7, preserve X and Dn upper lanes, then prove every
# writable EA, A7 byte geometry, and normal/special-memory writeback natively.
declare -a TAS_NATIVE_MATRIX_NAMES=(
    tas_b_d0_zero_x0_native tas_b_d0_zero_x1_native
    tas_b_d0_positive_x1_native tas_b_d0_negative_x0_native
    tas_b_aind_special_native tas_b_postinc_native tas_b_predec_native
    tas_b_d16_native tas_b_indexed_special_native tas_b_absw_native
    tas_b_absl_special_native tas_b_a7_postinc_native tas_b_a7_predec_native
)
TEST_ORDER+=("${TAS_NATIVE_MATRIX_NAMES[@]}")
# MOVE owns a fetched source through destination allocation, flags and storage.
# Cover every source/destination EA class, all widths, narrow-lane preservation,
# same-register/base aliases, A7 byte geometry, immediate/constant lowering,
# normal and forced-special memory, and exact native entry.
declare -a MOVE_NATIVE_MATRIX_NAMES=(
    move_core_b_reg_negative_native move_core_b_reg_zero_native
    move_core_w_reg_negative_native move_core_w_reg_zero_native
    move_core_l_reg_negative_native move_core_l_reg_zero_native
    move_core_b_self_alias_native move_core_w_self_alias_native
    mov_l_rr_self_native
    move_core_b_imm_negative_native move_core_w_imm_negative_native
    move_core_l_imm_zero_native
    move_core_b_aind_to_dn_special_native move_core_w_postinc_to_dn_native
    move_core_l_predec_to_dn_native move_core_b_d16_to_dn_native
    move_core_w_index_to_dn_special_native move_core_l_absw_to_dn_native
    move_core_b_absl_to_dn_special_native move_core_w_pc16_to_dn_native
    move_core_l_pcindex_to_dn_native
    move_core_b_dn_to_aind_special_native move_core_w_dn_to_postinc_native
    move_core_l_dn_to_predec_native move_core_b_dn_to_d16_native
    move_core_w_dn_to_index_special_native move_core_l_dn_to_absw_native
    move_core_b_dn_to_absl_special_native move_core_l_areg_postinc_alias_native
    move_core_l_memmem_postinc_alias_native move_core_b_a7_postinc_dst_native
    move_core_b_a7_postinc_src_native
)
TEST_ORDER+=("${MOVE_NATIVE_MATRIX_NAMES[@]}")
# MOVEA never publishes flags. Word sources sign-extend to 32 bits; source EA
# writeback precedes the destination assignment, so same-An aliases deliberately
# let the assignment win.
declare -a MOVEA_NATIVE_MATRIX_NAMES=(
    movea_core_w_dreg_native movea_core_w_imm_native movea_core_l_dreg_native
    mov_l_rr_const_movea_native
    movea_core_w_aind_special_native movea_core_w_postinc_alias_native
    movea_core_w_predec_alias_native movea_core_l_postinc_alias_native
    movea_core_l_a7_postinc_native movea_core_w_index_special_native
    movea_core_w_pc16_native
)
TEST_ORDER+=("${MOVEA_NATIVE_MATRIX_NAMES[@]}")
# MOVE16 is a distinct no-flags 16-byte transaction. Exercise all five encodings,
# aligned-address masking, postincrement aliases, direct and special-memory paths.
declare -a MOVE16_NATIVE_MATRIX_NAMES=(
    move16_core_postinc_to_absl_native move16_core_absl_to_postinc_native
    move16_core_aind_to_absl_native move16_core_absl_to_aind_native
    move16_core_postpost_distinct_native move16_core_postpost_same_native
    move16_core_postpost_special_native
)
TEST_ORDER+=("${MOVE16_NATIVE_MATRIX_NAMES[@]}")
# Scc consumes but never changes CCR. Pair all sixteen conditions in Dn form,
# then exercise every writable memory EA, An/A7 byte geometry, special-memory
# routing, upper-lane retention, and exact native entry.
declare -a SCC_NATIVE_MATRIX_NAMES=(
    scc_core_tf_dreg_native scc_core_hi_ls_dreg_native
    scc_core_cc_cs_dreg_native scc_core_ne_eq_dreg_native
    scc_core_vc_vs_dreg_native scc_core_pl_mi_dreg_native
    scc_core_ge_lt_dreg_native scc_core_gt_le_dreg_native
    scc_core_aind_hi_special_native scc_core_postinc_t_native
    scc_core_predec_f_native scc_core_d16_eq_native
    scc_core_index_vs_special_native scc_core_absw_mi_native
    scc_core_absl_gt_special_native scc_core_a7_postinc_t_native
    scc_core_a7_predec_f_native
)
TEST_ORDER+=("${SCC_NATIVE_MATRIX_NAMES[@]}")
# Bcc consumes but never changes CCR. Exercise every reachable condition in
# both directions at an exact native entry, then cover BRA and signed backward
# branches across byte, word, and long displacement decoding.
declare -a BCC_NATIVE_MATRIX_NAMES=(
    bcc_core_hi_taken_b_native bcc_core_hi_not_taken_b_native
    bcc_core_ls_taken_b_native bcc_core_ls_not_taken_b_native
    bcc_core_cc_taken_b_native bcc_core_cc_not_taken_b_native
    bcc_core_cs_taken_b_native bcc_core_cs_not_taken_b_native
    bcc_core_ne_taken_b_native bcc_core_ne_not_taken_b_native
    bcc_core_eq_taken_b_native bcc_core_eq_not_taken_b_native
    bcc_core_vc_taken_b_native bcc_core_vc_not_taken_b_native
    bcc_core_vs_taken_b_native bcc_core_vs_not_taken_b_native
    bcc_core_pl_taken_b_native bcc_core_pl_not_taken_b_native
    bcc_core_mi_taken_b_native bcc_core_mi_not_taken_b_native
    bcc_core_ge_taken_b_native bcc_core_ge_not_taken_b_native
    bcc_core_lt_taken_b_native bcc_core_lt_not_taken_b_native
    bcc_core_gt_taken_b_native bcc_core_gt_not_taken_b_native
    bcc_core_le_taken_b_native bcc_core_le_not_taken_b_native
    bcc_core_bra_b_forward_native bcc_core_bra_w_forward_native
    bcc_core_bra_l_forward_native bcc_core_bne_b_backward_native
    bcc_core_bne_w_backward_native bcc_core_bne_l_backward_native
)
TEST_ORDER+=("${BCC_NATIVE_MATRIX_NAMES[@]}")
# CLR writes zero without reading the previous operand, preserves upper Dn lanes
# at byte/word widths, and publishes X=old, N=V=C=0, Z=1 after memory storage.
declare -a CLR_NATIVE_MATRIX_NAMES=(
    clr_core_b_dreg_native clr_core_w_dreg_native clr_core_l_dreg_native
    clr_core_b_aind_special_native clr_core_w_postinc_native
    clr_core_l_predec_native clr_core_b_d16_native
    clr_core_w_index_special_native clr_core_l_absw_native
    clr_core_b_absl_special_native clr_core_b_a7_postinc_native
    clr_core_b_a7_predec_native clr_core_b_postinc_successor_bne_native
    clr_core_w_dreg_noflags_native clr_core_l_postinc_noflags_native
)
TEST_ORDER+=("${CLR_NATIVE_MATRIX_NAMES[@]}")
# EXG performs a simultaneous full-width register exchange without touching CCR.
# Cover every encoding class, same-register aliases, maximum fields, roundtrips,
# exact native entry, and a no-flags-table successor.
declare -a EXG_NATIVE_MATRIX_NAMES=(
    exg_core_dn_dn_native exg_core_an_an_native exg_core_dn_an_native
    exg_core_dn_dn_self_native exg_core_an_an_self_native
    exg_core_dn_dn_max_native exg_core_an_an_max_native
    exg_core_dn_an_max_native exg_core_dn_dn_roundtrip_native
    exg_core_an_an_roundtrip_native exg_core_dn_an_roundtrip_native
    exg_core_dn_an_noflags_native
)
TEST_ORDER+=("${EXG_NATIVE_MATRIX_NAMES[@]}")
# EXT.W, EXT.L, and EXTB.L sign-extend within Dn, publish logical flags, and
# preserve only EXT.W's upper word. Cover negative/zero/positive, max fields,
# exact native entry, and all three no-flags-table routes.
declare -a EXT_NATIVE_MATRIX_NAMES=(
    ext_core_w_negative_native ext_core_w_zero_native ext_core_w_positive_native
    ext_core_w_max_native ext_core_l_negative_native ext_core_l_zero_native
    ext_core_l_positive_native ext_core_l_max_native
    extb_core_l_negative_native extb_core_l_zero_native
    extb_core_l_positive_native extb_core_l_max_native
    ext_core_wl_chain_negative_native
    ext_core_w_noflags_native ext_core_l_noflags_native extb_core_l_noflags_native
)
TEST_ORDER+=("${EXT_NATIVE_MATRIX_NAMES[@]}")
# DBcc is a flags-preserving dynamic block edge. Cover DBT, DBF terminal/branch/
# wrap states and both members of every conditional pair, with upper-word,
# displacement, successor, and exact native evidence.
declare -a DBCC_NATIVE_MATRIX_NAMES=(
    dbcc_core_dbt_true_native
    dbcc_core_dbf_terminal_native dbcc_core_dbf_branch_native dbcc_core_dbf_wrap_native
    dbcc_core_hi_true_native dbcc_core_ls_false_branch_native
    dbcc_core_cc_true_native dbcc_core_cs_false_branch_native
    dbcc_core_ne_true_native dbcc_core_eq_false_branch_native
    dbcc_core_vc_true_native dbcc_core_vs_false_branch_native
    dbcc_core_pl_true_native dbcc_core_mi_false_branch_native
    dbcc_core_ge_true_native dbcc_core_lt_false_branch_native
    dbcc_core_gt_true_native dbcc_core_le_false_branch_native
)
TEST_ORDER+=("${DBCC_NATIVE_MATRIX_NAMES[@]}")
# Complete classic bit-operation lifecycle: long Dn versus byte memory width,
# dynamic/immediate modulo counts, original-bit Z, aliases, no-flags lowering,
# every writable EA, A7 geometry, special memory, and exact native entry.
declare -a BITOP_NATIVE_MATRIX_NAMES=(
    bitop_core_btst_dyn_l_count63_native bitop_core_btst_imm_l_count63_native
    bitop_core_bchg_dyn_l_alias_native bitop_core_bchg_imm_l_bit31_native
    bitop_core_bclr_dyn_l_count32_native bitop_core_bclr_imm_l_bit31_noflags_native
    bitop_core_bset_dyn_l_count63_native bitop_core_bset_imm_l_bit0_native
    bitop_core_bchg_dyn_l_distinct_native bitop_core_bset_dyn_l_alias_native
    bitop_core_bchg_imm_aind_zero_special_native bitop_core_bchg_imm_aind_one_native
    bitop_core_bclr_dyn_postinc_zero_native bitop_core_bclr_dyn_predec_one_native
    bitop_core_bset_imm_d16_zero_native bitop_core_bset_dyn_index_one_special_native
    bitop_core_bchg_dyn_absw_zero_native bitop_core_bclr_imm_absl_one_special_native
    bitop_core_bset_dyn_a7_postinc_zero_native bitop_core_bchg_dyn_a7_predec_one_native
    bitop_core_btst_dyn_aind_set_special_native bitop_core_btst_imm_d16_zero_native
    bitop_core_bchg_imm_aind_noflags_native
    bitop_core_bset_imm_pc_d16_zero_native bitop_core_bclr_dyn_pc_index_one_native
    bitop_core_btst_imm_pc_d16_set_native bitop_core_btst_dyn_pc_index_zero_native
    bitop_core_btst_imm_destination_zero_native bitop_core_btst_dyn_destination_set_native
)
TEST_ORDER+=("${BITOP_NATIVE_MATRIX_NAMES[@]}")
# Complete live compare lifecycle: CMP/CMPI/CMPM/CMPA share jff_CMP_{b,w,l}
# after EA fetch and CMPA widening. Cover constants, aliases, all widths,
# ordered dual-memory reads/writeback, no-flags access semantics, and X/NZVC.
declare -a CMP_NATIVE_MATRIX_NAMES=(
    cmp_core_b_reg_borrow_native cmp_core_w_reg_overflow_native
    cmp_core_l_reg_alias_equal_native cmp_core_b_imm_const_overflow_native
    cmp_core_w_imm_runtime_overflow_native cmp_core_l_imm_const_overflow_native
    cmp_core_l_reg_distinct_borrow_native cmp_core_b_aind_special_native
    cmp_core_w_postinc_native cmp_core_l_predec_native cmp_core_b_d16_native
    cmp_core_w_index_special_native cmp_core_l_absw_native
    cmp_core_b_absl_special_native cmp_core_w_pc_d16_native
    cmp_core_l_pc_index_native cmp_core_b_postinc_noflags_native
    cmpm_core_b_distinct_native cmpm_core_w_distinct_native
    cmpm_core_l_distinct_native cmpm_core_b_same_a0_native
    cmpm_core_b_same_a7_native cmpm_core_w_special_native
    cmpm_core_l_noflags_native cmpa_core_w_imm_negative_native
    cmpa_core_w_postinc_alias_native cmpa_core_w_d16_negative_native
    cmpa_core_l_areg_alias_native cmpa_core_l_aind_special_native
    cmpa_core_w_pc_index_native cmpa_core_l_postinc_noflags_native
)
TEST_ORDER+=("${CMP_NATIVE_MATRIX_NAMES[@]}")
# Immediate-to-CCR values are compile-time guest immediates, not JIT virtual-register IDs.
# Cover each logical operation, all five CCR bits, preservation/toggling, and entry
# from the subtraction carry-inverted lifecycle.
TEST_ORDER+=(ccr_ori_exact_bits ccr_andi_exact_mask ccr_eori_exact_toggle ccr_ori_after_borrow_flags ccr_andi_after_borrow_flags ccr_eori_after_borrow_flags)
# BCD arithmetic is one lifecycle family: C is copied to X, Z is sticky,
# data-register aliases consume the pre-write source, and byte predecrement
# uses the architectural two-byte A7 stride for each source/destination access.
TEST_ORDER+=(bcd_abcd_zero_sticky_set bcd_abcd_zero_sticky_clear bcd_abcd_nonzero_clears_sticky bcd_abcd_carry_zero bcd_abcd_same_reg_with_x)
TEST_ORDER+=(bcd_sbcd_zero_sticky_set bcd_sbcd_zero_sticky_clear bcd_sbcd_borrow bcd_sbcd_same_reg_with_x)
TEST_ORDER+=(bcd_nbcd_zero_sticky_set bcd_nbcd_zero_sticky_clear bcd_nbcd_nonzero bcd_nbcd_with_x)
TEST_ORDER+=(bcd_abcd_decimal_09_plus_01 bcd_abcd_invalid_nibble_exact bcd_abcd_extend_chain)
TEST_ORDER+=(bcd_sbcd_decimal_10_minus_01 bcd_sbcd_invalid_nibble_exact bcd_nbcd_decimal_10 bcd_nbcd_invalid_nibble_exact)
TEST_ORDER+=(bcd_native_abcd_zero_sticky bcd_native_abcd_invalid_extend bcd_native_sbcd_invalid_borrow bcd_native_nbcd_invalid_borrow)
TEST_ORDER+=(bcd_abcd_predec_src_a7 bcd_abcd_predec_dst_a7 bcd_abcd_predec_a7_alias bcd_sbcd_predec_src_a7 bcd_sbcd_predec_dst_a7 bcd_sbcd_predec_a7_alias bcd_nbcd_predec_a7)
# MULL closure vectors cover signed 32-bit overflow publication plus the
# source/result ownership and legal alias matrix for 64-bit results.
TEST_ORDER+=(mulls32_negative_fit_v_native mullu64_source_preserve_v_native mullu64_source_low_alias_native mullu64_same_result_alias_native)
TEST_ORDER+=(mullu32_low_sign_full_flags_native mullu32_overflow_low_zero_flags_native mulls32_negative_overflow_low_zero_native mulls32_positive_overflow_low_sign_native)
TEST_ORDER+=(mulls64_negative_flags_native mullu64_zero_flags_native mullu64_source_high_alias_native mullu64_all_alias_native mullu32_immediate_nf_native mullu64_memory_nf_native)
# MOVEM is a generator-owned lifecycle, not the four unreachable legacy MIDFUNCs.
# Cover both widths, all update modes, base-in-mask ownership, all-live pressure,
# forced special-memory helpers, zero masks, and the complete control-EA set.
TEST_ORDER+=(movem_l_postinc_base_alias_native movem_w_postinc_base_alias_native)
TEST_ORDER+=(movem_l_predec_base_alias_native movem_w_predec_base_alias_native)
TEST_ORDER+=(movem_l_aind_load_base_alias_native movem_l_aind_store_base_alias_native)
TEST_ORDER+=(movem_l_all_live_roundtrip_native movem_l_all_live_special_native)
TEST_ORDER+=(movem_zero_mask_native movem_l_control_modes_native movem_l_pc_modes_native)

declare -A TESTS
declare -A EXPECTED_D0
declare -A EXPECTED_REG_FIELDS
# Optional RAM-relative address/byte pairs installed before the first pass and,
# unless NATIVE_REPLAY_BYTES overrides them, restored before every exact replay.
declare -A TEST_MEMORY_BYTES
declare -A SPECIAL_MEMORY_TESTS=(
    [movem_l_all_live_special_native]=1
)
# Tests in this set replay from reset architectural state at an exact anchor.
# The JIT pass forces immediate RAM L2 promotion; the configured final replay
# proves native entry rather than merely proving that the tracer compiled it.
declare -A NATIVE_REPLAY_TESTS=(
    [rol_l_reg_const_count64]=1
    [rol_l_reg_const_count64_nf]=1
    [ror_l_reg_const_count64]=1
    [ror_l_reg_const_count64_nf]=1
    [rol_b_imm_count8]=1
    [rol_b_imm_count8_nf]=1
    [rol_w_imm_count8]=1
    [rol_w_imm_count8_nf]=1
    [rol_l_imm_count8]=1
    [rol_l_imm_count8_nf]=1
    [ror_b_imm_count8]=1
    [ror_b_imm_count8_nf]=1
    [ror_w_imm_count8]=1
    [ror_w_imm_count8_nf]=1
    [ror_l_imm_count8]=1
    [ror_l_imm_count8_nf]=1
    [rolw_mem_native]=1
    [rolw_mem_native_nf]=1
    [rorw_mem_native]=1
    [rorw_mem_native_nf]=1
    [aslw_mem_native]=1
    [aslw_mem_native_nf]=1
    [asrw_mem_native]=1
    [asrw_mem_native_nf]=1
    [lslw_mem_native]=1
    [lslw_mem_native_nf]=1
    [lsrw_mem_native]=1
    [lsrw_mem_native_nf]=1
    [roxlw_mem_x_native]=1
    [roxrw_mem_x_native]=1
    [asl_l_reg_zero_count32_const_v_clear]=1
    [lsr_l_reg_const_count32]=1
    [asr_l_reg_count0_pressure_preserves_x]=1
    [asl_b_reg_count32_boundary]=1
    [asl_w_reg_count32_boundary]=1
    [asl_l_reg_count32_boundary]=1
    [asl_l_reg_zero_count32_v_clear]=1
    [asl_b_reg_zero_count63_v_clear]=1
    [asl_w_reg_zero_count33_v_clear]=1
    [asr_b_reg_count32_boundary]=1
    [asr_w_reg_count32_boundary]=1
    [asr_l_reg_count32_boundary]=1
    [lsl_b_reg_count32_boundary]=1
    [lsl_w_reg_count32_boundary]=1
    [lsl_l_reg_count32_boundary]=1
    [lsr_b_reg_count32_boundary]=1
    [lsr_w_reg_count32_boundary]=1
    [lsr_l_reg_count32_boundary]=1
    [lsr_l_reg_count33_boundary]=1
    [asl_b_reg_count32_nf]=1
    [asl_w_reg_count32_nf]=1
    [asl_l_reg_count32_nf]=1
    [asr_b_reg_count32_nf]=1
    [asr_w_reg_count32_nf]=1
    [asr_l_reg_count32_nf]=1
    [lsl_b_reg_count32_nf]=1
    [lsl_w_reg_count32_nf]=1
    [lsl_l_reg_count32_nf]=1
    [lsr_b_reg_count32_nf]=1
    [lsr_w_reg_count32_nf]=1
    [lsr_l_reg_count32_nf]=1
    [asl_b_reg_same_count_data]=1
    [asl_w_reg_same_count_data]=1
    [asl_l_reg_same_count_data]=1
    [asr_b_reg_same_count_data]=1
    [asr_w_reg_same_count_data]=1
    [asr_l_reg_same_count_data]=1
    [lsl_b_reg_same_count_data]=1
    [lsl_w_reg_same_count_data]=1
    [lsl_l_reg_same_count_data]=1
    [lsr_b_reg_same_count_data]=1
    [lsr_w_reg_same_count_data]=1
    [lsr_l_reg_same_count_data]=1
    [asl_b_reg_same_count_data_nf]=1
    [asl_w_reg_same_count_data_nf]=1
    [asl_l_reg_same_count_data_nf]=1
    [asr_b_reg_same_count_data_nf]=1
    [asr_w_reg_same_count_data_nf]=1
    [asr_l_reg_same_count_data_nf]=1
    [lsl_b_reg_same_count_data_nf]=1
    [lsl_w_reg_same_count_data_nf]=1
    [lsl_l_reg_same_count_data_nf]=1
    [lsr_b_reg_same_count_data_nf]=1
    [lsr_w_reg_same_count_data_nf]=1
    [lsr_l_reg_same_count_data_nf]=1
    [divs_w_imm_overflow_preserve_z]=1
    [divu_l32_same_dq_dr_nf]=1
    [divs_l32_same_dq_dr_nf]=1
    [divu_l32_src_dr_alias_nf]=1
    [divs_l32_src_dr_alias_nf]=1
    [divs_w_overflow_preserve_z]=1
    [ccr_ori_exact_bits]=1
    [ccr_andi_exact_mask]=1
    [ccr_eori_exact_toggle]=1
    [ccr_ori_after_borrow_flags]=1
    [ccr_andi_after_borrow_flags]=1
    [ccr_eori_after_borrow_flags]=1
    [addx_b_zero_sticky_z_clear]=1
    [addx_w_zero_sticky_z_clear]=1
    [addx_l_zero_sticky_z_clear]=1
    [subx_b_zero_sticky_z_clear]=1
    [subx_w_zero_sticky_z_clear]=1
    [subx_l_zero_sticky_z_clear]=1
    [addx_b_overflow_with_x]=1
    [addx_w_overflow_with_x]=1
    [addx_l_overflow_with_x]=1
    [subx_b_overflow_with_x]=1
    [subx_w_overflow_with_x]=1
    [subx_l_overflow_with_x]=1
    [subx_b_without_x]=1
    [subx_w_without_x]=1
    [subx_l_without_x]=1
    [addx_b_zero_sticky_z_set]=1
    [addx_w_zero_sticky_z_set]=1
    [addx_l_zero_sticky_z_set]=1
    [addx_b_zero_without_x_sticky_z_set]=1
    [addx_w_zero_without_x_sticky_z_set]=1
    [addx_l_zero_without_x_sticky_z_set]=1
    [roxl_l_zero_count_copies_cleared_x]=1
    [subx_b_zero_sticky_z_set]=1
    [subx_w_zero_sticky_z_set]=1
    [subx_l_zero_sticky_z_set]=1
    [addx_b_distinct_reg_consumes_x]=1
    [addx_w_distinct_reg_consumes_x]=1
    [addx_l_distinct_reg_consumes_x]=1
    [subx_b_distinct_reg_consumes_x]=1
    [subx_w_distinct_reg_consumes_x]=1
    [subx_l_distinct_reg_consumes_x]=1
    [addx_b_same_reg_consumes_x]=1
    [addx_w_same_reg_consumes_x]=1
    [addx_l_same_reg_consumes_x]=1
    [subx_b_same_reg_consumes_x]=1
    [subx_w_same_reg_consumes_x]=1
    [subx_l_same_reg_consumes_x]=1
    [asl_b_reg_count_0_preserves_x]=1
    [asl_w_reg_count_0_preserves_x]=1
    [asl_l_reg_count_0_preserves_x]=1
    [asr_b_reg_count_0_preserves_x]=1
    [asr_w_reg_count_0_preserves_x]=1
    [asr_l_reg_count_0_preserves_x]=1
    [lsl_b_reg_count_0_preserves_x]=1
    [lsl_w_reg_count_0_preserves_x]=1
    [lsl_l_reg_count_0_preserves_x]=1
    [lsr_b_reg_count_0_preserves_x]=1
    [lsr_w_reg_count_0_preserves_x]=1
    [lsr_l_reg_count_0_preserves_x]=1
    [roxl_l_reg_count_33_pressure]=1
    [roxr_l_reg_count_33_pressure]=1
    [roxl_b_reg_count_63_copies_x]=1
    [roxr_b_reg_count_63_copies_x]=1
    [roxl_w_reg_count_51_copies_x]=1
    [roxr_w_reg_count_51_copies_x]=1
    [roxl_l_reg_count_33_copies_x]=1
    [roxr_l_reg_count_33_copies_x]=1
    [roxl_l_reg_count_0_copies_x]=1
    [roxr_reg_count_0_copies_x]=1
    [chk_w_in_range]=1
    [chk_w_zero]=1
    [chk_w_equal]=1
    [chk_w_negative_trap_n]=1
    [chk_w_upper_trap_n_clear]=1
    [chk_l_negative_trap_n]=1
    [chk_l_upper_trap_n_clear]=1
    [chk_l_in_range_preserve_ccr]=1
    [divu_w_zero_frame]=1
    [divs_w_zero_frame]=1
    [divu_l_zero_frame]=1
    [divs_l_zero_frame]=1
    [divu_l32_zero_distinct]=1
    [divs_l32_zero_distinct]=1
    [divu_l32_success_nf]=1
    [divs_l32_success_nf]=1
    [divu_l64_zero_frame]=1
    [divs_l64_zero_frame]=1
    [divu_l64_same_dq_dr]=1
    [divs_l64_same_dq_dr]=1
    [divu_l64_same_dq_dr_nf]=1
    [divs_l64_same_dq_dr_nf]=1
    [divu_l64_overflow]=1
    [divu_l64_overflow_nf]=1
    [divs_l64_overflow]=1
    [divs_l64_overflow_nf]=1
    [divs_l32_overflow]=1
    [divs_l32_overflow_nf]=1
    [trapv_taken_frame]=1
    [trapv_not_taken_preserve]=1
    [cas_b_predec]=1
    [moves_predec_store_alias]=1
    [bitfield_mem_an_family]=1
    [io_byte_write_roundtrip]=1
    [btst_b_d16_highbit]=1
    [move_to_mem_and_back]=1
    [move_l_d16_an_cov]=1
    [move_l_idx_absw_native]=1
    [strict_zero_ram_native]=1
    [host_code_reuse_coherence]=1
    [cache_disabled_selfmod_replay]=1
    [fpp_semantic_successor]=1
    [fscc_false_byte]=1
    [fbcc_false_operand_lengths]=1
    [cas2_w_success]=1
    [cas2_w_fail_first]=1
    [cas2_w_fail_second]=1
    [cas2_l_success]=1
    [cas2_l_fail_second]=1
    [cas2_l_alias_compare]=1
    [pack_dn_edge]=1
    [pack_predec_a7_alias]=1
    [unpk_dn_edge]=1
    [unpk_predec_a7_alias]=1
    [chk2_w_equal_preserve_ccr]=1
    [chk2_b_areg_fullwidth_d16]=1
    [chk2_l_wrapped_absl]=1
    [chk2_w_trap_vector6]=1
    [chk2_w_indexed_inrange]=1
    [chk2_l_fullindexed_inrange]=1
    [chk2_w_pcrel_inrange]=1
    [movep_l_roundtrip]=1
    [movea_l_sp_postinc_cov]=1
    [movea_l_postinc_alias]=1
    [branch_flush_bgt_zero]=1
    [dbra_ccr_preserve_z_clear]=1
    [dbra_ccr_preserve_z_set]=1
    [bcd_abcd_zero_sticky_set]=1
    [bcd_abcd_zero_sticky_clear]=1
    [bcd_abcd_nonzero_clears_sticky]=1
    [bcd_abcd_carry_zero]=1
    [bcd_abcd_same_reg_with_x]=1
    [bcd_sbcd_zero_sticky_set]=1
    [bcd_sbcd_zero_sticky_clear]=1
    [bcd_sbcd_borrow]=1
    [bcd_sbcd_same_reg_with_x]=1
    [bcd_nbcd_zero_sticky_set]=1
    [bcd_nbcd_zero_sticky_clear]=1
    [bcd_nbcd_nonzero]=1
    [bcd_nbcd_with_x]=1
    [bcd_abcd_decimal_09_plus_01]=1
    [bcd_abcd_invalid_nibble_exact]=1
    [bcd_abcd_extend_chain]=1
    [bcd_sbcd_decimal_10_minus_01]=1
    [bcd_sbcd_invalid_nibble_exact]=1
    [bcd_nbcd_decimal_10]=1
    [bcd_nbcd_invalid_nibble_exact]=1
    [bcd_native_abcd_zero_sticky]=1
    [bcd_native_abcd_invalid_extend]=1
    [bcd_native_sbcd_invalid_borrow]=1
    [bcd_native_nbcd_invalid_borrow]=1
    [bcd_abcd_predec_src_a7]=1
    [bcd_abcd_predec_dst_a7]=1
    [bcd_abcd_predec_a7_alias]=1
    [bcd_sbcd_predec_src_a7]=1
    [bcd_sbcd_predec_dst_a7]=1
    [bcd_sbcd_predec_a7_alias]=1
    [bcd_nbcd_predec_a7]=1
    [mulls32_negative_fit_v_native]=1
    [mullu64_source_preserve_v_native]=1
    [mullu64_source_low_alias_native]=1
    [mullu64_same_result_alias_native]=1
    [mullu32_low_sign_full_flags_native]=1
    [mullu32_overflow_low_zero_flags_native]=1
    [mulls32_negative_overflow_low_zero_native]=1
    [mulls32_positive_overflow_low_sign_native]=1
    [mulls64_negative_flags_native]=1
    [mullu64_zero_flags_native]=1
    [mullu64_source_high_alias_native]=1
    [mullu64_all_alias_native]=1
    [mullu32_immediate_nf_native]=1
    [mullu64_memory_nf_native]=1
    [movem_l_postinc_base_alias_native]=1
    [movem_w_postinc_base_alias_native]=1
    [movem_l_predec_base_alias_native]=1
    [movem_w_predec_base_alias_native]=1
    [movem_l_aind_load_base_alias_native]=1
    [movem_l_aind_store_base_alias_native]=1
    [movem_l_all_live_roundtrip_native]=1
    [movem_l_all_live_special_native]=1
    [movem_zero_mask_native]=1
    [movem_l_control_modes_native]=1
    [movem_l_pc_modes_native]=1
)
# A setup prefix may install architectural state before the audited instruction.
# Replay and native-entry proof then start at the exact family opcode PC.
declare -A NATIVE_REPLAY_PC=(
    [rol_l_reg_const_count64]=0x100c
    [rol_l_reg_const_count64_nf]=0x100c
    [ror_l_reg_const_count64]=0x100c
    [ror_l_reg_const_count64_nf]=0x100c
    [rol_b_imm_count8]=0x1000
    [rol_b_imm_count8_nf]=0x1000
    [rol_w_imm_count8]=0x1000
    [rol_w_imm_count8_nf]=0x1000
    [rol_l_imm_count8]=0x1000
    [rol_l_imm_count8_nf]=0x1000
    [ror_b_imm_count8]=0x1000
    [ror_b_imm_count8_nf]=0x1000
    [ror_w_imm_count8]=0x1000
    [ror_w_imm_count8_nf]=0x1000
    [ror_l_imm_count8]=0x1000
    [ror_l_imm_count8_nf]=0x1000
    [rolw_mem_native]=0x1000
    [rolw_mem_native_nf]=0x1000
    [rorw_mem_native]=0x1000
    [rorw_mem_native_nf]=0x1000
    [aslw_mem_native]=0x1000
    [aslw_mem_native_nf]=0x1000
    [asrw_mem_native]=0x1000
    [asrw_mem_native_nf]=0x1000
    [lslw_mem_native]=0x1000
    [lslw_mem_native_nf]=0x1000
    [lsrw_mem_native]=0x1000
    [lsrw_mem_native_nf]=0x1000
    [roxlw_mem_x_native]=0x1000
    [roxrw_mem_x_native]=0x1000
    [chk_w_in_range]=0x1004
    [chk_w_zero]=0x1004
    [chk_w_equal]=0x1004
    [chk_w_negative_trap_n]=0x1018
    [chk_w_upper_trap_n_clear]=0x1018
    [chk_l_negative_trap_n]=0x1018
    [chk_l_upper_trap_n_clear]=0x1020
    [chk_l_in_range_preserve_ccr]=0x1010
    [divu_w_zero_frame]=0x101c
    [divs_w_zero_frame]=0x101c
    [divs_w_overflow_preserve_z]=0x100c
    [divs_w_imm_overflow_preserve_z]=0x100a
    [asl_b_reg_count32_boundary]=0x100c
    [asl_w_reg_count32_boundary]=0x100c
    [asl_l_reg_count32_boundary]=0x100c
    [asl_l_reg_zero_count32_v_clear]=0x100c
    [asl_b_reg_zero_count63_v_clear]=0x100c
    [asl_w_reg_zero_count33_v_clear]=0x100c
    [asr_b_reg_count32_boundary]=0x100c
    [asr_w_reg_count32_boundary]=0x100c
    [asr_l_reg_count32_boundary]=0x100c
    [lsl_b_reg_count32_boundary]=0x100c
    [lsl_w_reg_count32_boundary]=0x100c
    [lsl_l_reg_count32_boundary]=0x100c
    [lsr_b_reg_count32_boundary]=0x100c
    [lsr_w_reg_count32_boundary]=0x100c
    [lsr_l_reg_count32_boundary]=0x100c
    [lsr_l_reg_count33_boundary]=0x100c
    [asl_b_reg_count32_nf]=0x100c
    [asl_w_reg_count32_nf]=0x100c
    [asl_l_reg_count32_nf]=0x100c
    [asr_b_reg_count32_nf]=0x100c
    [asr_w_reg_count32_nf]=0x100c
    [asr_l_reg_count32_nf]=0x100c
    [lsl_b_reg_count32_nf]=0x100c
    [lsl_w_reg_count32_nf]=0x100c
    [lsl_l_reg_count32_nf]=0x100c
    [lsr_b_reg_count32_nf]=0x100c
    [lsr_w_reg_count32_nf]=0x100c
    [lsr_l_reg_count32_nf]=0x100c
    [asl_b_reg_same_count_data]=0x100a
    [asl_w_reg_same_count_data]=0x100a
    [asl_l_reg_same_count_data]=0x100a
    [asr_b_reg_same_count_data]=0x100a
    [asr_w_reg_same_count_data]=0x100a
    [asr_l_reg_same_count_data]=0x100a
    [lsl_b_reg_same_count_data]=0x100a
    [lsl_w_reg_same_count_data]=0x100a
    [lsl_l_reg_same_count_data]=0x100a
    [lsr_b_reg_same_count_data]=0x100a
    [lsr_w_reg_same_count_data]=0x100a
    [lsr_l_reg_same_count_data]=0x100a
    [asl_b_reg_same_count_data_nf]=0x100a
    [asl_w_reg_same_count_data_nf]=0x100a
    [asl_l_reg_same_count_data_nf]=0x100a
    [asr_b_reg_same_count_data_nf]=0x100a
    [asr_w_reg_same_count_data_nf]=0x100a
    [asr_l_reg_same_count_data_nf]=0x100a
    [lsl_b_reg_same_count_data_nf]=0x100a
    [lsl_w_reg_same_count_data_nf]=0x100a
    [lsl_l_reg_same_count_data_nf]=0x100a
    [lsr_b_reg_same_count_data_nf]=0x100a
    [lsr_w_reg_same_count_data_nf]=0x100a
    [lsr_l_reg_same_count_data_nf]=0x100a
    [divu_l_zero_frame]=0x101c
    [divs_l_zero_frame]=0x101c
    [divu_l32_zero_distinct]=0x1022
    [divs_l32_zero_distinct]=0x1022
    [divu_l32_success_nf]=0x1016
    [divs_l32_success_nf]=0x1016
    [divu_l32_same_dq_dr_nf]=0x1010
    [divs_l32_same_dq_dr_nf]=0x1010
    [divu_l32_src_dr_alias_nf]=0x1010
    [divs_l32_src_dr_alias_nf]=0x1010
    [divu_l64_zero_frame]=0x1022
    [divs_l64_zero_frame]=0x1022
    [divu_l64_same_dq_dr]=0x1010
    [divs_l64_same_dq_dr]=0x1010
    [divu_l64_same_dq_dr_nf]=0x1010
    [divs_l64_same_dq_dr_nf]=0x1010
    [divu_l64_overflow]=0x1016
    [divu_l64_overflow_nf]=0x1016
    [divs_l64_overflow]=0x1016
    [divs_l64_overflow_nf]=0x1016
    [divs_l32_overflow]=0x1016
    [divs_l32_overflow_nf]=0x1016
    [trapv_taken_frame]=0x1014
    [trapv_not_taken_preserve]=0x1004
    [bcd_abcd_zero_sticky_set]=0x100c
    [bcd_abcd_zero_sticky_clear]=0x1008
    [bcd_abcd_nonzero_clears_sticky]=0x100c
    [bcd_abcd_carry_zero]=0x1010
    [bcd_abcd_same_reg_with_x]=0x100e
    [bcd_sbcd_zero_sticky_set]=0x100c
    [bcd_sbcd_zero_sticky_clear]=0x1008
    [bcd_sbcd_borrow]=0x100c
    [bcd_sbcd_same_reg_with_x]=0x100e
    [bcd_nbcd_zero_sticky_set]=0x100a
    [bcd_nbcd_zero_sticky_clear]=0x1006
    [bcd_nbcd_nonzero]=0x100a
    [bcd_nbcd_with_x]=0x100a
    [bcd_abcd_decimal_09_plus_01]=0x1008
    [bcd_abcd_invalid_nibble_exact]=0x100c
    [bcd_abcd_extend_chain]=0x1014
    [bcd_sbcd_decimal_10_minus_01]=0x1008
    [bcd_sbcd_invalid_nibble_exact]=0x100c
    [bcd_nbcd_decimal_10]=0x1006
    [bcd_nbcd_invalid_nibble_exact]=0x100a
    [bcd_native_abcd_zero_sticky]=0x1000
    [bcd_native_abcd_invalid_extend]=0x1000
    [bcd_native_sbcd_invalid_borrow]=0x1000
    [bcd_native_nbcd_invalid_borrow]=0x1000
    [bcd_abcd_predec_src_a7]=0x1028
    [bcd_abcd_predec_dst_a7]=0x1028
    [bcd_abcd_predec_a7_alias]=0x1022
    [bcd_sbcd_predec_src_a7]=0x1028
    [bcd_sbcd_predec_dst_a7]=0x1028
    [bcd_sbcd_predec_a7_alias]=0x1022
    [bcd_nbcd_predec_a7]=0x1018
    [movem_l_postinc_base_alias_native]=0x1018
    [movem_w_postinc_base_alias_native]=0x1014
    [movem_l_predec_base_alias_native]=0x100a
    [movem_w_predec_base_alias_native]=0x100a
    [movem_l_aind_load_base_alias_native]=0x1014
    [movem_l_aind_store_base_alias_native]=0x1010
    [movem_l_all_live_roundtrip_native]=0x1000
    [movem_l_all_live_special_native]=0x1000
    [movem_zero_mask_native]=0x1004
    [movem_l_control_modes_native]=0x1010
    [movem_l_pc_modes_native]=0x1014
)
# Byte pairs are RAM-relative address/value operands restored before every
# exact-PC replay. This keeps memory-EA vectors deterministic across the trace
# pass and the later native-entry pass.
declare -A NATIVE_REPLAY_BYTES=(
    [rolw_mem_native]="A000 80 A001 01"
    [rolw_mem_native_nf]="A000 80 A001 01"
    [rorw_mem_native]="A000 80 A001 01"
    [rorw_mem_native_nf]="A000 80 A001 01"
    [aslw_mem_native]="A000 40 A001 00"
    [aslw_mem_native_nf]="A000 40 A001 00"
    [asrw_mem_native]="A000 80 A001 01"
    [asrw_mem_native_nf]="A000 80 A001 01"
    [lslw_mem_native]="A000 80 A001 01"
    [lslw_mem_native_nf]="A000 80 A001 01"
    [lsrw_mem_native]="A000 80 A001 01"
    [lsrw_mem_native_nf]="A000 80 A001 01"
    [roxlw_mem_x_native]="A000 80 A001 01"
    [roxrw_mem_x_native]="A000 80 A001 00"
    [mullu64_memory_nf_native]="A000 00 A001 00 A002 00 A003 02"
    [bcd_abcd_predec_src_a7]="2080 01 2040 99"
    [bcd_abcd_predec_dst_a7]="2080 01 2040 99"
    [bcd_abcd_predec_a7_alias]="2082 01 2080 99"
    [bcd_sbcd_predec_src_a7]="2080 01 2040 00"
    [bcd_sbcd_predec_dst_a7]="2080 01 2040 00"
    [bcd_sbcd_predec_a7_alias]="2082 01 2080 00"
    [bcd_nbcd_predec_a7]="2040 01"
    [movem_l_postinc_base_alias_native]="3000 11 3001 11 3002 11 3003 11 3004 22 3005 22 3006 22 3007 22"
    [movem_w_postinc_base_alias_native]="3000 80 3001 01 3002 7f 3003 ff 3004 ff 3005 ff"
    [movem_l_aind_load_base_alias_native]="3000 11 3001 11 3002 11 3003 11 3004 22 3005 22 3006 22 3007 22"
    [movem_l_pc_modes_native]="3000 11 3001 11 3002 11 3003 11 3004 22 3005 22 3006 22 3007 22"
)
declare -A NATIVE_REPLAY_COUNT=(
    [rol_l_reg_const_count64]=2
    [rol_l_reg_const_count64_nf]=2
    [ror_l_reg_const_count64]=2
    [ror_l_reg_const_count64_nf]=2
    [rol_b_imm_count8]=2
    [rol_b_imm_count8_nf]=2
    [rol_w_imm_count8]=2
    [rol_w_imm_count8_nf]=2
    [rol_l_imm_count8]=2
    [rol_l_imm_count8_nf]=2
    [ror_b_imm_count8]=2
    [ror_b_imm_count8_nf]=2
    [ror_w_imm_count8]=2
    [ror_w_imm_count8_nf]=2
    [ror_l_imm_count8]=2
    [ror_l_imm_count8_nf]=2
    [rolw_mem_native]=2
    [rolw_mem_native_nf]=2
    [rorw_mem_native]=2
    [rorw_mem_native_nf]=2
    [aslw_mem_native]=2
    [aslw_mem_native_nf]=2
    [asrw_mem_native]=2
    [asrw_mem_native_nf]=2
    [lslw_mem_native]=2
    [lslw_mem_native_nf]=2
    [lsrw_mem_native]=2
    [lsrw_mem_native_nf]=2
    [roxlw_mem_x_native]=2
    [roxrw_mem_x_native]=2
    [chk_w_in_range]=2
    [chk_w_zero]=2
    [chk_w_equal]=2
    [chk_w_negative_trap_n]=2
    [chk_w_upper_trap_n_clear]=2
    [chk_l_negative_trap_n]=2
    [chk_l_upper_trap_n_clear]=2
    [chk_l_in_range_preserve_ccr]=2
    [divu_w_zero_frame]=2
    [divs_w_zero_frame]=2
    [divs_w_overflow_preserve_z]=2
    [divs_w_imm_overflow_preserve_z]=2
    [asl_b_reg_count32_boundary]=2
    [asl_w_reg_count32_boundary]=2
    [asl_l_reg_count32_boundary]=2
    [asl_l_reg_zero_count32_v_clear]=2
    [asl_b_reg_zero_count63_v_clear]=2
    [asl_w_reg_zero_count33_v_clear]=2
    [asr_b_reg_count32_boundary]=2
    [asr_w_reg_count32_boundary]=2
    [asr_l_reg_count32_boundary]=2
    [lsl_b_reg_count32_boundary]=2
    [lsl_w_reg_count32_boundary]=2
    [lsl_l_reg_count32_boundary]=2
    [lsr_b_reg_count32_boundary]=2
    [lsr_w_reg_count32_boundary]=2
    [lsr_l_reg_count32_boundary]=2
    [lsr_l_reg_count33_boundary]=2
    [asl_b_reg_count32_nf]=2
    [asl_w_reg_count32_nf]=2
    [asl_l_reg_count32_nf]=2
    [asr_b_reg_count32_nf]=2
    [asr_w_reg_count32_nf]=2
    [asr_l_reg_count32_nf]=2
    [lsl_b_reg_count32_nf]=2
    [lsl_w_reg_count32_nf]=2
    [lsl_l_reg_count32_nf]=2
    [lsr_b_reg_count32_nf]=2
    [lsr_w_reg_count32_nf]=2
    [lsr_l_reg_count32_nf]=2
    [asl_b_reg_same_count_data]=2
    [asl_w_reg_same_count_data]=2
    [asl_l_reg_same_count_data]=2
    [asr_b_reg_same_count_data]=2
    [asr_w_reg_same_count_data]=2
    [asr_l_reg_same_count_data]=2
    [lsl_b_reg_same_count_data]=2
    [lsl_w_reg_same_count_data]=2
    [lsl_l_reg_same_count_data]=2
    [lsr_b_reg_same_count_data]=2
    [lsr_w_reg_same_count_data]=2
    [lsr_l_reg_same_count_data]=2
    [asl_b_reg_same_count_data_nf]=2
    [asl_w_reg_same_count_data_nf]=2
    [asl_l_reg_same_count_data_nf]=2
    [asr_b_reg_same_count_data_nf]=2
    [asr_w_reg_same_count_data_nf]=2
    [asr_l_reg_same_count_data_nf]=2
    [lsl_b_reg_same_count_data_nf]=2
    [lsl_w_reg_same_count_data_nf]=2
    [lsl_l_reg_same_count_data_nf]=2
    [lsr_b_reg_same_count_data_nf]=2
    [lsr_w_reg_same_count_data_nf]=2
    [lsr_l_reg_same_count_data_nf]=2
    [divu_l_zero_frame]=2
    [divs_l_zero_frame]=2
    [divu_l32_zero_distinct]=2
    [divs_l32_zero_distinct]=2
    [divu_l32_success_nf]=2
    [divs_l32_success_nf]=2
    [divu_l32_same_dq_dr_nf]=2
    [divs_l32_same_dq_dr_nf]=2
    [divu_l32_src_dr_alias_nf]=2
    [divs_l32_src_dr_alias_nf]=2
    [divu_l64_zero_frame]=2
    [divs_l64_zero_frame]=2
    [divu_l64_same_dq_dr]=2
    [divs_l64_same_dq_dr]=2
    [divu_l64_same_dq_dr_nf]=2
    [divs_l64_same_dq_dr_nf]=2
    [divu_l64_overflow]=2
    [divu_l64_overflow_nf]=2
    [divs_l64_overflow]=2
    [divs_l64_overflow_nf]=2
    [divs_l32_overflow]=2
    [divs_l32_overflow_nf]=2
    [trapv_taken_frame]=2
    [trapv_not_taken_preserve]=2
    # Prefix-bearing BCD vectors need one replay to trace the exact opcode
    # anchor and a second replay to prove native entry at that same address.
    [bcd_abcd_zero_sticky_set]=2
    [bcd_abcd_zero_sticky_clear]=2
    [bcd_abcd_nonzero_clears_sticky]=2
    [bcd_abcd_carry_zero]=2
    [bcd_abcd_same_reg_with_x]=2
    [bcd_sbcd_zero_sticky_set]=2
    [bcd_sbcd_zero_sticky_clear]=2
    [bcd_sbcd_borrow]=2
    [bcd_sbcd_same_reg_with_x]=2
    [bcd_nbcd_zero_sticky_set]=2
    [bcd_nbcd_zero_sticky_clear]=2
    [bcd_nbcd_nonzero]=2
    [bcd_nbcd_with_x]=2
    [bcd_abcd_decimal_09_plus_01]=2
    [bcd_abcd_invalid_nibble_exact]=2
    [bcd_abcd_extend_chain]=2
    [bcd_sbcd_decimal_10_minus_01]=2
    [bcd_sbcd_invalid_nibble_exact]=2
    [bcd_nbcd_decimal_10]=2
    [bcd_nbcd_invalid_nibble_exact]=2
    [bcd_abcd_predec_src_a7]=2
    [bcd_abcd_predec_dst_a7]=2
    [bcd_abcd_predec_a7_alias]=2
    [bcd_sbcd_predec_src_a7]=2
    [bcd_sbcd_predec_dst_a7]=2
    [bcd_sbcd_predec_a7_alias]=2
    [bcd_nbcd_predec_a7]=2
    # Prefix-bearing MOVEM vectors likewise trace the audited internal anchor
    # once, then require native entry at precisely that MOVEM PC.
    [movem_l_postinc_base_alias_native]=2
    [movem_w_postinc_base_alias_native]=2
    [movem_l_predec_base_alias_native]=2
    [movem_w_predec_base_alias_native]=2
    [movem_l_aind_load_base_alias_native]=2
    [movem_l_aind_store_base_alias_native]=2
    [movem_l_all_live_roundtrip_native]=2
    [movem_l_all_live_special_native]=2
    [movem_zero_mask_native]=2
    [movem_l_control_modes_native]=2
    [movem_l_pc_modes_native]=2
    [cache_disabled_selfmod_replay]=2
    [host_code_reuse_coherence]=2
)
for _shift_name in "${SHIFT_BOUNDARY_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_shift_name"]=1
    NATIVE_REPLAY_PC["$_shift_name"]=0x100c
    NATIVE_REPLAY_COUNT["$_shift_name"]=2
done
unset _shift_name
for _rotate_name in "${ROTATE_REGISTER_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_rotate_name"]=1
    NATIVE_REPLAY_PC["$_rotate_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_rotate_name"]=2
done
unset _rotate_name
for _add_name in "${ADD_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_add_name"]=1
    NATIVE_REPLAY_PC["$_add_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_add_name"]=2
done
unset _add_name
NATIVE_REPLAY_BYTES[add_core_b_aind_source_special_native]="A000 01"
NATIVE_REPLAY_BYTES[add_core_w_postinc_source_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[add_core_l_predec_source_native]="A000 00 A001 00 A002 00 A003 01"
NATIVE_REPLAY_BYTES[add_core_b_d16_source_native]="A010 FF"
NATIVE_REPLAY_BYTES[add_core_w_index_source_special_native]="A002 00 A003 01"
NATIVE_REPLAY_BYTES[add_core_l_absw_source_native]="6000 00 6001 00 6002 00 6003 01"
NATIVE_REPLAY_BYTES[add_core_b_absl_source_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_w_pc16_source_native]="0FF0 00 0FF1 01"
NATIVE_REPLAY_BYTES[add_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"
NATIVE_REPLAY_BYTES[add_core_b_aind_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_w_postinc_dest_native]="A000 FF A001 FF"
NATIVE_REPLAY_BYTES[add_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
NATIVE_REPLAY_BYTES[add_core_b_d16_dest_native]="A010 FF"
NATIVE_REPLAY_BYTES[add_core_w_index_dest_special_native]="A002 7F A003 FF"
NATIVE_REPLAY_BYTES[add_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[add_core_b_absl_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_b_a7_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_b_a7_predec_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_b_addi_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_b_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[add_core_b_postinc_dest_noflags_native]="A000 7F"
SPECIAL_MEMORY_TESTS[add_core_b_aind_source_special_native]=1
SPECIAL_MEMORY_TESTS[add_core_w_index_source_special_native]=1
SPECIAL_MEMORY_TESTS[add_core_b_absl_source_special_native]=1
SPECIAL_MEMORY_TESTS[add_core_b_aind_dest_special_native]=1
SPECIAL_MEMORY_TESTS[add_core_w_index_dest_special_native]=1
SPECIAL_MEMORY_TESTS[add_core_b_absl_dest_special_native]=1
for _and_name in "${AND_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_and_name"]=1
    NATIVE_REPLAY_PC["$_and_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_and_name"]=2
done
unset _and_name
NATIVE_REPLAY_BYTES[and_core_b_aind_source_special_native]="A000 0F"
NATIVE_REPLAY_BYTES[and_core_w_postinc_source_native]="A000 0F A001 0F"
NATIVE_REPLAY_BYTES[and_core_l_predec_source_native]="A000 80 A001 00 A002 00 A003 00"
NATIVE_REPLAY_BYTES[and_core_b_d16_source_native]="A010 0F"
NATIVE_REPLAY_BYTES[and_core_w_index_source_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[and_core_l_absw_source_native]="6000 0F 6001 0F 6002 0F 6003 0F"
NATIVE_REPLAY_BYTES[and_core_b_absl_source_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_w_pc16_source_native]="0FF0 00 0FF1 FF"
NATIVE_REPLAY_BYTES[and_core_l_pcindex_source_native]="0FF0 80 0FF1 00 0FF2 00 0FF3 00"
NATIVE_REPLAY_BYTES[and_core_b_aind_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_w_postinc_dest_native]="A000 FF A001 FF"
NATIVE_REPLAY_BYTES[and_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
NATIVE_REPLAY_BYTES[and_core_b_d16_dest_native]="A010 FF"
NATIVE_REPLAY_BYTES[and_core_w_index_dest_special_native]="A002 FF A003 FF"
NATIVE_REPLAY_BYTES[and_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[and_core_b_absl_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_b_a7_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_b_a7_predec_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_b_andi_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_b_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[and_core_b_postinc_dest_noflags_native]="A000 FF"
SPECIAL_MEMORY_TESTS[and_core_b_aind_source_special_native]=1
SPECIAL_MEMORY_TESTS[and_core_w_index_source_special_native]=1
SPECIAL_MEMORY_TESTS[and_core_b_absl_source_special_native]=1
SPECIAL_MEMORY_TESTS[and_core_b_aind_dest_special_native]=1
SPECIAL_MEMORY_TESTS[and_core_w_index_dest_special_native]=1
SPECIAL_MEMORY_TESTS[and_core_b_absl_dest_special_native]=1
for _eor_name in "${EOR_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_eor_name"]=1
    NATIVE_REPLAY_PC["$_eor_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_eor_name"]=2
done
unset _eor_name
NATIVE_REPLAY_BYTES[eor_core_b_aind_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[eor_core_w_postinc_dest_native]="A000 FF A001 FF"
NATIVE_REPLAY_BYTES[eor_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
NATIVE_REPLAY_BYTES[eor_core_b_d16_dest_native]="A010 FF"
NATIVE_REPLAY_BYTES[eor_core_w_index_dest_special_native]="A002 FF A003 FF"
NATIVE_REPLAY_BYTES[eor_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[eor_core_b_absl_dest_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[eor_core_b_a7_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[eor_core_b_a7_predec_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[eor_core_b_eori_postinc_dest_native]="A000 FF"
NATIVE_REPLAY_BYTES[eor_core_b_postinc_dest_native]="A000 F0"
NATIVE_REPLAY_BYTES[eor_core_b_postinc_dest_noflags_native]="A000 FF"
SPECIAL_MEMORY_TESTS[eor_core_b_aind_dest_special_native]=1
SPECIAL_MEMORY_TESTS[eor_core_w_index_dest_special_native]=1
SPECIAL_MEMORY_TESTS[eor_core_b_absl_dest_special_native]=1
for _or_name in "${OR_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_or_name"]=1
    NATIVE_REPLAY_PC["$_or_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_or_name"]=2
done
unset _or_name
NATIVE_REPLAY_BYTES[or_core_b_aind_source_special_native]="A000 0F"
NATIVE_REPLAY_BYTES[or_core_w_postinc_source_native]="A000 0F A001 0F"
NATIVE_REPLAY_BYTES[or_core_l_predec_source_native]="A000 80 A001 00 A002 00 A003 00"
NATIVE_REPLAY_BYTES[or_core_b_d16_source_native]="A010 0F"
NATIVE_REPLAY_BYTES[or_core_w_index_source_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[or_core_l_absw_source_native]="6000 0F 6001 0F 6002 0F 6003 0F"
NATIVE_REPLAY_BYTES[or_core_b_absl_source_special_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_w_pc16_source_native]="0FF0 00 0FF1 FF"
NATIVE_REPLAY_BYTES[or_core_l_pcindex_source_native]="0FF0 80 0FF1 00 0FF2 00 0FF3 00"
NATIVE_REPLAY_BYTES[or_core_b_aind_dest_special_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_w_postinc_dest_native]="A000 F0 A001 F0"
NATIVE_REPLAY_BYTES[or_core_l_predec_dest_native]="A000 F0 A001 F0 A002 F0 A003 F0"
NATIVE_REPLAY_BYTES[or_core_b_d16_dest_native]="A010 F0"
NATIVE_REPLAY_BYTES[or_core_w_index_dest_special_native]="A002 F0 A003 F0"
NATIVE_REPLAY_BYTES[or_core_l_absw_dest_native]="6000 F0 6001 F0 6002 F0 6003 F0"
NATIVE_REPLAY_BYTES[or_core_b_absl_dest_special_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_b_a7_postinc_dest_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_b_a7_predec_dest_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_b_ori_postinc_dest_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_b_postinc_dest_native]="A000 F0"
NATIVE_REPLAY_BYTES[or_core_b_postinc_dest_noflags_native]="A000 F0"
SPECIAL_MEMORY_TESTS[or_core_b_aind_source_special_native]=1
SPECIAL_MEMORY_TESTS[or_core_w_index_source_special_native]=1
SPECIAL_MEMORY_TESTS[or_core_b_absl_source_special_native]=1
SPECIAL_MEMORY_TESTS[or_core_b_aind_dest_special_native]=1
SPECIAL_MEMORY_TESTS[or_core_w_index_dest_special_native]=1
SPECIAL_MEMORY_TESTS[or_core_b_absl_dest_special_native]=1
for _sub_name in "${SUB_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_sub_name"]=1
    NATIVE_REPLAY_PC["$_sub_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_sub_name"]=2
done
unset _sub_name
NATIVE_REPLAY_BYTES[sub_core_b_aind_source_special_native]="A000 01"
NATIVE_REPLAY_BYTES[sub_core_w_postinc_source_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[sub_core_l_predec_source_native]="A000 00 A001 00 A002 00 A003 01"
NATIVE_REPLAY_BYTES[sub_core_b_d16_source_native]="A010 FF"
NATIVE_REPLAY_BYTES[sub_core_w_index_source_special_native]="A002 00 A003 01"
NATIVE_REPLAY_BYTES[sub_core_l_absw_source_native]="6000 00 6001 00 6002 00 6003 01"
NATIVE_REPLAY_BYTES[sub_core_b_absl_source_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[sub_core_w_pc16_source_native]="0FF0 00 0FF1 01"
NATIVE_REPLAY_BYTES[sub_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"
NATIVE_REPLAY_BYTES[sub_core_b_aind_dest_special_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_w_postinc_dest_native]="A000 00 A001 00"
NATIVE_REPLAY_BYTES[sub_core_l_predec_dest_native]="A000 00 A001 00 A002 00 A003 00"
NATIVE_REPLAY_BYTES[sub_core_b_d16_dest_native]="A010 00"
NATIVE_REPLAY_BYTES[sub_core_w_index_dest_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[sub_core_l_absw_dest_native]="6000 00 6001 00 6002 00 6003 00"
NATIVE_REPLAY_BYTES[sub_core_b_absl_dest_special_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_b_a7_postinc_dest_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_b_a7_predec_dest_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_b_subi_postinc_dest_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_b_postinc_dest_native]="A000 00"
NATIVE_REPLAY_BYTES[sub_core_b_postinc_dest_noflags_native]="A000 00"
SPECIAL_MEMORY_TESTS[sub_core_b_aind_source_special_native]=1
SPECIAL_MEMORY_TESTS[sub_core_w_index_source_special_native]=1
SPECIAL_MEMORY_TESTS[sub_core_b_absl_source_special_native]=1
SPECIAL_MEMORY_TESTS[sub_core_b_aind_dest_special_native]=1
SPECIAL_MEMORY_TESTS[sub_core_w_index_dest_special_native]=1
SPECIAL_MEMORY_TESTS[sub_core_b_absl_dest_special_native]=1
for _adda_name in "${ADDA_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_adda_name"]=1
    NATIVE_REPLAY_PC["$_adda_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_adda_name"]=2
done
unset _adda_name
# A fully constant ADDA emits no host instruction at its own guest PC, so the
# two constant-fold vectors remain strict equivalence cases rather than forging
# impossible exact-native-entry evidence.
unset 'NATIVE_REPLAY_TESTS[adda_core_w_const_dst_wrap]'
unset 'NATIVE_REPLAY_TESTS[adda_core_l_const_dst_wrap]'
unset 'NATIVE_REPLAY_PC[adda_core_w_const_dst_wrap]'
unset 'NATIVE_REPLAY_PC[adda_core_l_const_dst_wrap]'
unset 'NATIVE_REPLAY_COUNT[adda_core_w_const_dst_wrap]'
unset 'NATIVE_REPLAY_COUNT[adda_core_l_const_dst_wrap]'
NATIVE_REPLAY_BYTES[adda_core_w_aind_alias_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[adda_core_w_postinc_alias_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[adda_core_w_predec_alias_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[adda_core_l_postinc_alias_native]="A000 00 A001 00 A002 00 A003 01"
NATIVE_REPLAY_BYTES[adda_core_l_predec_alias_native]="A000 00 A001 00 A002 00 A003 01"
NATIVE_REPLAY_BYTES[adda_core_w_d16_source_native]="A010 FF A011 FF"
NATIVE_REPLAY_BYTES[adda_core_w_index_source_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[adda_core_l_absw_source_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[adda_core_w_absl_source_special_native]="A000 7F A001 FF"
NATIVE_REPLAY_BYTES[adda_core_w_pc16_source_native]="0FF0 80 0FF1 00"
NATIVE_REPLAY_BYTES[adda_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"
SPECIAL_MEMORY_TESTS[adda_core_w_index_source_special_native]=1
SPECIAL_MEMORY_TESTS[adda_core_w_absl_source_special_native]=1
for _neg_name in "${NEG_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_neg_name"]=1
    NATIVE_REPLAY_PC["$_neg_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_neg_name"]=2
done
unset _neg_name
NATIVE_REPLAY_BYTES[neg_b_aind_special_native]="A000 80"
NATIVE_REPLAY_BYTES[neg_w_postinc_native]="A000 00 A001 01"
NATIVE_REPLAY_BYTES[neg_l_predec_native]="A000 00 A001 00 A002 00 A003 01"
NATIVE_REPLAY_BYTES[neg_b_d16_native]="A010 80"
NATIVE_REPLAY_BYTES[neg_w_indexed_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[neg_l_absw_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[neg_b_absl_special_native]="A000 00"
NATIVE_REPLAY_BYTES[neg_b_a7_postinc_native]="A000 80"
NATIVE_REPLAY_BYTES[neg_b_a7_predec_native]="A000 01"
SPECIAL_MEMORY_TESTS[neg_b_aind_special_native]=1
SPECIAL_MEMORY_TESTS[neg_w_indexed_special_native]=1
SPECIAL_MEMORY_TESTS[neg_b_absl_special_native]=1
for _negx_name in "${NEGX_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_negx_name"]=1
    NATIVE_REPLAY_PC["$_negx_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_negx_name"]=2
done
unset _negx_name
NATIVE_REPLAY_BYTES[negx_b_aind_special_native]="A000 80"
NATIVE_REPLAY_BYTES[negx_w_postinc_native]="A000 00 A001 00"
NATIVE_REPLAY_BYTES[negx_l_predec_native]="A000 00 A001 00 A002 00 A003 00"
NATIVE_REPLAY_BYTES[negx_b_d16_native]="A010 80"
NATIVE_REPLAY_BYTES[negx_w_indexed_special_native]="A002 80 A003 00"
NATIVE_REPLAY_BYTES[negx_l_absw_native]="6000 80 6001 00 6002 00 6003 00"
NATIVE_REPLAY_BYTES[negx_b_absl_special_native]="A000 00"
NATIVE_REPLAY_BYTES[negx_b_a7_postinc_native]="A000 80"
NATIVE_REPLAY_BYTES[negx_b_a7_predec_native]="A000 00"
SPECIAL_MEMORY_TESTS[negx_b_aind_special_native]=1
SPECIAL_MEMORY_TESTS[negx_w_indexed_special_native]=1
SPECIAL_MEMORY_TESTS[negx_b_absl_special_native]=1
for _tas_name in "${TAS_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_tas_name"]=1
    NATIVE_REPLAY_PC["$_tas_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_tas_name"]=2
done
unset _tas_name
NATIVE_REPLAY_BYTES[tas_b_aind_special_native]="A000 00"
NATIVE_REPLAY_BYTES[tas_b_postinc_native]="A000 7F"
NATIVE_REPLAY_BYTES[tas_b_predec_native]="A000 80"
NATIVE_REPLAY_BYTES[tas_b_d16_native]="A010 FF"
NATIVE_REPLAY_BYTES[tas_b_indexed_special_native]="A002 00"
NATIVE_REPLAY_BYTES[tas_b_absw_native]="6000 01"
NATIVE_REPLAY_BYTES[tas_b_absl_special_native]="A000 80"
NATIVE_REPLAY_BYTES[tas_b_a7_postinc_native]="A000 00"
NATIVE_REPLAY_BYTES[tas_b_a7_predec_native]="A000 7F"
SPECIAL_MEMORY_TESTS[tas_b_aind_special_native]=1
SPECIAL_MEMORY_TESTS[tas_b_indexed_special_native]=1
SPECIAL_MEMORY_TESTS[tas_b_absl_special_native]=1
for _move_name in "${MOVE_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_move_name"]=1
    NATIVE_REPLAY_PC["$_move_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_move_name"]=2
done
unset _move_name
# This existing sequence keeps D0 constant across MOVE.L #imm then MOVE.B #imm,
# exercising mov_l_ri guest-constant propagation and mov_b_ri's constant-folded
# low-lane update under strict replay. indexed_full_neg_base separately forces
# constant PC_P materialisation through the 64-bit allocator exception.
NATIVE_REPLAY_TESTS[move_b_preserve_flags]=1
NATIVE_REPLAY_PC[move_b_preserve_flags]=0x1000
NATIVE_REPLAY_COUNT[move_b_preserve_flags]=2
NATIVE_REPLAY_TESTS[indexed_full_neg_base]=1
NATIVE_REPLAY_PC[indexed_full_neg_base]=0x1000
NATIVE_REPLAY_COUNT[indexed_full_neg_base]=1
for _movea_name in "${MOVEA_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_movea_name"]=1
    NATIVE_REPLAY_PC["$_movea_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_movea_name"]=2
done
unset _movea_name
for _move16_name in "${MOVE16_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_move16_name"]=1
    NATIVE_REPLAY_PC["$_move16_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_move16_name"]=2
done
unset _move16_name
for _scc_name in "${SCC_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_scc_name"]=1
    NATIVE_REPLAY_PC["$_scc_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_scc_name"]=2
done
unset _scc_name
for _bcc_name in "${BCC_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_bcc_name"]=1
    NATIVE_REPLAY_PC["$_bcc_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_bcc_name"]=2
done
unset _bcc_name
for _bcc_name in bcc_core_bne_b_backward_native bcc_core_bne_w_backward_native bcc_core_bne_l_backward_native; do
    NATIVE_REPLAY_PC["$_bcc_name"]=0x1004
done
unset _bcc_name
for _clr_name in "${CLR_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_clr_name"]=1
    NATIVE_REPLAY_PC["$_clr_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_clr_name"]=2
done
unset _clr_name
NATIVE_REPLAY_BYTES[clr_core_b_aind_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[clr_core_w_postinc_native]="A000 FF A001 FF"
NATIVE_REPLAY_BYTES[clr_core_l_predec_native]="9FFC FF 9FFD FF 9FFE FF 9FFF FF"
NATIVE_REPLAY_BYTES[clr_core_b_d16_native]="A010 FF"
NATIVE_REPLAY_BYTES[clr_core_w_index_special_native]="A002 FF A003 FF"
NATIVE_REPLAY_BYTES[clr_core_l_absw_native]="6000 FF 6001 FF 6002 FF 6003 FF"
NATIVE_REPLAY_BYTES[clr_core_b_absl_special_native]="A000 FF"
NATIVE_REPLAY_BYTES[clr_core_b_a7_postinc_native]="A000 FF"
NATIVE_REPLAY_BYTES[clr_core_b_a7_predec_native]="9FFE FF"
NATIVE_REPLAY_BYTES[clr_core_b_postinc_successor_bne_native]="A000 FF"
NATIVE_REPLAY_BYTES[clr_core_l_postinc_noflags_native]="A000 FF A001 FF A002 FF A003 FF"
SPECIAL_MEMORY_TESTS[clr_core_b_aind_special_native]=1
SPECIAL_MEMORY_TESTS[clr_core_w_index_special_native]=1
SPECIAL_MEMORY_TESTS[clr_core_b_absl_special_native]=1
for _exg_name in "${EXG_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_exg_name"]=1
    NATIVE_REPLAY_PC["$_exg_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_exg_name"]=2
done
unset _exg_name
for _ext_name in "${EXT_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_ext_name"]=1
    NATIVE_REPLAY_PC["$_ext_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_ext_name"]=2
done
unset _ext_name
for _dbcc_name in "${DBCC_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_dbcc_name"]=1
    NATIVE_REPLAY_PC["$_dbcc_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_dbcc_name"]=2
done
unset _dbcc_name
for _bitop_name in "${BITOP_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_bitop_name"]=1
    NATIVE_REPLAY_PC["$_bitop_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_bitop_name"]=2
done
unset _bitop_name
for _cmp_name in "${CMP_NATIVE_MATRIX_NAMES[@]}"; do
    NATIVE_REPLAY_TESTS["$_cmp_name"]=1
    NATIVE_REPLAY_PC["$_cmp_name"]=0x1000
    NATIVE_REPLAY_COUNT["$_cmp_name"]=2
done
unset _cmp_name
SPECIAL_MEMORY_TESTS[move_core_b_aind_to_dn_special_native]=1
SPECIAL_MEMORY_TESTS[move_core_w_index_to_dn_special_native]=1
SPECIAL_MEMORY_TESTS[move_core_b_absl_to_dn_special_native]=1
SPECIAL_MEMORY_TESTS[move_core_b_dn_to_aind_special_native]=1
SPECIAL_MEMORY_TESTS[move_core_w_dn_to_index_special_native]=1
SPECIAL_MEMORY_TESTS[move_core_b_dn_to_absl_special_native]=1
SPECIAL_MEMORY_TESTS[movea_core_w_aind_special_native]=1
SPECIAL_MEMORY_TESTS[movea_core_w_index_special_native]=1
SPECIAL_MEMORY_TESTS[move16_core_postpost_special_native]=1
SPECIAL_MEMORY_TESTS[scc_core_aind_hi_special_native]=1
SPECIAL_MEMORY_TESTS[scc_core_index_vs_special_native]=1
SPECIAL_MEMORY_TESTS[scc_core_absl_gt_special_native]=1
SPECIAL_MEMORY_TESTS[bitop_core_bchg_imm_aind_zero_special_native]=1
SPECIAL_MEMORY_TESTS[bitop_core_bset_dyn_index_one_special_native]=1
SPECIAL_MEMORY_TESTS[bitop_core_bclr_imm_absl_one_special_native]=1
SPECIAL_MEMORY_TESTS[bitop_core_btst_dyn_aind_set_special_native]=1
SPECIAL_MEMORY_TESTS[cmp_core_b_aind_special_native]=1
SPECIAL_MEMORY_TESTS[cmp_core_w_index_special_native]=1
SPECIAL_MEMORY_TESTS[cmp_core_b_absl_special_native]=1
SPECIAL_MEMORY_TESTS[cmpm_core_w_special_native]=1
SPECIAL_MEMORY_TESTS[cmpa_core_l_aind_special_native]=1
# NOP: trivial decode/execute path sanity check
TESTS[nop]="4E71 4E71"
# Strict-mode zero RAM must be traced once, compiled at L2, and replayed
# natively. Each 0000 0000 pair is ORI.B #0,D0.
TESTS[strict_zero_ram_native]="0000 0000 0000 0000"
# Pass one caches MOVEQ #1 at a host-injected RAM address. The harness then
# rewrites that same address to MOVEQ #2; pass two must retrace it and pass three
# must execute the replacement natively rather than replaying stale code.
TESTS[host_code_reuse_coherence]="7001"
EXPECTED_D0[host_code_reuse_coherence]="00000002"
# Pass one rewrites the mutable body into a stable BRA.W to a MOVEQ #9 target,
# invalidating the traced block. Pass two retraces the rewritten stream without
# further stores. Pass three must retire the stable stream natively and yield 9;
# stale code, missed invalidation, or an interpreter-only replay cannot pass.
TESTS[cache_disabled_selfmod_replay]="6000 003C 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 4E71 7007 31FC 7009 1060 31FC 6000 1040 31FC 001C 1042 4EF8 1060 4E71 4E71 4E71 4E71 7001"
EXPECTED_D0[cache_disabled_selfmod_replay]="00000009"
# Runtime helper register-field decode: 205f is MOVEA.L (A7)+,A0. A second
# native pass must load A0 and restore A7, never byte-swap it into (A0)+,A7.
TESTS[movea_l_sp_postinc_cov]="2F3C 1234 5678 205F"
# MOVEA.L (A0)+,A0: destination assignment wins over source postincrement.
# This must be generated natively rather than hidden behind a runtime override.
TESTS[movea_l_postinc_alias]="207C 0000 9000 20BC 1234 5678 2058"
# ADD.L yields zero; BGT must remain not-taken after end-of-block canonical
# register writeback and branch finalisation reload the architectural NZCV.
TESTS[branch_flush_bgt_zero]="700C 72F4 D280 6E04 7401 6002 7402"
# NOP_TRIPLET: additional decode/dispatch stream-length sanity for repeated NOPs
TESTS[nop_triplet]="4E71 4E71 4E71"
# --- HIGH-RISK OPCODE VECTORS ---
# ROXL_X_PROPAGATION: ORI #0x10,CCR (set X); MOVEQ #1,D0; ROXL.L #1,D0
# X=1 rotates into bit 0, so D0 should become 3, and X/C reflect bit 31 (was 0)
# ORI.B #imm,CCR = 003C 0010; MOVEQ #1,D0 = 7001; ROXL.L #1,D0 = E390
TESTS[roxl_x_propagation]="003C 0010 7001 E390"
# ROXR_X_PROPAGATION: ORI #0x10,CCR (set X); MOVEQ #2,D0; ROXR.L #1,D0
# X=1 rotates into bit 31, so D0=0x80000001, X/C reflect old bit 0 (was 0)
# ORI.B #imm,CCR = 003C 0010; MOVEQ #2,D0 = 7002; ROXR.L #1,D0 = E290
TESTS[roxr_x_propagation]="003C 0010 7002 E290"
# ROXL_COUNT_2: ORI #0x10,CCR (set X); MOVEQ #3,D0; ROXL.L #2,D0
# Rotate left by 2 through X: bit pattern exercise
# ROXL.L #2,D0 = E590
TESTS[roxl_count_2]="003C 0010 7003 E590"
# ASL_OVERFLOW: MOVEQ #0x40,D0; SWAP D0 (D0=0x00400000...wait)
# Actually: MOVE.L #0x40000000,D0; ASL.L #1,D0 → should set V=1
# MOVE.L #imm,D0 = 203C 4000 0000; ASL.L #1,D0 = E380
TESTS[asl_overflow]="203C 4000 0000 E380"
# LSR_COUNT_32: MOVEQ #-1,D0 (0xFFFFFFFF); MOVEQ #32,D1 (0x20); LSR.L D1,D0
# Shift count=32 for .L → D0 should become 0, C=MSB of original
# MOVEQ #-1,D0 = 70FF; MOVEQ #32,D1 = 7220; LSR.L D1,D0 = E2A8
TESTS[lsr_count_32]="70FF 7220 E2A8"
# ASR_COUNT_0: MOVEQ #-1,D0; MOVEQ #0,D1; ASR.L D1,D0
# Shift count=0 → D0 unchanged, C cleared
# MOVEQ #-1,D0 = 70FF; MOVEQ #0,D1 = 7200; ASR.L D1,D0 = E2A0
TESTS[asr_count_0]="70FF 7200 E2A0"
# ROR_WORD: MOVE.L #0x00010000,D0; ROR.W #1,D0
# ROR.W operates on low word only; upper word preserved
# MOVE.L #0x00010000,D0 = 203C 0001 0000; ROR.W #1,D0 = E258
TESTS[ror_word]="203C 0001 0000 E258"
# ROL_WORD: MOVE.L #0xFFFF8001,D0; ROL.W #1,D0
# ROL.W on low word 0x8001 → 0x0003, upper word 0xFFFF preserved
# MOVE.L #0xFFFF8001,D0 = 203C FFFF 8001; ROL.W #1,D0 = E358
TESTS[rol_word]="203C FFFF 8001 E358"
# BTST_REG_HIGH_BIT: MOVEQ #31,D1; MOVE.L #0x80000000,D0; BTST D1,D0
# Register BTST uses bit mod 32, so bit 31 should test set → Z=0
# MOVEQ #31,D1 = 721F; MOVE.L #0x80000000,D0 = 203C 8000 0000; BTST D1,D0 = 0300
TESTS[btst_reg_high_bit]="721F 203C 8000 0000 0300"
# Native byte-EA path: BTST #7,(d16,A0) must use the shared readbyte primitive,
# preserve X/N/V/C, and clear Z for a set high bit.
TESTS[btst_b_d16_highbit]="207C 0000 9000 10BC 0080 44FC 001B 0828 0007 0000 40C1"
# MULS_NEG_NEG: MOVEQ #-3,D0 (0xFFFFFFFD); MOVEQ #-5,D1 (0xFFFFFFFB); MULS D1,D0
# (-3)*(-5) = 15, result in D0.L
# MOVEQ #-3,D0 = 70FD; MOVEQ #-5,D1 = 72FB; MULS D1,D0 = C1C1
TESTS[muls_neg_neg]="70FD 72FB C1C1"
# MULS_ZERO: MOVEQ #0,D0; MOVEQ #-1,D1; MULS D1,D0
# 0 * anything = 0, Z=1, N=0
TESTS[muls_zero]="7000 72FF C1C1"
# DIVS_NEG_NEG: MOVE.L #0xFFFFFFF1,D0 (-15); MOVEQ #-3,D1; DIVS D1,D0
# -15 / -3 = quotient 5, remainder 0
# MOVE.L #0xFFFFFFF1,D0 = 203C FFFF FFF1; MOVEQ #-3,D1 = 72FD; DIVS D1,D0 = 81C1
TESTS[divs_neg_neg]="203C FFFF FFF1 72FD 81C1"
# DIVS_OVERFLOW: MOVE.L #0x00010000,D0 (65536); MOVEQ #1,D1; DIVS D1,D0
# 65536/1 = 65536 which doesn't fit in 16-bit quotient → V=1, operands unchanged
# MOVE.L #0x00010000,D0 = 203C 0001 0000; MOVEQ #1,D1 = 7201; DIVS D1,D0 = 81C1
TESTS[divs_overflow]="203C 0001 0000 7201 81C1"
# ABCD_BASIC: MOVEQ #0x09,D0; MOVEQ #0x09,D1; ABCD D1,D0
# BCD: 09+09=18 → D0.B=0x18
# MOVEQ #9,D0 = 7009; MOVEQ #9,D1 = 7209; ABCD D1,D0 = C101
TESTS[abcd_basic]="7009 7209 C101"
# SBCD_BASIC: MOVEQ #0x18,D0; MOVEQ #0x09,D1; SBCD D1,D0
# BCD: 18-09=09 → D0.B=0x09
# MOVEQ #0x18,D0 = 7018; MOVEQ #9,D1 = 7209; SBCD D1,D0 = 8101
TESTS[sbcd_basic]="7018 7209 8101"
# NEGX_WITH_X: ORI #0x10,CCR (set X); MOVEQ #5,D0; NEGX.L D0
# NEGX = 0 - D0 - X = 0 - 5 - 1 = -6 = 0xFFFFFFFA
# ORI.B #imm,CCR = 003C 0010; MOVEQ #5,D0 = 7005; NEGX.L D0 = 4080
TESTS[negx_with_x]="003C 0010 7005 4080"
# NEGX_ZERO: MOVEQ #0,D0; NEGX.L D0 (with X clear)
# NEGX of 0 with X=0 → result 0, but Z is only cleared if result≠0 (unchanged here)
# ANDI #0xEF,CCR clears X; MOVEQ #0,D0; NEGX.L D0
# ANDI.B #imm,CCR = 023C 00EF; MOVEQ #0,D0 = 7000; NEGX.L D0 = 4080
TESTS[negx_zero]="023C 00EF 7000 4080"
# Exact-opcode ADD matrix. Every case begins at the ADD opcode; B2_TEST_INIT
# supplies the operand/CCR state and exact-PC replay requires native execution.
TESTS[add_core_b_reg_zero_native]="D001"
TESTS[add_core_w_reg_overflow_native]="D041"
TESTS[add_core_l_reg_carry_native]="D081"
TESTS[add_core_b_self_alias_native]="D000"
TESTS[add_core_w_self_alias_native]="D040"
TESTS[add_core_l_self_alias_native]="D080"
TESTS[add_core_b_imm_overflow_native]="0600 0001"
TESTS[add_core_w_imm_carry_native]="0640 FFFF"
TESTS[add_core_l_imm_large_native]="0680 1234 5678"
TESTS[add_core_l_imm_negative_native]="0680 FFFF FFFF"
# Full-SR replacement kills every ADD output flag while preserving the result.
TESTS[add_core_b_reg_noflags_native]="D001 46FC 2700"
TESTS[add_core_w_reg_noflags_native]="D041 46FC 2700"
TESTS[add_core_l_reg_noflags_native]="D081 46FC 2700"
# Readable memory sources retain their source EA and snapshot arithmetic flags.
TESTS[add_core_b_aind_source_special_native]="D011 40C2"
TESTS[add_core_w_postinc_source_native]="D059 40C2"
TESTS[add_core_l_predec_source_native]="D0A1 40C2"
TESTS[add_core_b_d16_source_native]="D029 0010 40C2"
TESTS[add_core_w_index_source_special_native]="D071 2000 40C2"
TESTS[add_core_l_absw_source_native]="D0B8 6000 40C2"
TESTS[add_core_b_absl_source_special_native]="D039 0000 A000 40C2"
TESTS[add_core_w_pc16_source_native]="D07A FFEE 40C2"
TESTS[add_core_l_pcindex_source_native]="D0BB 1000 40C2"
# Writable memory destinations snapshot arithmetic SR, reload the stored result,
# and thereby expose data, EA/writeback, MIDFUNC operands, and pre-write EA ownership.
TESTS[add_core_b_aind_dest_special_native]="D110 40C2 1010"
TESTS[add_core_w_postinc_dest_native]="D158 40C2 3028 FFFE"
TESTS[add_core_l_predec_dest_native]="D1A0 40C2 2010"
TESTS[add_core_b_d16_dest_native]="D128 0010 40C2 1028 0010"
TESTS[add_core_w_index_dest_special_native]="D170 1000 40C2 3030 1000"
TESTS[add_core_l_absw_dest_native]="D1B8 6000 40C2 2038 6000"
TESTS[add_core_b_absl_dest_special_native]="D139 0000 A000 40C2 1039 0000 A000"
TESTS[add_core_b_a7_postinc_dest_native]="D11F 40C2 102F FFFE"
TESTS[add_core_b_a7_predec_dest_native]="D127 40C2 1017"
TESTS[add_core_b_addi_postinc_dest_native]="0618 0001 40C2 1028 FFFF"
TESTS[add_core_b_postinc_dest_native]="D118 40C2 1028 FFFF"
# The SR replacement immediately after ADD makes the postincrement destination
# case a nominal no-flags path; the later reload validates stored data only.
TESTS[add_core_b_postinc_dest_noflags_native]="D118 46FC 2700 1028 FFFF"
EXPECTED_REG_FIELDS[add_core_b_reg_zero_native]="D0=A5A50000 D1=00000001 SR=2715"
EXPECTED_REG_FIELDS[add_core_w_reg_overflow_native]="D0=A5A58000 D1=00000001 SR=270A"
EXPECTED_REG_FIELDS[add_core_l_reg_carry_native]="D0=00000000 D1=00000001 SR=2715"
EXPECTED_REG_FIELDS[add_core_b_self_alias_native]="D0=A5A50000 SR=2717"
EXPECTED_REG_FIELDS[add_core_w_self_alias_native]="D0=A5A50000 SR=2717"
EXPECTED_REG_FIELDS[add_core_l_self_alias_native]="D0=00000000 SR=2717"
EXPECTED_REG_FIELDS[add_core_b_imm_overflow_native]="D0=A5A50080 SR=270A"
EXPECTED_REG_FIELDS[add_core_w_imm_carry_native]="D0=A5A50000 SR=2715"
EXPECTED_REG_FIELDS[add_core_l_imm_large_native]="D0=12345679 SR=2700"
EXPECTED_REG_FIELDS[add_core_l_imm_negative_native]="D0=00000000 SR=2715"
EXPECTED_REG_FIELDS[add_core_b_reg_noflags_native]="D0=A5A50080 D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[add_core_w_reg_noflags_native]="D0=A5A58000 D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[add_core_l_reg_noflags_native]="D0=80000000 D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[add_core_b_aind_source_special_native]="D0=A5A50080 D2=0000270A A1=0000A000 SR=270A"
EXPECTED_REG_FIELDS[add_core_w_postinc_source_native]="D0=A5A50000 D2=00002715 A1=0000A002 SR=2715"
EXPECTED_REG_FIELDS[add_core_l_predec_source_native]="D0=80000000 D2=0000270A A1=0000A000 SR=270A"
EXPECTED_REG_FIELDS[add_core_b_d16_source_native]="D0=A5A50000 D2=00002715 A1=0000A000 SR=2715"
EXPECTED_REG_FIELDS[add_core_w_index_source_special_native]="D0=A5A58000 D2=0000270A A1=0000A000 SR=270A"
EXPECTED_REG_FIELDS[add_core_l_absw_source_native]="D0=00000000 D2=00002715 SR=2715"
EXPECTED_REG_FIELDS[add_core_b_absl_source_special_native]="D0=A5A50000 D2=00002715 SR=2715"
EXPECTED_REG_FIELDS[add_core_w_pc16_source_native]="D0=A5A58000 D2=0000270A SR=270A"
EXPECTED_REG_FIELDS[add_core_l_pcindex_source_native]="D0=00000000 D1=FFFFFFEE D2=00002715 SR=2715"
EXPECTED_REG_FIELDS[add_core_b_aind_dest_special_native]="D0=A5A50000 D2=00002715 A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[add_core_w_postinc_dest_native]="D0=A5A50000 D2=00002715 A0=0000A002 SR=2714"
EXPECTED_REG_FIELDS[add_core_l_predec_dest_native]="D0=00000000 D2=00002715 A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_d16_dest_native]="D0=A5A50000 D2=00002715 A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[add_core_w_index_dest_special_native]="D0=A5A58000 D1=00000002 D2=0000270A A0=0000A000 SR=2708"
EXPECTED_REG_FIELDS[add_core_l_absw_dest_native]="D0=00000000 D2=00002715 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_absl_dest_special_native]="D0=A5A50000 D2=00002715 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_a7_postinc_dest_native]="D0=A5A50000 D2=00002715 A7=0000A002 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_a7_predec_dest_native]="D0=A5A50000 D2=00002715 A7=0000A000 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_addi_postinc_dest_native]="D0=A5A50000 D2=00002715 A0=0000A001 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_postinc_dest_native]="D0=A5A50000 D2=00002715 A0=0000A001 SR=2714"
EXPECTED_REG_FIELDS[add_core_b_postinc_dest_noflags_native]="D0=A5A50080 A0=0000A001 SR=2708"
TEST_MEMORY_BYTES[add_core_b_aind_source_special_native]="A000 01"
TEST_MEMORY_BYTES[add_core_w_postinc_source_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[add_core_l_predec_source_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[add_core_b_d16_source_native]="A010 FF"
TEST_MEMORY_BYTES[add_core_w_index_source_special_native]="A002 00 A003 01"
TEST_MEMORY_BYTES[add_core_l_absw_source_native]="6000 00 6001 00 6002 00 6003 01"
TEST_MEMORY_BYTES[add_core_b_absl_source_special_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_w_pc16_source_native]="0FF0 00 0FF1 01"
TEST_MEMORY_BYTES[add_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"
TEST_MEMORY_BYTES[add_core_b_aind_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_w_postinc_dest_native]="A000 FF A001 FF"
TEST_MEMORY_BYTES[add_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
TEST_MEMORY_BYTES[add_core_b_d16_dest_native]="A010 FF"
TEST_MEMORY_BYTES[add_core_w_index_dest_special_native]="A002 7F A003 FF"
TEST_MEMORY_BYTES[add_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[add_core_b_absl_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_b_a7_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_b_a7_predec_dest_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_b_addi_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_b_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[add_core_b_postinc_dest_noflags_native]="A000 7F"

# Exact-opcode AND matrix. Register forms begin at the audited opcode and prove
# width truncation, upper-lane preservation, N/Z, V/C clear, X preservation,
# immediate/constant lowering, aliases, and no-flags selection. Memory forms
# cover every legal source/destination EA and snapshot SR before verification.
TESTS[and_core_b_reg_zero_native]="C001"
TESTS[and_core_w_reg_negative_native]="C041"
TESTS[and_core_l_reg_positive_native]="C081"
TESTS[and_core_b_self_alias_native]="C000"
TESTS[and_core_w_self_alias_native]="C040"
TESTS[and_core_l_self_alias_native]="C080"
TESTS[and_core_b_imm_zero_native]="0200 0000"
TESTS[and_core_w_imm_negative_native]="0240 8000"
TESTS[and_core_l_imm_pattern_native]="0280 1234 5678"
TESTS[and_core_l_imm_negative_native]="0280 8000 0000"
# Full-SR replacement kills every AND output flag while preserving the result.
TESTS[and_core_b_reg_noflags_native]="C001 46FC 2700"
TESTS[and_core_w_reg_noflags_native]="C041 46FC 2700"
TESTS[and_core_l_reg_noflags_native]="C081 46FC 2700"
TESTS[and_core_b_aind_source_special_native]="C011 40C2"
TESTS[and_core_w_postinc_source_native]="C059 40C2"
TESTS[and_core_l_predec_source_native]="C0A1 40C2"
TESTS[and_core_b_d16_source_native]="C029 0010 40C2"
TESTS[and_core_w_index_source_special_native]="C071 2000 40C2"
TESTS[and_core_l_absw_source_native]="C0B8 6000 40C2"
TESTS[and_core_b_absl_source_special_native]="C039 0000 A000 40C2"
TESTS[and_core_w_pc16_source_native]="C07A FFEE 40C2"
TESTS[and_core_l_pcindex_source_native]="C0BB 1000 40C2"
TESTS[and_core_b_aind_dest_special_native]="C110 40C2 1010"
TESTS[and_core_w_postinc_dest_native]="C158 40C2 3028 FFFE"
TESTS[and_core_l_predec_dest_native]="C1A0 40C2 2010"
TESTS[and_core_b_d16_dest_native]="C128 0010 40C2 1028 0010"
TESTS[and_core_w_index_dest_special_native]="C170 1000 40C2 3030 1000"
TESTS[and_core_l_absw_dest_native]="C1B8 6000 40C2 2038 6000"
TESTS[and_core_b_absl_dest_special_native]="C139 0000 A000 40C2 1039 0000 A000"
TESTS[and_core_b_a7_postinc_dest_native]="C11F 40C2 102F FFFE"
TESTS[and_core_b_a7_predec_dest_native]="C127 40C2 1017"
TESTS[and_core_b_andi_postinc_dest_native]="0218 000F 40C2 1028 FFFF"
TESTS[and_core_b_postinc_dest_native]="C118 40C2 1028 FFFF"
TESTS[and_core_b_postinc_dest_noflags_native]="C118 46FC 2700 1028 FFFF"
EXPECTED_REG_FIELDS[and_core_b_reg_zero_native]="D0=A5A50000 D1=00000000 SR=2714"
EXPECTED_REG_FIELDS[and_core_w_reg_negative_native]="D0=A5A58000 D1=00008000 SR=2718"
EXPECTED_REG_FIELDS[and_core_l_reg_positive_native]="D0=7FFFFFFF D1=7FFFFFFF SR=2710"
EXPECTED_REG_FIELDS[and_core_b_self_alias_native]="D0=A5A50080 SR=2718"
EXPECTED_REG_FIELDS[and_core_w_self_alias_native]="D0=A5A58000 SR=2718"
EXPECTED_REG_FIELDS[and_core_l_self_alias_native]="D0=80000000 SR=2718"
EXPECTED_REG_FIELDS[and_core_b_imm_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[and_core_w_imm_negative_native]="D0=A5A58000 SR=2718"
EXPECTED_REG_FIELDS[and_core_l_imm_pattern_native]="D0=12345678 SR=2710"
EXPECTED_REG_FIELDS[and_core_l_imm_negative_native]="D0=80000000 SR=2718"
EXPECTED_REG_FIELDS[and_core_b_reg_noflags_native]="D0=A5A5000F D1=0000000F SR=2700"
EXPECTED_REG_FIELDS[and_core_w_reg_noflags_native]="D0=A5A50F0F D1=00000F0F SR=2700"
EXPECTED_REG_FIELDS[and_core_l_reg_noflags_native]="D0=0F0F0F0F D1=0F0F0F0F SR=2700"
EXPECTED_REG_FIELDS[and_core_b_aind_source_special_native]="D0=A5A50000 D2=00002714 A1=0000A000 SR=2714"
EXPECTED_REG_FIELDS[and_core_w_postinc_source_native]="D0=A5A50000 D2=00002714 A1=0000A002 SR=2714"
EXPECTED_REG_FIELDS[and_core_l_predec_source_native]="D0=80000000 D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[and_core_b_d16_source_native]="D0=A5A5000F D2=00002710 A1=0000A000 SR=2710"
EXPECTED_REG_FIELDS[and_core_w_index_source_special_native]="D0=A5A58000 D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[and_core_l_absw_source_native]="D0=00000000 D2=00002714 SR=2714"
EXPECTED_REG_FIELDS[and_core_b_absl_source_special_native]="D0=A5A500F0 D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[and_core_w_pc16_source_native]="D0=A5A500FF D2=00002710 SR=2710"
EXPECTED_REG_FIELDS[and_core_l_pcindex_source_native]="D0=80000000 D1=FFFFFFEE D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[and_core_b_aind_dest_special_native]="D0=A5A5000F D2=00002710 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[and_core_w_postinc_dest_native]="D0=A5A50F0F D2=00002710 A0=0000A002 SR=2710"
EXPECTED_REG_FIELDS[and_core_l_predec_dest_native]="D0=0F0F0F0F D2=00002710 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_d16_dest_native]="D0=A5A5000F D2=00002710 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[and_core_w_index_dest_special_native]="D0=A5A58000 D1=00000002 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[and_core_l_absw_dest_native]="D0=0F0F0F0F D2=00002710 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_absl_dest_special_native]="D0=A5A5000F D2=00002710 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_a7_postinc_dest_native]="D0=A5A5000F D2=00002710 A7=0000A002 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_a7_predec_dest_native]="D0=A5A5000F D2=00002710 A7=0000A000 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_andi_postinc_dest_native]="D0=A5A5000F D2=00002710 A0=0000A001 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_postinc_dest_native]="D0=A5A5000F D2=00002710 A0=0000A001 SR=2710"
EXPECTED_REG_FIELDS[and_core_b_postinc_dest_noflags_native]="D0=A5A5000F A0=0000A001 SR=2700"
TEST_MEMORY_BYTES[and_core_b_aind_source_special_native]="A000 0F"
TEST_MEMORY_BYTES[and_core_w_postinc_source_native]="A000 0F A001 0F"
TEST_MEMORY_BYTES[and_core_l_predec_source_native]="A000 80 A001 00 A002 00 A003 00"
TEST_MEMORY_BYTES[and_core_b_d16_source_native]="A010 0F"
TEST_MEMORY_BYTES[and_core_w_index_source_special_native]="A002 80 A003 00"
TEST_MEMORY_BYTES[and_core_l_absw_source_native]="6000 0F 6001 0F 6002 0F 6003 0F"
TEST_MEMORY_BYTES[and_core_b_absl_source_special_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_w_pc16_source_native]="0FF0 00 0FF1 FF"
TEST_MEMORY_BYTES[and_core_l_pcindex_source_native]="0FF0 80 0FF1 00 0FF2 00 0FF3 00"
TEST_MEMORY_BYTES[and_core_b_aind_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_w_postinc_dest_native]="A000 FF A001 FF"
TEST_MEMORY_BYTES[and_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
TEST_MEMORY_BYTES[and_core_b_d16_dest_native]="A010 FF"
TEST_MEMORY_BYTES[and_core_w_index_dest_special_native]="A002 FF A003 FF"
TEST_MEMORY_BYTES[and_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[and_core_b_absl_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_b_a7_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_b_a7_predec_dest_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_b_andi_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_b_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[and_core_b_postinc_dest_noflags_native]="A000 FF"

# Exact-opcode EOR matrix. Dn/immediate sources cover all twelve flag-live and
# no-flags MIDFUNC routes, aliases, W upper-lane preservation, N/Z, mandatory
# V/C clear, X preservation, and every writable destination EA. Memory routes
# snapshot SR before exact readback; no-flags routes overwrite SR immediately.
TESTS[eor_core_b_reg_zero_native]="B300"
TESTS[eor_core_w_reg_negative_native]="B340"
TESTS[eor_core_l_reg_positive_native]="B380"
TESTS[eor_core_b_self_alias_native]="B100"
TESTS[eor_core_w_self_alias_native]="B140"
TESTS[eor_core_l_self_alias_native]="B180"
TESTS[eor_core_b_imm_zero_native]="0A00 00FF"
TESTS[eor_core_w_imm_negative_native]="0A40 FFFF"
TESTS[eor_core_l_imm_pattern_native]="0A80 1234 5678"
TESTS[eor_core_l_imm_negative_native]="0A80 8000 0000"
TESTS[eor_core_b_reg_noflags_native]="B300 46FC 2700"
TESTS[eor_core_w_reg_noflags_native]="B340 46FC 2700"
TESTS[eor_core_l_reg_noflags_native]="B380 46FC 2700"
TESTS[eor_core_b_imm_noflags_native]="0A00 000F 46FC 2700"
TESTS[eor_core_w_imm_noflags_native]="0A40 0F0F 46FC 2700"
TESTS[eor_core_l_imm_noflags_native]="0A80 0F0F 0F0F 46FC 2700"
TESTS[eor_core_b_aind_dest_special_native]="B110 40C2 1010"
TESTS[eor_core_w_postinc_dest_native]="B158 40C2 3028 FFFE"
TESTS[eor_core_l_predec_dest_native]="B1A0 40C2 2010"
TESTS[eor_core_b_d16_dest_native]="B128 0010 40C2 1028 0010"
TESTS[eor_core_w_index_dest_special_native]="B170 1000 40C2 3030 1000"
TESTS[eor_core_l_absw_dest_native]="B1B8 6000 40C2 2038 6000"
TESTS[eor_core_b_absl_dest_special_native]="B139 0000 A000 40C2 1039 0000 A000"
TESTS[eor_core_b_a7_postinc_dest_native]="B11F 40C2 102F FFFE"
TESTS[eor_core_b_a7_predec_dest_native]="B127 40C2 1017"
TESTS[eor_core_b_eori_postinc_dest_native]="0A18 000F 40C2 1028 FFFF"
TESTS[eor_core_b_postinc_dest_native]="B118 40C2 1028 FFFF"
TESTS[eor_core_b_postinc_dest_noflags_native]="B118 46FC 2700 1028 FFFF"
EXPECTED_REG_FIELDS[eor_core_b_reg_zero_native]="D0=A5A50000 D1=000000FF SR=2714"
EXPECTED_REG_FIELDS[eor_core_w_reg_negative_native]="D0=A5A58000 D1=0000FFFF SR=2718"
EXPECTED_REG_FIELDS[eor_core_l_reg_positive_native]="D0=7FFFFFFF D1=80000000 SR=2710"
EXPECTED_REG_FIELDS[eor_core_b_self_alias_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[eor_core_w_self_alias_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[eor_core_l_self_alias_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[eor_core_b_imm_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[eor_core_w_imm_negative_native]="D0=A5A58000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_l_imm_pattern_native]="D0=12345678 SR=2710"
EXPECTED_REG_FIELDS[eor_core_l_imm_negative_native]="D0=80000000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_reg_noflags_native]="D0=A5A500FF D1=0000000F SR=2700"
EXPECTED_REG_FIELDS[eor_core_w_reg_noflags_native]="D0=A5A5FFFF D1=00000F0F SR=2700"
EXPECTED_REG_FIELDS[eor_core_l_reg_noflags_native]="D0=FFFFFFFF D1=0F0F0F0F SR=2700"
EXPECTED_REG_FIELDS[eor_core_b_imm_noflags_native]="D0=A5A500FF SR=2700"
EXPECTED_REG_FIELDS[eor_core_w_imm_noflags_native]="D0=A5A5FFFF SR=2700"
EXPECTED_REG_FIELDS[eor_core_l_imm_noflags_native]="D0=FFFFFFFF SR=2700"
EXPECTED_REG_FIELDS[eor_core_b_aind_dest_special_native]="D0=A5A500F0 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_w_postinc_dest_native]="D0=A5A5F0F0 D2=00002718 A0=0000A002 SR=2718"
EXPECTED_REG_FIELDS[eor_core_l_predec_dest_native]="D0=F0F0F0F0 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_d16_dest_native]="D0=A5A500F0 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_w_index_dest_special_native]="D0=A5A5F0F0 D1=00000002 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_l_absw_dest_native]="D0=F0F0F0F0 D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_absl_dest_special_native]="D0=A5A500F0 D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_a7_postinc_dest_native]="D0=A5A500F0 D2=00002718 A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_a7_predec_dest_native]="D0=A5A500F0 D2=00002718 A7=0000A000 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_eori_postinc_dest_native]="D0=A5A500F0 D2=00002718 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_postinc_dest_native]="D0=A5A500FF D2=00002718 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[eor_core_b_postinc_dest_noflags_native]="D0=A5A500F0 A0=0000A001 SR=2708"
TEST_MEMORY_BYTES[eor_core_b_aind_dest_special_native]="A000 F0"
TEST_MEMORY_BYTES[eor_core_w_postinc_dest_native]="A000 F0 A001 F0"
TEST_MEMORY_BYTES[eor_core_l_predec_dest_native]="A000 F0 A001 F0 A002 F0 A003 F0"
TEST_MEMORY_BYTES[eor_core_b_d16_dest_native]="A010 F0"
TEST_MEMORY_BYTES[eor_core_w_index_dest_special_native]="A002 F0 A003 F0"
TEST_MEMORY_BYTES[eor_core_l_absw_dest_native]="6000 F0 6001 F0 6002 F0 6003 F0"
TEST_MEMORY_BYTES[eor_core_b_absl_dest_special_native]="A000 F0"
TEST_MEMORY_BYTES[eor_core_b_a7_postinc_dest_native]="A000 F0"
TEST_MEMORY_BYTES[eor_core_b_a7_predec_dest_native]="A000 F0"
TEST_MEMORY_BYTES[eor_core_b_eori_postinc_dest_native]="A000 F0"
TEST_MEMORY_BYTES[eor_core_b_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[eor_core_b_postinc_dest_noflags_native]="A000 F0"

# Exact-opcode OR matrix. Register and immediate forms prove all twelve
# flag-live/no-flags routes, aliases, narrow upper-lane preservation, N/Z,
# mandatory V/C clear, and X preservation. Memory forms cover all readable
# source and writable destination EAs and snapshot SR before exact readback.
TESTS[or_core_b_reg_zero_native]="8001"
TESTS[or_core_w_reg_negative_native]="8041"
TESTS[or_core_l_reg_positive_native]="8081"
TESTS[or_core_b_self_alias_native]="8000"
TESTS[or_core_w_self_alias_native]="8040"
TESTS[or_core_l_self_alias_native]="8080"
TESTS[or_core_b_imm_zero_native]="0000 0000"
TESTS[or_core_w_imm_negative_native]="0040 8000"
TESTS[or_core_l_imm_pattern_native]="0080 1234 5678"
TESTS[or_core_l_imm_negative_native]="0080 8000 0000"
TESTS[or_core_b_reg_noflags_native]="8001 46FC 2700"
TESTS[or_core_w_reg_noflags_native]="8041 46FC 2700"
TESTS[or_core_l_reg_noflags_native]="8081 46FC 2700"
TESTS[or_core_b_imm_noflags_native]="0000 000F 46FC 2700"
TESTS[or_core_w_imm_noflags_native]="0040 0F0F 46FC 2700"
TESTS[or_core_l_imm_noflags_native]="0080 0F0F 0F0F 46FC 2700"
TESTS[or_core_b_aind_source_special_native]="8011 40C2"
TESTS[or_core_w_postinc_source_native]="8059 40C2"
TESTS[or_core_l_predec_source_native]="80A1 40C2"
TESTS[or_core_b_d16_source_native]="8029 0010 40C2"
TESTS[or_core_w_index_source_special_native]="8071 2000 40C2"
TESTS[or_core_l_absw_source_native]="80B8 6000 40C2"
TESTS[or_core_b_absl_source_special_native]="8039 0000 A000 40C2"
TESTS[or_core_w_pc16_source_native]="807A FFEE 40C2"
TESTS[or_core_l_pcindex_source_native]="80BB 1000 40C2"
TESTS[or_core_b_aind_dest_special_native]="8110 40C2 1010"
TESTS[or_core_w_postinc_dest_native]="8158 40C2 3028 FFFE"
TESTS[or_core_l_predec_dest_native]="81A0 40C2 2010"
TESTS[or_core_b_d16_dest_native]="8128 0010 40C2 1028 0010"
TESTS[or_core_w_index_dest_special_native]="8170 1000 40C2 3030 1000"
TESTS[or_core_l_absw_dest_native]="81B8 6000 40C2 2038 6000"
TESTS[or_core_b_absl_dest_special_native]="8139 0000 A000 40C2 1039 0000 A000"
TESTS[or_core_b_a7_postinc_dest_native]="811F 40C2 102F FFFE"
TESTS[or_core_b_a7_predec_dest_native]="8127 40C2 1017"
TESTS[or_core_b_ori_postinc_dest_native]="0018 000F 40C2 1028 FFFF"
TESTS[or_core_b_postinc_dest_native]="8118 40C2 1028 FFFF"
TESTS[or_core_b_postinc_dest_noflags_native]="8118 46FC 2700 1028 FFFF"
EXPECTED_REG_FIELDS[or_core_b_reg_zero_native]="D0=A5A50000 D1=00000000 SR=2714"
EXPECTED_REG_FIELDS[or_core_w_reg_negative_native]="D0=A5A58000 D1=00008000 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_reg_positive_native]="D0=7FFFFFFF D1=0FFFFFFF SR=2710"
EXPECTED_REG_FIELDS[or_core_b_self_alias_native]="D0=A5A50080 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_self_alias_native]="D0=A5A58000 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_self_alias_native]="D0=80000000 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_imm_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[or_core_w_imm_negative_native]="D0=A5A58000 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_imm_pattern_native]="D0=12345678 SR=2710"
EXPECTED_REG_FIELDS[or_core_l_imm_negative_native]="D0=80000000 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_reg_noflags_native]="D0=A5A500FF D1=0000000F SR=2700"
EXPECTED_REG_FIELDS[or_core_w_reg_noflags_native]="D0=A5A5FFFF D1=00000F0F SR=2700"
EXPECTED_REG_FIELDS[or_core_l_reg_noflags_native]="D0=FFFFFFFF D1=0F0F0F0F SR=2700"
EXPECTED_REG_FIELDS[or_core_b_imm_noflags_native]="D0=A5A500FF SR=2700"
EXPECTED_REG_FIELDS[or_core_w_imm_noflags_native]="D0=A5A5FFFF SR=2700"
EXPECTED_REG_FIELDS[or_core_l_imm_noflags_native]="D0=FFFFFFFF SR=2700"
EXPECTED_REG_FIELDS[or_core_b_aind_source_special_native]="D0=A5A500FF D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_postinc_source_native]="D0=A5A5FFFF D2=00002718 A1=0000A002 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_predec_source_native]="D0=8F0F0F0F D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_d16_source_native]="D0=A5A500FF D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_index_source_special_native]="D0=A5A580F0 D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_absw_source_native]="D0=FFFFFFFF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_absl_source_special_native]="D0=A5A500FF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_pc16_source_native]="D0=A5A5FFFF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_pcindex_source_native]="D0=FF000000 D1=FFFFFFEE D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_aind_dest_special_native]="D0=A5A500FF D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_postinc_dest_native]="D0=A5A5FFFF D2=00002718 A0=0000A002 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_predec_dest_native]="D0=FFFFFFFF D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_d16_dest_native]="D0=A5A500FF D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_w_index_dest_special_native]="D0=A5A5FFFF D1=00000002 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_l_absw_dest_native]="D0=FFFFFFFF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_absl_dest_special_native]="D0=A5A500FF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_a7_postinc_dest_native]="D0=A5A500FF D2=00002718 A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_a7_predec_dest_native]="D0=A5A500FF D2=00002718 A7=0000A000 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_ori_postinc_dest_native]="D0=A5A500FF D2=00002718 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_postinc_dest_native]="D0=A5A500FF D2=00002718 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[or_core_b_postinc_dest_noflags_native]="D0=A5A500FF A0=0000A001 SR=2708"
TEST_MEMORY_BYTES[or_core_b_aind_source_special_native]="A000 0F"
TEST_MEMORY_BYTES[or_core_w_postinc_source_native]="A000 0F A001 0F"
TEST_MEMORY_BYTES[or_core_l_predec_source_native]="A000 80 A001 00 A002 00 A003 00"
TEST_MEMORY_BYTES[or_core_b_d16_source_native]="A010 0F"
TEST_MEMORY_BYTES[or_core_w_index_source_special_native]="A002 80 A003 00"
TEST_MEMORY_BYTES[or_core_l_absw_source_native]="6000 0F 6001 0F 6002 0F 6003 0F"
TEST_MEMORY_BYTES[or_core_b_absl_source_special_native]="A000 F0"
TEST_MEMORY_BYTES[or_core_w_pc16_source_native]="0FF0 00 0FF1 FF"
TEST_MEMORY_BYTES[or_core_l_pcindex_source_native]="0FF0 80 0FF1 00 0FF2 00 0FF3 00"
TEST_MEMORY_BYTES[or_core_b_aind_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_w_postinc_dest_native]="A000 FF A001 FF"
TEST_MEMORY_BYTES[or_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
TEST_MEMORY_BYTES[or_core_b_d16_dest_native]="A010 FF"
TEST_MEMORY_BYTES[or_core_w_index_dest_special_native]="A002 FF A003 FF"
TEST_MEMORY_BYTES[or_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[or_core_b_absl_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_b_a7_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_b_a7_predec_dest_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_b_ori_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_b_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[or_core_b_postinc_dest_noflags_native]="A000 FF"

# Exact-opcode SUB matrix. Every case begins at the SUB opcode; exact-PC replay
# requires native entry. Arithmetic cases cover NZVCX, aliases, all twelve
# register/immediate flag-live/no-flags routes, and narrow upper-lane retention.
TESTS[sub_core_b_reg_zero_native]="9001"
TESTS[sub_core_w_reg_overflow_native]="9041"
TESTS[sub_core_l_reg_borrow_native]="9081"
TESTS[sub_core_b_self_alias_native]="9000"
TESTS[sub_core_w_self_alias_native]="9040"
TESTS[sub_core_l_self_alias_native]="9080"
TESTS[sub_core_b_imm_overflow_native]="0400 0001"
TESTS[sub_core_w_imm_borrow_native]="0440 0001"
TESTS[sub_core_l_imm_large_native]="0480 1234 5678"
TESTS[sub_core_l_imm_negative_native]="0480 FFFF FFFF"
TESTS[sub_core_b_reg_noflags_native]="9001 46FC 2700"
TESTS[sub_core_w_reg_noflags_native]="9041 46FC 2700"
TESTS[sub_core_l_reg_noflags_native]="9081 46FC 2700"
TESTS[sub_core_b_imm_noflags_native]="0400 0001 46FC 2700"
TESTS[sub_core_w_imm_noflags_native]="0440 0001 46FC 2700"
TESTS[sub_core_l_imm_noflags_native]="0480 0000 0001 46FC 2700"
# Readable memory sources retain their source EA and snapshot arithmetic flags.
TESTS[sub_core_b_aind_source_special_native]="9011 40C2"
TESTS[sub_core_w_postinc_source_native]="9059 40C2"
TESTS[sub_core_l_predec_source_native]="90A1 40C2"
TESTS[sub_core_b_d16_source_native]="9029 0010 40C2"
TESTS[sub_core_w_index_source_special_native]="9071 2000 40C2"
TESTS[sub_core_l_absw_source_native]="90B8 6000 40C2"
TESTS[sub_core_b_absl_source_special_native]="9039 0000 A000 40C2"
TESTS[sub_core_w_pc16_source_native]="907A FFEE 40C2"
TESTS[sub_core_l_pcindex_source_native]="90BB 1000 40C2"
# Writable destinations expose ordered storage and pre-write EA ownership.
TESTS[sub_core_b_aind_dest_special_native]="9110 40C2 1010"
TESTS[sub_core_w_postinc_dest_native]="9158 40C2 3028 FFFE"
TESTS[sub_core_l_predec_dest_native]="91A0 40C2 2010"
TESTS[sub_core_b_d16_dest_native]="9128 0010 40C2 1028 0010"
TESTS[sub_core_w_index_dest_special_native]="9170 1000 40C2 3030 1000"
TESTS[sub_core_l_absw_dest_native]="91B8 6000 40C2 2038 6000"
TESTS[sub_core_b_absl_dest_special_native]="9139 0000 A000 40C2 1039 0000 A000"
TESTS[sub_core_b_a7_postinc_dest_native]="911F 40C2 102F FFFE"
TESTS[sub_core_b_a7_predec_dest_native]="9127 40C2 1017"
TESTS[sub_core_b_subi_postinc_dest_native]="0418 0001 40C2 1028 FFFF"
TESTS[sub_core_b_postinc_dest_native]="9118 40C2 1028 FFFF"
TESTS[sub_core_b_postinc_dest_noflags_native]="9118 46FC 2700 1028 FFFF"
EXPECTED_REG_FIELDS[sub_core_b_reg_zero_native]="D0=A5A50000 D1=00000001 SR=2704"
EXPECTED_REG_FIELDS[sub_core_w_reg_overflow_native]="D0=A5A57FFF D1=00000001 SR=2702"
EXPECTED_REG_FIELDS[sub_core_l_reg_borrow_native]="D0=FFFFFFFF D1=00000001 SR=2719"
EXPECTED_REG_FIELDS[sub_core_b_self_alias_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[sub_core_w_self_alias_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[sub_core_l_self_alias_native]="D0=00000000 SR=2704"
EXPECTED_REG_FIELDS[sub_core_b_imm_overflow_native]="D0=A5A5007F SR=2702"
EXPECTED_REG_FIELDS[sub_core_w_imm_borrow_native]="D0=A5A5FFFF SR=2719"
EXPECTED_REG_FIELDS[sub_core_l_imm_large_native]="D0=00000001 SR=2700"
EXPECTED_REG_FIELDS[sub_core_l_imm_negative_native]="D0=00000001 SR=2711"
EXPECTED_REG_FIELDS[sub_core_b_reg_noflags_native]="D0=A5A5007F D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[sub_core_w_reg_noflags_native]="D0=A5A57FFF D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[sub_core_l_reg_noflags_native]="D0=7FFFFFFF D1=00000001 SR=2700"
EXPECTED_REG_FIELDS[sub_core_b_imm_noflags_native]="D0=A5A5007F SR=2700"
EXPECTED_REG_FIELDS[sub_core_w_imm_noflags_native]="D0=A5A57FFF SR=2700"
EXPECTED_REG_FIELDS[sub_core_l_imm_noflags_native]="D0=7FFFFFFF SR=2700"
EXPECTED_REG_FIELDS[sub_core_b_aind_source_special_native]="D0=A5A5007F D2=00002702 A1=0000A000 SR=2702"
EXPECTED_REG_FIELDS[sub_core_w_postinc_source_native]="D0=A5A5FFFF D2=00002719 A1=0000A002 SR=2719"
EXPECTED_REG_FIELDS[sub_core_l_predec_source_native]="D0=7FFFFFFF D2=00002702 A1=0000A000 SR=2702"
EXPECTED_REG_FIELDS[sub_core_b_d16_source_native]="D0=A5A50001 D2=00002711 A1=0000A000 SR=2711"
EXPECTED_REG_FIELDS[sub_core_w_index_source_special_native]="D0=A5A57FFF D2=00002702 A1=0000A000 SR=2702"
EXPECTED_REG_FIELDS[sub_core_l_absw_source_native]="D0=FFFFFFFF D2=00002719 SR=2719"
EXPECTED_REG_FIELDS[sub_core_b_absl_source_special_native]="D0=A5A50001 D2=00002711 SR=2711"
EXPECTED_REG_FIELDS[sub_core_w_pc16_source_native]="D0=A5A57FFF D2=00002702 SR=2702"
EXPECTED_REG_FIELDS[sub_core_l_pcindex_source_native]="D0=FFFFFFFF D1=FFFFFFEE D2=00002719 SR=2719"
EXPECTED_REG_FIELDS[sub_core_b_aind_dest_special_native]="D0=A5A500FF D2=00002719 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[sub_core_w_postinc_dest_native]="D0=A5A5FFFF D2=00002719 A0=0000A002 SR=2718"
EXPECTED_REG_FIELDS[sub_core_l_predec_dest_native]="D0=FFFFFFFF D2=00002719 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_d16_dest_native]="D0=A5A500FF D2=00002719 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[sub_core_w_index_dest_special_native]="D0=A5A57FFF D1=00000002 D2=00002702 A0=0000A000 SR=2700"
EXPECTED_REG_FIELDS[sub_core_l_absw_dest_native]="D0=FFFFFFFF D2=00002719 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_absl_dest_special_native]="D0=A5A500FF D2=00002719 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_a7_postinc_dest_native]="D0=A5A500FF D2=00002719 A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_a7_predec_dest_native]="D0=A5A500FF D2=00002719 A7=0000A000 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_subi_postinc_dest_native]="D0=A5A500FF D2=00002719 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_postinc_dest_native]="D0=A5A500FF D2=00002719 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[sub_core_b_postinc_dest_noflags_native]="D0=A5A500FF A0=0000A001 SR=2708"
TEST_MEMORY_BYTES[sub_core_b_aind_source_special_native]="A000 01"
TEST_MEMORY_BYTES[sub_core_w_postinc_source_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[sub_core_l_predec_source_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[sub_core_b_d16_source_native]="A010 FF"
TEST_MEMORY_BYTES[sub_core_w_index_source_special_native]="A002 00 A003 01"
TEST_MEMORY_BYTES[sub_core_l_absw_source_native]="6000 00 6001 00 6002 00 6003 01"
TEST_MEMORY_BYTES[sub_core_b_absl_source_special_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_w_pc16_source_native]="0FF0 00 0FF1 01"
TEST_MEMORY_BYTES[sub_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"
TEST_MEMORY_BYTES[sub_core_b_aind_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_w_postinc_dest_native]="A000 FF A001 FF"
TEST_MEMORY_BYTES[sub_core_l_predec_dest_native]="A000 FF A001 FF A002 FF A003 FF"
TEST_MEMORY_BYTES[sub_core_b_d16_dest_native]="A010 FF"
TEST_MEMORY_BYTES[sub_core_w_index_dest_special_native]="A002 7F A003 FF"
TEST_MEMORY_BYTES[sub_core_l_absw_dest_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[sub_core_b_absl_dest_special_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_b_a7_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_b_a7_predec_dest_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_b_subi_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_b_postinc_dest_native]="A000 FF"
TEST_MEMORY_BYTES[sub_core_b_postinc_dest_noflags_native]="A000 FF"

# ADDA matrix. Twenty-seven dynamic cases begin at ADDA and require exact-native
# entry. Two constant-destination cases begin with LEA and prove folding by
# equivalence because a fully folded ADDA has no host instruction to enter.
# MOVE SR,D3 makes complete XNZVC preservation externally visible; the two
# no-flags cases overwrite SR after ADDA to select the nominal comp_nf table.
TESTS[adda_core_w_dreg_positive_native]="D0C0 40C3"
TESTS[adda_core_w_dreg_negative_native]="D0C0 40C3"
TESTS[adda_core_l_dreg_wrap_native]="D1C0 40C3"
TESTS[adda_core_w_areg_alias_native]="D0C8 40C3"
TESTS[adda_core_l_areg_alias_native]="D1C8 40C3"
TESTS[adda_core_w_max_fields_native]="DEC7 40C3"
TESTS[adda_core_w_imm_small_positive_native]="D0FC 0FFF 40C3"
TESTS[adda_core_w_imm_small_negative_native]="D0FC F001 40C3"
TESTS[adda_core_w_imm_large_positive_native]="D0FC 7FFF 40C3"
TESTS[adda_core_w_imm_large_negative_native]="D0FC 8000 40C3"
TESTS[adda_core_l_imm_small_positive_native]="D1FC 0000 0FFF 40C3"
TESTS[adda_core_l_imm_small_negative_native]="D1FC FFFF F001 40C3"
TESTS[adda_core_l_imm_large_positive_native]="D1FC 1234 5678 40C3"
TESTS[adda_core_l_imm_large_negative_native]="D1FC 8000 0000 40C3"
TESTS[adda_core_w_const_dst_wrap]="41F9 FFFF FFFF D0FC 0001 40C3"
TESTS[adda_core_l_const_dst_wrap]="41F9 FFFF FFFF D1FC 0000 0001 40C3"
TESTS[adda_core_w_aind_alias_native]="D0D0 40C3"
TESTS[adda_core_w_postinc_alias_native]="D0D8 40C3"
TESTS[adda_core_w_predec_alias_native]="D0E0 40C3"
TESTS[adda_core_l_postinc_alias_native]="D1D8 40C3"
TESTS[adda_core_l_predec_alias_native]="D1E0 40C3"
TESTS[adda_core_w_d16_source_native]="D0E9 0010 40C3"
TESTS[adda_core_w_index_source_special_native]="D0F1 2000 40C3"
TESTS[adda_core_l_absw_source_native]="D1F8 6000 40C3"
TESTS[adda_core_w_absl_source_special_native]="D0F9 0000 A000 40C3"
TESTS[adda_core_w_pc16_source_native]="D0FA FFEE 40C3"
TESTS[adda_core_l_pcindex_source_native]="D1FB 1000 40C3"
TESTS[adda_core_w_dreg_noflags_native]="D0C0 46FC 2700"
TESTS[adda_core_l_dreg_noflags_native]="D1C0 46FC 2700"
EXPECTED_REG_FIELDS[adda_core_w_dreg_positive_native]="D0=00007FFF D3=0000271F A0=10007FFF SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_dreg_negative_native]="D0=DEAD8000 D3=0000271F A0=0FFF8000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_dreg_wrap_native]="D0=FFFFFFFF D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_areg_alias_native]="D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_areg_alias_native]="D3=0000271F A0=00000002 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_max_fields_native]="D3=0000271F D7=00008000 A7=00018000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_imm_small_positive_native]="D3=0000271F A0=00001FFF SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_imm_small_negative_native]="D3=0000271F A0=00000001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_imm_large_positive_native]="D3=0000271F A0=00017FFF SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_imm_large_negative_native]="D3=0000271F A0=00008000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_imm_small_positive_native]="D3=0000271F A0=00001FFF SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_imm_small_negative_native]="D3=0000271F A0=00000001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_imm_large_positive_native]="D3=0000271F A0=12345679 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_imm_large_negative_native]="D3=0000271F A0=80000001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_const_dst_wrap]="D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_const_dst_wrap]="D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_aind_alias_native]="D3=0000271F A0=0000A001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_postinc_alias_native]="D3=0000271F A0=0000A003 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_predec_alias_native]="D3=0000271F A0=0000A001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_postinc_alias_native]="D3=0000271F A0=0000A005 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_predec_alias_native]="D3=0000271F A0=0000A001 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_d16_source_native]="D3=0000271F A0=00000FFF A1=0000A000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_index_source_special_native]="D2=00000002 D3=0000271F A0=00008000 A1=0000A000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_absw_source_native]="D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_absl_source_special_native]="D3=0000271F A0=00008000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_pc16_source_native]="D3=0000271F A0=00008000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_l_pcindex_source_native]="D1=FFFFFFEE D3=0000271F A0=00000000 SR=271F"
EXPECTED_REG_FIELDS[adda_core_w_dreg_noflags_native]="D0=00000001 A0=00001001 SR=2700"
EXPECTED_REG_FIELDS[adda_core_l_dreg_noflags_native]="D0=00000001 A0=00001001 SR=2700"
TEST_MEMORY_BYTES[adda_core_w_aind_alias_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[adda_core_w_postinc_alias_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[adda_core_w_predec_alias_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[adda_core_l_postinc_alias_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[adda_core_l_predec_alias_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[adda_core_w_d16_source_native]="A010 FF A011 FF"
TEST_MEMORY_BYTES[adda_core_w_index_source_special_native]="A002 80 A003 00"
TEST_MEMORY_BYTES[adda_core_l_absw_source_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[adda_core_w_absl_source_special_native]="A000 7F A001 FF"
TEST_MEMORY_BYTES[adda_core_w_pc16_source_native]="0FF0 80 0FF1 00"
TEST_MEMORY_BYTES[adda_core_l_pcindex_source_native]="0FF0 00 0FF1 00 0FF2 00 0FF3 01"

# Exact-opcode NEG matrix. Register forms begin with the audited opcode so
# B2_TEST_INIT supplies the operand/CCR state at exact native entry.  The matrix
# proves width truncation and upper-lane preservation, all NZVCX outcomes,
# no-flags lowering, every writable memory EA class, and A7 byte stepping.
TESTS[neg_b_zero_native]="4400"
TESTS[neg_w_zero_native]="4440"
TESTS[neg_l_zero_native]="4480"
TESTS[neg_b_one_native]="4400"
TESTS[neg_w_one_native]="4440"
TESTS[neg_l_one_native]="4480"
TESTS[neg_b_min_overflow_native]="4400"
TESTS[neg_w_min_overflow_native]="4440"
TESTS[neg_l_min_overflow_native]="4480"
TESTS[neg_b_minus_one_native]="4400"
TESTS[neg_w_minus_one_native]="4440"
TESTS[neg_l_minus_one_native]="4480"
# Full-SR replacement kills every NEG output flag, selecting flag_sub's
# no-flags lowering while retaining the arithmetic data result.
TESTS[neg_b_min_nf_native]="4400 46FC 2700"
TESTS[neg_w_min_nf_native]="4440 46FC 2700"
TESTS[neg_l_min_nf_native]="4480 46FC 2700"
# Memory RMW forms snapshot SR before loading the modified location, exposing
# both stored data and architectural address-register writeback.
TESTS[neg_b_aind_special_native]="4410 40C2 1010"
TESTS[neg_w_postinc_native]="4458 40C2 3028 FFFE"
TESTS[neg_l_predec_native]="44A0 40C2 2010"
TESTS[neg_b_d16_native]="4428 0010 40C2 1028 0010"
TESTS[neg_w_indexed_special_native]="4470 1000 40C2 3030 1000"
TESTS[neg_l_absw_native]="44B8 6000 40C2 2038 6000"
TESTS[neg_b_absl_special_native]="4439 0000 A000 40C2 1039 0000 A000"
TESTS[neg_b_a7_postinc_native]="441F 40C2 102F FFFE"
TESTS[neg_b_a7_predec_native]="4427 40C2 1017"
EXPECTED_REG_FIELDS[neg_b_zero_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[neg_w_zero_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[neg_l_zero_native]="D0=00000000 SR=2704"
EXPECTED_REG_FIELDS[neg_b_one_native]="D0=A5A500FF SR=2719"
EXPECTED_REG_FIELDS[neg_w_one_native]="D0=A5A5FFFF SR=2719"
EXPECTED_REG_FIELDS[neg_l_one_native]="D0=FFFFFFFF SR=2719"
EXPECTED_REG_FIELDS[neg_b_min_overflow_native]="D0=A5A50080 SR=271B"
EXPECTED_REG_FIELDS[neg_w_min_overflow_native]="D0=A5A58000 SR=271B"
EXPECTED_REG_FIELDS[neg_l_min_overflow_native]="D0=80000000 SR=271B"
EXPECTED_REG_FIELDS[neg_b_minus_one_native]="D0=A5A50001 SR=2711"
EXPECTED_REG_FIELDS[neg_w_minus_one_native]="D0=A5A50001 SR=2711"
EXPECTED_REG_FIELDS[neg_l_minus_one_native]="D0=00000001 SR=2711"
EXPECTED_REG_FIELDS[neg_b_min_nf_native]="D0=A5A50080 SR=2700"
EXPECTED_REG_FIELDS[neg_w_min_nf_native]="D0=A5A58000 SR=2700"
EXPECTED_REG_FIELDS[neg_l_min_nf_native]="D0=80000000 SR=2700"
EXPECTED_REG_FIELDS[neg_b_aind_special_native]="D0=A5A50080 D2=0000271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[neg_w_postinc_native]="D0=A5A5FFFF D2=00002719 A0=0000A002 SR=2718"
EXPECTED_REG_FIELDS[neg_l_predec_native]="D0=FFFFFFFF D2=00002719 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[neg_b_d16_native]="D0=A5A50080 D2=0000271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[neg_w_indexed_special_native]="D0=A5A58000 D1=00000002 D2=0000271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[neg_l_absw_native]="D0=00000001 D2=00002711 SR=2710"
EXPECTED_REG_FIELDS[neg_b_absl_special_native]="D0=A5A50000 D2=00002704 SR=2704"
EXPECTED_REG_FIELDS[neg_b_a7_postinc_native]="D0=A5A50080 D2=0000271B A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[neg_b_a7_predec_native]="D0=A5A500FF D2=00002719 A7=0000A000 SR=2718"
TEST_MEMORY_BYTES[neg_b_aind_special_native]="A000 80"
TEST_MEMORY_BYTES[neg_w_postinc_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[neg_l_predec_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[neg_b_d16_native]="A010 80"
TEST_MEMORY_BYTES[neg_w_indexed_special_native]="A002 80 A003 00"
TEST_MEMORY_BYTES[neg_l_absw_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[neg_b_absl_special_native]="A000 00"
TEST_MEMORY_BYTES[neg_b_a7_postinc_native]="A000 80"
TEST_MEMORY_BYTES[neg_b_a7_predec_native]="A000 01"

# Exact-opcode NEGX matrix. Register forms contain only the audited opcode;
# B2_TEST_INIT supplies the operand and X/Z state so exact-PC replay is honest.
TESTS[negx_b_zero_x0_z1_native]="4000"
TESTS[negx_w_zero_x0_z1_native]="4040"
TESTS[negx_l_zero_x0_z1_native]="4080"
TESTS[negx_b_zero_x0_z0_native]="4000"
TESTS[negx_w_zero_x0_z0_native]="4040"
TESTS[negx_l_zero_x0_z0_native]="4080"
TESTS[negx_b_zero_x1_z1_native]="4000"
TESTS[negx_w_zero_x1_z1_native]="4040"
TESTS[negx_l_zero_x1_z1_native]="4080"
TESTS[negx_b_min_x0_overflow_native]="4000"
TESTS[negx_w_min_x0_overflow_native]="4040"
TESTS[negx_l_min_x0_overflow_native]="4080"
TESTS[negx_b_min_x1_native]="4000"
TESTS[negx_w_min_x1_native]="4040"
TESTS[negx_l_min_x1_native]="4080"
# Full-SR replacement kills every NEGX output flag, selecting flag_subx's
# no-flags lowering while the data result still consumes the incoming X bit.
TESTS[negx_b_min_x1_nf_native]="4000 46FC 2700"
TESTS[negx_w_min_x1_nf_native]="4040 46FC 2700"
TESTS[negx_l_min_x1_nf_native]="4080 46FC 2700"
# Memory RMW forms append a load from the modified address so the dump proves
# both the stored result and the architectural address-register writeback.
TESTS[negx_b_aind_special_native]="4010 40C2 1010"
TESTS[negx_w_postinc_native]="4058 40C2 3028 FFFE"
TESTS[negx_l_predec_native]="40A0 40C2 2010"
TESTS[negx_b_d16_native]="4028 0010 40C2 1028 0010"
TESTS[negx_w_indexed_special_native]="4070 1000 40C2 3030 1000"
TESTS[negx_l_absw_native]="40B8 6000 40C2 2038 6000"
TESTS[negx_b_absl_special_native]="4039 0000 A000 40C2 1039 0000 A000"
TESTS[negx_b_a7_postinc_native]="401F 40C2 102F FFFE"
TESTS[negx_b_a7_predec_native]="4027 40C2 1017"
EXPECTED_REG_FIELDS[negx_b_zero_x0_z1_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[negx_w_zero_x0_z1_native]="D0=A5A50000 SR=2704"
EXPECTED_REG_FIELDS[negx_l_zero_x0_z1_native]="D0=00000000 SR=2704"
EXPECTED_REG_FIELDS[negx_b_zero_x0_z0_native]="D0=A5A50000 SR=2700"
EXPECTED_REG_FIELDS[negx_w_zero_x0_z0_native]="D0=A5A50000 SR=2700"
EXPECTED_REG_FIELDS[negx_l_zero_x0_z0_native]="D0=00000000 SR=2700"
EXPECTED_REG_FIELDS[negx_b_zero_x1_z1_native]="D0=A5A500FF SR=2719"
EXPECTED_REG_FIELDS[negx_w_zero_x1_z1_native]="D0=A5A5FFFF SR=2719"
EXPECTED_REG_FIELDS[negx_l_zero_x1_z1_native]="D0=FFFFFFFF SR=2719"
EXPECTED_REG_FIELDS[negx_b_min_x0_overflow_native]="D0=A5A50080 SR=271B"
EXPECTED_REG_FIELDS[negx_w_min_x0_overflow_native]="D0=A5A58000 SR=271B"
EXPECTED_REG_FIELDS[negx_l_min_x0_overflow_native]="D0=80000000 SR=271B"
EXPECTED_REG_FIELDS[negx_b_min_x1_native]="D0=A5A5007F SR=2711"
EXPECTED_REG_FIELDS[negx_w_min_x1_native]="D0=A5A57FFF SR=2711"
EXPECTED_REG_FIELDS[negx_l_min_x1_native]="D0=7FFFFFFF SR=2711"
EXPECTED_REG_FIELDS[negx_b_min_x1_nf_native]="D0=A5A5007F SR=2700"
EXPECTED_REG_FIELDS[negx_w_min_x1_nf_native]="D0=A5A57FFF SR=2700"
EXPECTED_REG_FIELDS[negx_l_min_x1_nf_native]="D0=7FFFFFFF SR=2700"
EXPECTED_REG_FIELDS[negx_b_aind_special_native]="D0=A5A50080 D2=0000271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[negx_w_postinc_native]="D0=A5A50000 D2=00002704 A0=0000A002 SR=2704"
EXPECTED_REG_FIELDS[negx_l_predec_native]="D0=FFFFFFFF D2=00002719 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[negx_b_d16_native]="D0=A5A5007F D2=00002711 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[negx_w_indexed_special_native]="D0=A5A58000 D1=00000002 D2=0000271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[negx_l_absw_native]="D0=80000000 D2=0000271B SR=2718"
EXPECTED_REG_FIELDS[negx_b_absl_special_native]="D0=A5A50000 D2=00002700 SR=2704"
EXPECTED_REG_FIELDS[negx_b_a7_postinc_native]="D0=A5A50080 D2=0000271B A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[negx_b_a7_predec_native]="D0=A5A500FF D2=00002719 A7=0000A000 SR=2718"
# Exact-opcode TAS matrix.  Register forms prove original-byte N/Z, V/C clear,
# X preservation, and upper-lane retention.  Memory forms snapshot SR before a
# verification load so its own flag update cannot masquerade as TAS evidence.
TESTS[tas_b_d0_zero_x0_native]="4AC0"
TESTS[tas_b_d0_zero_x1_native]="4AC0"
TESTS[tas_b_d0_positive_x1_native]="4AC0"
TESTS[tas_b_d0_negative_x0_native]="4AC0"
TESTS[tas_b_aind_special_native]="4AD0 40C2 1010"
TESTS[tas_b_postinc_native]="4AD8 40C2 1028 FFFF"
TESTS[tas_b_predec_native]="4AE0 40C2 1010"
TESTS[tas_b_d16_native]="4AE8 0010 40C2 1028 0010"
TESTS[tas_b_indexed_special_native]="4AF0 1000 40C2 1030 1000"
TESTS[tas_b_absw_native]="4AF8 6000 40C2 1038 6000"
TESTS[tas_b_absl_special_native]="4AF9 0000 A000 40C2 1039 0000 A000"
TESTS[tas_b_a7_postinc_native]="4ADF 40C2 102F FFFE"
TESTS[tas_b_a7_predec_native]="4AE7 40C2 1017"
EXPECTED_REG_FIELDS[tas_b_d0_zero_x0_native]="D0=A5A50080 SR=2704"
EXPECTED_REG_FIELDS[tas_b_d0_zero_x1_native]="D0=A5A50080 SR=2714"
EXPECTED_REG_FIELDS[tas_b_d0_positive_x1_native]="D0=A5A500FF SR=2710"
EXPECTED_REG_FIELDS[tas_b_d0_negative_x0_native]="D0=A5A50080 SR=2708"
EXPECTED_REG_FIELDS[tas_b_aind_special_native]="D0=A5A50080 D2=00002714 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[tas_b_postinc_native]="D0=A5A500FF D2=00002710 A0=0000A001 SR=2718"
EXPECTED_REG_FIELDS[tas_b_predec_native]="D0=A5A50080 D2=00002708 A0=0000A000 SR=2708"
EXPECTED_REG_FIELDS[tas_b_d16_native]="D0=A5A500FF D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[tas_b_indexed_special_native]="D0=A5A50080 D1=00000002 D2=00002704 A0=0000A000 SR=2708"
EXPECTED_REG_FIELDS[tas_b_absw_native]="D0=A5A50081 D2=00002710 SR=2718"
EXPECTED_REG_FIELDS[tas_b_absl_special_native]="D0=A5A50080 D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[tas_b_a7_postinc_native]="D0=A5A50080 D2=00002714 A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[tas_b_a7_predec_native]="D0=A5A500FF D2=00002700 A7=0000A000 SR=2708"

# Exact-native Scc condition and destination lifecycle. Dn pairs evaluate a
# condition and its inverse from one unchanged CCR state. Memory forms capture
# SR before the verification load and expose both stored byte and EA writeback.
TESTS[scc_core_tf_dreg_native]="50C0 51C1"
TESTS[scc_core_hi_ls_dreg_native]="52C0 53C1"
TESTS[scc_core_cc_cs_dreg_native]="54C0 55C1"
TESTS[scc_core_ne_eq_dreg_native]="56C0 57C1"
TESTS[scc_core_vc_vs_dreg_native]="58C0 59C1"
TESTS[scc_core_pl_mi_dreg_native]="5AC0 5BC1"
TESTS[scc_core_ge_lt_dreg_native]="5CC0 5DC1"
TESTS[scc_core_gt_le_dreg_native]="5EC0 5FC1"
TESTS[scc_core_aind_hi_special_native]="52D0 40C2 1010"
TESTS[scc_core_postinc_t_native]="50D8 40C2 1028 FFFF"
TESTS[scc_core_predec_f_native]="51E0 40C2 1010"
TESTS[scc_core_d16_eq_native]="57E8 0010 40C2 1028 0010"
TESTS[scc_core_index_vs_special_native]="59F0 1000 40C2 1030 1000"
TESTS[scc_core_absw_mi_native]="5BF8 6000 40C2 1038 6000"
TESTS[scc_core_absl_gt_special_native]="5EF9 0000 A000 40C2 1039 0000 A000"
TESTS[scc_core_a7_postinc_t_native]="50DF 40C2 102F FFFE"
TESTS[scc_core_a7_predec_f_native]="51E7 40C2 1017"
for _scc_dreg_name in scc_core_tf_dreg_native scc_core_hi_ls_dreg_native scc_core_cc_cs_dreg_native scc_core_ne_eq_dreg_native scc_core_vc_vs_dreg_native scc_core_pl_mi_dreg_native scc_core_ge_lt_dreg_native scc_core_gt_le_dreg_native; do
    EXPECTED_REG_FIELDS["$_scc_dreg_name"]="D0=A5A500FF D1=B6B60000"
done
unset _scc_dreg_name
EXPECTED_REG_FIELDS[scc_core_tf_dreg_native]+=" SR=271F"
EXPECTED_REG_FIELDS[scc_core_hi_ls_dreg_native]+=" SR=2710"
EXPECTED_REG_FIELDS[scc_core_cc_cs_dreg_native]+=" SR=2714"
EXPECTED_REG_FIELDS[scc_core_ne_eq_dreg_native]+=" SR=2718"
EXPECTED_REG_FIELDS[scc_core_vc_vs_dreg_native]+=" SR=2711"
EXPECTED_REG_FIELDS[scc_core_pl_mi_dreg_native]+=" SR=2712"
EXPECTED_REG_FIELDS[scc_core_ge_lt_dreg_native]+=" SR=271A"
EXPECTED_REG_FIELDS[scc_core_gt_le_dreg_native]+=" SR=271A"
EXPECTED_REG_FIELDS[scc_core_aind_hi_special_native]="D0=A5A500FF D2=00002710 A0=0000A000"
EXPECTED_REG_FIELDS[scc_core_postinc_t_native]="D0=A5A500FF D2=0000271F A0=0000A001"
EXPECTED_REG_FIELDS[scc_core_predec_f_native]="D0=A5A50000 D2=0000271F A0=0000A000"
EXPECTED_REG_FIELDS[scc_core_d16_eq_native]="D0=A5A500FF D2=00002714 A0=0000A000"
EXPECTED_REG_FIELDS[scc_core_index_vs_special_native]="D0=A5A500FF D1=00000002 D2=00002712 A0=0000A000"
EXPECTED_REG_FIELDS[scc_core_absw_mi_native]="D0=A5A500FF D2=00002718"
EXPECTED_REG_FIELDS[scc_core_absl_gt_special_native]="D0=A5A500FF D2=0000271A"
EXPECTED_REG_FIELDS[scc_core_a7_postinc_t_native]="D0=A5A500FF D2=0000271F A7=0000A002"
EXPECTED_REG_FIELDS[scc_core_a7_predec_f_native]="D0=A5A50000 D2=0000271F A7=0000A000"
TEST_MEMORY_BYTES[scc_core_aind_hi_special_native]="A000 00"
TEST_MEMORY_BYTES[scc_core_postinc_t_native]="A000 00"
TEST_MEMORY_BYTES[scc_core_predec_f_native]="A000 FF"
TEST_MEMORY_BYTES[scc_core_d16_eq_native]="A010 00"
TEST_MEMORY_BYTES[scc_core_index_vs_special_native]="A002 00"
TEST_MEMORY_BYTES[scc_core_absw_mi_native]="6000 00"
TEST_MEMORY_BYTES[scc_core_absl_gt_special_native]="A000 00"
TEST_MEMORY_BYTES[scc_core_a7_postinc_t_native]="A000 00"
TEST_MEMORY_BYTES[scc_core_a7_predec_f_native]="A000 FF"

# Exact-native Bcc dynamic-edge lifecycle. Byte displacements are relative to
# the opcode successor; word/long displacements are relative to the extension
# word at opcode+2. MOVEA markers preserve CCR, so every expected SR proves that
# the branch consumed, but did not publish over, all XNZVC bits.
TESTS[bcc_core_hi_taken_b_native]="6206 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_hi_not_taken_b_native]="6206 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ls_taken_b_native]="6306 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ls_not_taken_b_native]="6306 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_cc_taken_b_native]="6406 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_cc_not_taken_b_native]="6406 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_cs_taken_b_native]="6506 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_cs_not_taken_b_native]="6506 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ne_taken_b_native]="6606 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ne_not_taken_b_native]="6606 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_eq_taken_b_native]="6706 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_eq_not_taken_b_native]="6706 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_vc_taken_b_native]="6806 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_vc_not_taken_b_native]="6806 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_vs_taken_b_native]="6906 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_vs_not_taken_b_native]="6906 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_pl_taken_b_native]="6A06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_pl_not_taken_b_native]="6A06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_mi_taken_b_native]="6B06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_mi_not_taken_b_native]="6B06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ge_taken_b_native]="6C06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_ge_not_taken_b_native]="6C06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_lt_taken_b_native]="6D06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_lt_not_taken_b_native]="6D06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_gt_taken_b_native]="6E06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_gt_not_taken_b_native]="6E06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_le_taken_b_native]="6F06 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_le_not_taken_b_native]="6F06 227C 1111 1111 247C 2222 2222"
for _bcc_taken_name in bcc_core_hi_taken_b_native bcc_core_ls_taken_b_native bcc_core_cc_taken_b_native bcc_core_cs_taken_b_native bcc_core_ne_taken_b_native bcc_core_eq_taken_b_native bcc_core_vc_taken_b_native bcc_core_vs_taken_b_native bcc_core_pl_taken_b_native bcc_core_mi_taken_b_native bcc_core_ge_taken_b_native bcc_core_lt_taken_b_native bcc_core_gt_taken_b_native bcc_core_le_taken_b_native; do
    EXPECTED_REG_FIELDS["$_bcc_taken_name"]="A1=0000A100 A2=22222222"
done
for _bcc_not_taken_name in bcc_core_hi_not_taken_b_native bcc_core_ls_not_taken_b_native bcc_core_cc_not_taken_b_native bcc_core_cs_not_taken_b_native bcc_core_ne_not_taken_b_native bcc_core_eq_not_taken_b_native bcc_core_vc_not_taken_b_native bcc_core_vs_not_taken_b_native bcc_core_pl_not_taken_b_native bcc_core_mi_not_taken_b_native bcc_core_ge_not_taken_b_native bcc_core_lt_not_taken_b_native bcc_core_gt_not_taken_b_native bcc_core_le_not_taken_b_native; do
    EXPECTED_REG_FIELDS["$_bcc_not_taken_name"]="A1=11111111 A2=22222222"
done
for _bcc_name in bcc_core_hi_taken_b_native bcc_core_ls_not_taken_b_native bcc_core_cc_taken_b_native bcc_core_cs_not_taken_b_native bcc_core_ne_taken_b_native bcc_core_eq_not_taken_b_native bcc_core_vc_taken_b_native bcc_core_vs_not_taken_b_native bcc_core_pl_taken_b_native bcc_core_mi_not_taken_b_native bcc_core_ge_taken_b_native bcc_core_lt_not_taken_b_native bcc_core_gt_taken_b_native bcc_core_le_not_taken_b_native; do EXPECTED_REG_FIELDS["$_bcc_name"]+=" SR=2710"; done
for _bcc_name in bcc_core_hi_not_taken_b_native bcc_core_ls_taken_b_native bcc_core_cc_not_taken_b_native bcc_core_cs_taken_b_native; do EXPECTED_REG_FIELDS["$_bcc_name"]+=" SR=2711"; done
for _bcc_name in bcc_core_ne_not_taken_b_native bcc_core_eq_taken_b_native bcc_core_gt_not_taken_b_native bcc_core_le_taken_b_native; do EXPECTED_REG_FIELDS["$_bcc_name"]+=" SR=2714"; done
for _bcc_name in bcc_core_vc_not_taken_b_native bcc_core_vs_taken_b_native; do EXPECTED_REG_FIELDS["$_bcc_name"]+=" SR=2712"; done
for _bcc_name in bcc_core_pl_not_taken_b_native bcc_core_mi_taken_b_native bcc_core_ge_not_taken_b_native bcc_core_lt_taken_b_native; do EXPECTED_REG_FIELDS["$_bcc_name"]+=" SR=2718"; done
unset _bcc_taken_name _bcc_not_taken_name _bcc_name

# Unconditional forward targets cover all Bcc/BRA displacement widths. Signed
# backward BNE loops cover negative byte/word/long target arithmetic; replay is
# anchored at the BNE opcode after the MOVEQ/SUBQ setup prefix.
TESTS[bcc_core_bra_b_forward_native]="6006 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_bra_w_forward_native]="6000 0008 227C 1111 1111 247C 2222 2222"
TESTS[bcc_core_bra_l_forward_native]="60FF 0000 000A 227C 1111 1111 247C 2222 2222"
for _bcc_name in bcc_core_bra_b_forward_native bcc_core_bra_w_forward_native bcc_core_bra_l_forward_native; do
    EXPECTED_REG_FIELDS["$_bcc_name"]="A1=0000A100 A2=22222222 SR=271F"
done
TESTS[bcc_core_bne_b_backward_native]="7002 5380 66FC 227C 1111 1111"
TESTS[bcc_core_bne_w_backward_native]="7002 5380 6600 FFFC 227C 1111 1111"
TESTS[bcc_core_bne_l_backward_native]="7002 5380 66FF FFFF FFFC 227C 1111 1111"
for _bcc_name in bcc_core_bne_b_backward_native bcc_core_bne_w_backward_native bcc_core_bne_l_backward_native; do
    EXPECTED_REG_FIELDS["$_bcc_name"]="D0=00000000 A1=11111111 SR=2704"
done
unset _bcc_name

# Exact-native CLR generator lifecycle. Register cases assert upper-lane
# preservation and the fixed logical result (X preserved; N/V/C clear; Z set).
# Memory cases cover every writable EA class, A7 byte geometry, special-memory
# routing, post-store flags, and no-flags table execution.
TESTS[clr_core_b_dreg_native]="4200"
TESTS[clr_core_w_dreg_native]="4240"
TESTS[clr_core_l_dreg_native]="4280"
TESTS[clr_core_b_aind_special_native]="4210"
TESTS[clr_core_w_postinc_native]="4258"
TESTS[clr_core_l_predec_native]="42A0"
TESTS[clr_core_b_d16_native]="4228 0010"
TESTS[clr_core_w_index_special_native]="4270 1802"
TESTS[clr_core_l_absw_native]="42B8 6000"
TESTS[clr_core_b_absl_special_native]="4239 0000 A000"
TESTS[clr_core_b_a7_postinc_native]="421F"
TESTS[clr_core_b_a7_predec_native]="4227"
TESTS[clr_core_b_postinc_successor_bne_native]="4218 6602 7207 7408"
TESTS[clr_core_w_dreg_noflags_native]="4240 7401"
TESTS[clr_core_l_postinc_noflags_native]="4298 7401"
EXPECTED_REG_FIELDS[clr_core_b_dreg_native]="D0=A5A5FF00 SR=2714"
EXPECTED_REG_FIELDS[clr_core_w_dreg_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_l_dreg_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_aind_special_native]="A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_w_postinc_native]="A0=0000A002 SR=2714"
EXPECTED_REG_FIELDS[clr_core_l_predec_native]="A0=00009FFC SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_d16_native]="A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_w_index_special_native]="D1=00000002 A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_l_absw_native]="A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_absl_special_native]="A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_a7_postinc_native]="A7=0000A002 SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_a7_predec_native]="A7=00009FFE SR=2714"
EXPECTED_REG_FIELDS[clr_core_b_postinc_successor_bne_native]="D1=00000007 D2=00000008 A0=0000A001 SR=2710"
EXPECTED_REG_FIELDS[clr_core_w_dreg_noflags_native]="D0=A5A50000 D2=00000001 SR=2700"
EXPECTED_REG_FIELDS[clr_core_l_postinc_noflags_native]="D2=00000001 A0=0000A004 SR=2700"
TEST_MEMORY_BYTES[clr_core_b_aind_special_native]="A000 00"
TEST_MEMORY_BYTES[clr_core_w_postinc_native]="A000 00 A001 00"
TEST_MEMORY_BYTES[clr_core_l_predec_native]="9FFC 00 9FFD 00 9FFE 00 9FFF 00"
TEST_MEMORY_BYTES[clr_core_b_d16_native]="A010 00"
TEST_MEMORY_BYTES[clr_core_w_index_special_native]="A002 00 A003 00"
TEST_MEMORY_BYTES[clr_core_l_absw_native]="6000 00 6001 00 6002 00 6003 00"
TEST_MEMORY_BYTES[clr_core_b_absl_special_native]="A000 00"
TEST_MEMORY_BYTES[clr_core_b_a7_postinc_native]="A000 00"
TEST_MEMORY_BYTES[clr_core_b_a7_predec_native]="9FFE 00"
TEST_MEMORY_BYTES[clr_core_b_postinc_successor_bne_native]="A000 00"
TEST_MEMORY_BYTES[clr_core_l_postinc_noflags_native]="A000 00 A001 00 A002 00 A003 00"

# Exact-native EXG lifecycle. Every vector starts directly at EXG; distinct
# values prove simultaneous exchange, self forms prove aliases, and exact SR
# checks prove that EXG never changes XNZVC in either compiler table.
TESTS[exg_core_dn_dn_native]="C141"
TESTS[exg_core_an_an_native]="C149"
TESTS[exg_core_dn_an_native]="C189"
TESTS[exg_core_dn_dn_self_native]="C140"
TESTS[exg_core_an_an_self_native]="C148"
TESTS[exg_core_dn_dn_max_native]="CD47"
TESTS[exg_core_an_an_max_native]="CB4F"
TESTS[exg_core_dn_an_max_native]="CF8F"
TESTS[exg_core_dn_dn_roundtrip_native]="C141 C141"
TESTS[exg_core_an_an_roundtrip_native]="C149 C149"
TESTS[exg_core_dn_an_roundtrip_native]="C189 C189"
TESTS[exg_core_dn_an_noflags_native]="C189 7401"
EXPECTED_REG_FIELDS[exg_core_dn_dn_native]="D0=AABBCCDD D1=11223344 SR=271F"
EXPECTED_REG_FIELDS[exg_core_an_an_native]="A0=0000B000 A1=0000A000 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_an_native]="D0=0000B000 A1=11223344 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_dn_self_native]="D0=11223344 SR=271F"
EXPECTED_REG_FIELDS[exg_core_an_an_self_native]="A0=0000A000 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_dn_max_native]="D6=77777777 D7=66666666 SR=271F"
EXPECTED_REG_FIELDS[exg_core_an_an_max_native]="A5=0000F700 A7=0000F500 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_an_max_native]="D7=0000F700 A7=77777777 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_dn_roundtrip_native]="D0=11223344 D1=AABBCCDD SR=271F"
EXPECTED_REG_FIELDS[exg_core_an_an_roundtrip_native]="A0=0000A000 A1=0000B000 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_an_roundtrip_native]="D0=11223344 A1=0000B000 SR=271F"
EXPECTED_REG_FIELDS[exg_core_dn_an_noflags_native]="D0=0000B000 D2=00000001 A1=11223344 SR=2700"

# Exact-native EXT lifecycle. EXT.W preserves Dn[31:16]; EXT.L and EXTB.L
# replace all 32 bits. X survives while N/Z derive from the widened result and
# V/C clear. No-flags cases use a later MOVEQ to control the observed SR.
TESTS[ext_core_w_negative_native]="4880"
TESTS[ext_core_w_zero_native]="4880"
TESTS[ext_core_w_positive_native]="4880"
TESTS[ext_core_w_max_native]="4887"
TESTS[ext_core_l_negative_native]="48C0"
TESTS[ext_core_l_zero_native]="48C0"
TESTS[ext_core_l_positive_native]="48C0"
TESTS[ext_core_l_max_native]="48C7"
TESTS[extb_core_l_negative_native]="49C0"
TESTS[extb_core_l_zero_native]="49C0"
TESTS[extb_core_l_positive_native]="49C0"
TESTS[extb_core_l_max_native]="49C7"
TESTS[ext_core_wl_chain_negative_native]="4880 48C0"
TESTS[ext_core_w_noflags_native]="4880 7401"
TESTS[ext_core_l_noflags_native]="48C0 7401"
TESTS[extb_core_l_noflags_native]="49C0 7401"
EXPECTED_REG_FIELDS[ext_core_w_negative_native]="D0=A5A5FF80 SR=2718"
EXPECTED_REG_FIELDS[ext_core_w_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[ext_core_w_positive_native]="D0=A5A5007F SR=2710"
EXPECTED_REG_FIELDS[ext_core_w_max_native]="D7=7777FF80 SR=2718"
EXPECTED_REG_FIELDS[ext_core_l_negative_native]="D0=FFFF8000 SR=2718"
EXPECTED_REG_FIELDS[ext_core_l_zero_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[ext_core_l_positive_native]="D0=00007FFF SR=2710"
EXPECTED_REG_FIELDS[ext_core_l_max_native]="D7=FFFF8000 SR=2718"
EXPECTED_REG_FIELDS[extb_core_l_negative_native]="D0=FFFFFF80 SR=2718"
EXPECTED_REG_FIELDS[extb_core_l_zero_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[extb_core_l_positive_native]="D0=0000007F SR=2710"
EXPECTED_REG_FIELDS[extb_core_l_max_native]="D7=FFFFFF80 SR=2718"
EXPECTED_REG_FIELDS[ext_core_wl_chain_negative_native]="D0=FFFFFF80 SR=2718"
EXPECTED_REG_FIELDS[ext_core_w_noflags_native]="D0=A5A5FF80 D2=00000001 SR=2700"
EXPECTED_REG_FIELDS[ext_core_l_noflags_native]="D0=FFFF8000 D2=00000001 SR=2700"
EXPECTED_REG_FIELDS[extb_core_l_noflags_native]="D0=FFFFFF80 D2=00000001 SR=2700"

# Exact-native DBcc dynamic-edge lifecycle. The +8 displacement is relative to
# DBcc's extension-word PC and lands on the second MOVEA marker, skipping the
# first on a taken decrement branch. MOVEA and the appended sentinel do not
# alter CCR, so the final dump proves DBcc's flag preservation directly.
_DBCC_TRUE_HEX_SUFFIX="0008 227C 1111 1111 247C 2222 2222"
TESTS[dbcc_core_dbt_true_native]="50C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_dbf_terminal_native]="51C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_dbf_branch_native]="51C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_dbf_wrap_native]="51C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_hi_true_native]="52C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_ls_false_branch_native]="53C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_cc_true_native]="54C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_cs_false_branch_native]="55C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_ne_true_native]="56C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_eq_false_branch_native]="57C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_vc_true_native]="58C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_vs_false_branch_native]="59C8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_pl_true_native]="5AC8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_mi_false_branch_native]="5BC8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_ge_true_native]="5CC8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_lt_false_branch_native]="5DC8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_gt_true_native]="5EC8 $_DBCC_TRUE_HEX_SUFFIX"
TESTS[dbcc_core_le_false_branch_native]="5FC8 $_DBCC_TRUE_HEX_SUFFIX"
unset _DBCC_TRUE_HEX_SUFFIX
EXPECTED_REG_FIELDS[dbcc_core_dbt_true_native]="D0=A5A50001 A1=11111111 A2=22222222 SR=271F"
EXPECTED_REG_FIELDS[dbcc_core_dbf_terminal_native]="D0=A5A5FFFF A1=11111111 A2=22222222 SR=271F"
EXPECTED_REG_FIELDS[dbcc_core_dbf_branch_native]="D0=A5A50000 A1=0000A100 A2=22222222 SR=271F"
EXPECTED_REG_FIELDS[dbcc_core_dbf_wrap_native]="D0=A5A5FFFE A1=0000A100 A2=22222222 SR=271F"
for _dbcc_true_name in dbcc_core_hi_true_native dbcc_core_cc_true_native dbcc_core_ne_true_native dbcc_core_vc_true_native dbcc_core_pl_true_native dbcc_core_ge_true_native dbcc_core_gt_true_native; do
    EXPECTED_REG_FIELDS["$_dbcc_true_name"]="D0=A5A50001 A1=11111111 A2=22222222"
done
for _dbcc_false_name in dbcc_core_ls_false_branch_native dbcc_core_cs_false_branch_native dbcc_core_eq_false_branch_native dbcc_core_vs_false_branch_native dbcc_core_mi_false_branch_native dbcc_core_lt_false_branch_native dbcc_core_le_false_branch_native; do
    EXPECTED_REG_FIELDS["$_dbcc_false_name"]="D0=A5A50000 A1=0000A100 A2=22222222"
done
unset _dbcc_true_name _dbcc_false_name
for _dbcc_name in dbcc_core_hi_true_native dbcc_core_ls_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=2710"; done
for _dbcc_name in dbcc_core_cc_true_native dbcc_core_cs_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=2714"; done
for _dbcc_name in dbcc_core_ne_true_native dbcc_core_eq_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=2718"; done
for _dbcc_name in dbcc_core_vc_true_native dbcc_core_vs_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=2711"; done
for _dbcc_name in dbcc_core_pl_true_native dbcc_core_mi_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=2712"; done
for _dbcc_name in dbcc_core_ge_true_native dbcc_core_lt_false_branch_native dbcc_core_gt_true_native dbcc_core_le_false_branch_native; do EXPECTED_REG_FIELDS["$_dbcc_name"]+=" SR=271A"; done
unset _dbcc_name

# Exact-native classic bit-operation matrix. Register forms assert modulo-32
# counts, source/destination aliases and original-bit Z. Memory forms snapshot
# SR before a verification load so the load cannot contaminate the bit-op CCR.
TESTS[bitop_core_btst_dyn_l_count63_native]="0300"
TESTS[bitop_core_btst_imm_l_count63_native]="0800 003F"
TESTS[bitop_core_bchg_dyn_l_alias_native]="0140"
TESTS[bitop_core_bchg_imm_l_bit31_native]="0840 001F"
TESTS[bitop_core_bclr_dyn_l_count32_native]="0380"
TESTS[bitop_core_bclr_imm_l_bit31_noflags_native]="203C 8000 0000 0880 001F 7400"
TESTS[bitop_core_bset_dyn_l_count63_native]="03C0"
TESTS[bitop_core_bset_imm_l_bit0_native]="08C0 0000"
TESTS[bitop_core_bchg_dyn_l_distinct_native]="0340"
TESTS[bitop_core_bset_dyn_l_alias_native]="01C0"
TESTS[bitop_core_bchg_imm_aind_zero_special_native]="0850 0007 40C2 1010"
TESTS[bitop_core_bchg_imm_aind_one_native]="0850 0007 40C2 1010"
TESTS[bitop_core_bclr_dyn_postinc_zero_native]="0198 40C2 1028 FFFF"
TESTS[bitop_core_bclr_dyn_predec_one_native]="01A0 40C2 1010"
TESTS[bitop_core_bset_imm_d16_zero_native]="08E8 0000 0010 40C2 1028 0010"
TESTS[bitop_core_bset_dyn_index_one_special_native]="01F0 1000 40C2 1030 1000"
TESTS[bitop_core_bchg_dyn_absw_zero_native]="0178 6000 40C2 1038 6000"
TESTS[bitop_core_bclr_imm_absl_one_special_native]="08B9 0000 0000 A000 40C2 1039 0000 A000"
TESTS[bitop_core_bset_dyn_a7_postinc_zero_native]="01DF 40C2 102F FFFE"
TESTS[bitop_core_bchg_dyn_a7_predec_one_native]="0167 40C2 1017"
TESTS[bitop_core_btst_dyn_aind_set_special_native]="0110 40C2 1210"
TESTS[bitop_core_btst_imm_d16_zero_native]="0828 0007 0010 40C2 1228 0010"
TESTS[bitop_core_bchg_imm_aind_noflags_native]="0850 0000 7400 1010"
TESTS[bitop_core_bset_imm_pc_d16_zero_native]="08FA 0000 FFEC 40C2 1038 0FF0"
TESTS[bitop_core_bclr_dyn_pc_index_one_native]="01BB 1000 40C2 1038 0FF0"
TESTS[bitop_core_btst_imm_pc_d16_set_native]="083A 0007 FFEC 40C2 1238 0FF0"
TESTS[bitop_core_btst_dyn_pc_index_zero_native]="013B 1000 40C2 1638 0FF0"
TESTS[bitop_core_btst_imm_destination_zero_native]="083C 0000 0080"
TESTS[bitop_core_btst_dyn_destination_set_native]="013C 0080"

EXPECTED_REG_FIELDS[bitop_core_btst_dyn_l_count63_native]="D0=80000000 D1=0000003F SR=271B"
EXPECTED_REG_FIELDS[bitop_core_btst_imm_l_count63_native]="D0=00000000 SR=271F"
EXPECTED_REG_FIELDS[bitop_core_bchg_dyn_l_alias_native]="D0=25A5001F SR=271B"
EXPECTED_REG_FIELDS[bitop_core_bchg_imm_l_bit31_native]="D0=A5A5001F SR=271F"
EXPECTED_REG_FIELDS[bitop_core_bclr_dyn_l_count32_native]="D0=A5A50000 D1=00000020 SR=271B"
EXPECTED_REG_FIELDS[bitop_core_bclr_imm_l_bit31_noflags_native]="D0=00000000 D2=00000000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bset_dyn_l_count63_native]="D0=A5A5001F D1=0000003F SR=271F"
EXPECTED_REG_FIELDS[bitop_core_bset_imm_l_bit0_native]="D0=A5A50001 SR=271B"
EXPECTED_REG_FIELDS[bitop_core_bchg_dyn_l_distinct_native]="D0=A5A50000 D1=00000020 SR=271B"
EXPECTED_REG_FIELDS[bitop_core_bset_dyn_l_alias_native]="D0=00000025 SR=271F"
EXPECTED_REG_FIELDS[bitop_core_bchg_imm_aind_zero_special_native]="D0=A5A50080 D2=2222271F A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[bitop_core_bchg_imm_aind_one_native]="D0=A5A50000 D2=2222271B A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bclr_dyn_postinc_zero_native]="D0=A5A50000 D2=2222271F A0=0000A001 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bclr_dyn_predec_one_native]="D0=A5A50000 D2=2222271B A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bset_imm_d16_zero_native]="D0=A5A50001 D2=2222271F A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bset_dyn_index_one_special_native]="D0=A5A50001 D1=00000002 D2=2222271B A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bchg_dyn_absw_zero_native]="D0=A5A50001 D2=2222271F SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bclr_imm_absl_one_special_native]="D0=A5A50000 D2=2222271B SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bset_dyn_a7_postinc_zero_native]="D0=A5A50001 D2=2222271F A7=0000A002 SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bchg_dyn_a7_predec_one_native]="D0=A5A50000 D2=2222271B A7=0000A000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_btst_dyn_aind_set_special_native]="D0=00000007 D1=00000080 D2=2222271B A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[bitop_core_btst_imm_d16_zero_native]="D1=00000000 D2=2222271F A0=0000A000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_bchg_imm_aind_noflags_native]="D0=A5A50001 D2=00000000 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bset_imm_pc_d16_zero_native]="D0=A5A50001 D2=2222271F SR=2710"
EXPECTED_REG_FIELDS[bitop_core_bclr_dyn_pc_index_one_native]="D0=A5A50000 D1=FFFFFFEE D2=2222271B SR=2714"
EXPECTED_REG_FIELDS[bitop_core_btst_imm_pc_d16_set_native]="D1=00000080 D2=2222271B SR=2718"
EXPECTED_REG_FIELDS[bitop_core_btst_dyn_pc_index_zero_native]="D0=00000007 D1=FFFFFFEE D2=2222271F D3=00000000 SR=2714"
EXPECTED_REG_FIELDS[bitop_core_btst_imm_destination_zero_native]="SR=271F"
EXPECTED_REG_FIELDS[bitop_core_btst_dyn_destination_set_native]="D0=00000007 SR=271B"

TEST_MEMORY_BYTES[bitop_core_bchg_imm_aind_zero_special_native]="A000 00"
TEST_MEMORY_BYTES[bitop_core_bchg_imm_aind_one_native]="A000 80"
TEST_MEMORY_BYTES[bitop_core_bclr_dyn_postinc_zero_native]="A000 00"
TEST_MEMORY_BYTES[bitop_core_bclr_dyn_predec_one_native]="A000 01"
TEST_MEMORY_BYTES[bitop_core_bset_imm_d16_zero_native]="A010 00"
TEST_MEMORY_BYTES[bitop_core_bset_dyn_index_one_special_native]="A002 01"
TEST_MEMORY_BYTES[bitop_core_bchg_dyn_absw_zero_native]="6000 00"
TEST_MEMORY_BYTES[bitop_core_bclr_imm_absl_one_special_native]="A000 01"
TEST_MEMORY_BYTES[bitop_core_bset_dyn_a7_postinc_zero_native]="A000 00"
TEST_MEMORY_BYTES[bitop_core_bchg_dyn_a7_predec_one_native]="A000 01"
TEST_MEMORY_BYTES[bitop_core_btst_dyn_aind_set_special_native]="A000 80"
TEST_MEMORY_BYTES[bitop_core_btst_imm_d16_zero_native]="A010 00"
TEST_MEMORY_BYTES[bitop_core_bchg_imm_aind_noflags_native]="A000 00"
TEST_MEMORY_BYTES[bitop_core_bset_imm_pc_d16_zero_native]="0FF0 00"
TEST_MEMORY_BYTES[bitop_core_bclr_dyn_pc_index_one_native]="0FF0 01"
TEST_MEMORY_BYTES[bitop_core_btst_imm_pc_d16_set_native]="0FF0 80"
TEST_MEMORY_BYTES[bitop_core_btst_dyn_pc_index_zero_native]="0FF0 00"

# Exact-native compare matrix. CMP/CMPM compute destination-source, preserve X,
# and replace NZVC. CMPA.W sign-extends its source before the shared long CMP.
TESTS[cmp_core_b_reg_borrow_native]="B001 40C2"
TESTS[cmp_core_w_reg_overflow_native]="B041 40C2"
TESTS[cmp_core_l_reg_alias_equal_native]="B080 40C2"
TESTS[cmp_core_b_imm_const_overflow_native]="707F 0C00 00FF 40C2"
TESTS[cmp_core_w_imm_runtime_overflow_native]="0C40 0001 40C2"
TESTS[cmp_core_l_imm_const_overflow_native]="203C 8000 0000 0C80 0000 0001 40C2"
TESTS[cmp_core_l_reg_distinct_borrow_native]="B081 40C2"
TESTS[cmp_core_b_aind_special_native]="B010 40C2"
TESTS[cmp_core_w_postinc_native]="B058 40C2"
TESTS[cmp_core_l_predec_native]="B0A0 40C2"
TESTS[cmp_core_b_d16_native]="B028 0010 40C2"
TESTS[cmp_core_w_index_special_native]="B070 1000 40C2"
TESTS[cmp_core_l_absw_native]="B0B8 6000 40C2"
TESTS[cmp_core_b_absl_special_native]="B039 0000 A000 40C2"
TESTS[cmp_core_w_pc_d16_native]="B07A FFEE 40C2"
TESTS[cmp_core_l_pc_index_native]="B0BB 1000 40C2"
TESTS[cmp_core_b_postinc_noflags_native]="B018 7400 40C3"
TESTS[cmpm_core_b_distinct_native]="B308 40C2"
TESTS[cmpm_core_w_distinct_native]="B348 40C2"
TESTS[cmpm_core_l_distinct_native]="B388 40C2"
TESTS[cmpm_core_b_same_a0_native]="B108 40C2"
TESTS[cmpm_core_b_same_a7_native]="BF0F 40C2"
TESTS[cmpm_core_w_special_native]="B348 40C2"
TESTS[cmpm_core_l_noflags_native]="B388 7400 40C3"
TESTS[cmpa_core_w_imm_negative_native]="B0FC FFFF 40C2"
TESTS[cmpa_core_w_postinc_alias_native]="B0D8 40C2"
TESTS[cmpa_core_w_d16_negative_native]="B2E8 0010 40C2"
TESTS[cmpa_core_l_areg_alias_native]="B1C8 40C2"
TESTS[cmpa_core_l_aind_special_native]="B3D0 40C2"
TESTS[cmpa_core_w_pc_index_native]="B0FB 1000 40C2"
TESTS[cmpa_core_l_postinc_noflags_native]="B1D8 7400 40C3"

EXPECTED_REG_FIELDS[cmp_core_b_reg_borrow_native]="D0=A5A50000 D1=00000001 D2=22222719 SR=2719"
EXPECTED_REG_FIELDS[cmp_core_w_reg_overflow_native]="D0=A5A58000 D1=00000001 D2=22222712 SR=2712"
EXPECTED_REG_FIELDS[cmp_core_l_reg_alias_equal_native]="D0=80000000 D2=22222714 SR=2714"
EXPECTED_REG_FIELDS[cmp_core_b_imm_const_overflow_native]="D0=0000007F D2=2222271B SR=271B"
EXPECTED_REG_FIELDS[cmp_core_w_imm_runtime_overflow_native]="D0=A5A58000 D2=22222712 SR=2712"
EXPECTED_REG_FIELDS[cmp_core_l_imm_const_overflow_native]="D0=80000000 D2=22222712 SR=2712"
EXPECTED_REG_FIELDS[cmp_core_l_reg_distinct_borrow_native]="D0=00000000 D1=FFFFFFFF D2=22222711 SR=2711"
EXPECTED_REG_FIELDS[cmp_core_b_aind_special_native]="D0=A5A5007F D2=2222271B A0=0000A000 SR=271B"
EXPECTED_REG_FIELDS[cmp_core_w_postinc_native]="D0=A5A58000 D2=22222712 A0=0000A002 SR=2712"
EXPECTED_REG_FIELDS[cmp_core_l_predec_native]="D0=00000000 D2=22222719 A0=0000A000 SR=2719"
EXPECTED_REG_FIELDS[cmp_core_b_d16_native]="D0=A5A50000 D2=22222719 A0=0000A000 SR=2719"
EXPECTED_REG_FIELDS[cmp_core_w_index_special_native]="D0=A5A57FFF D1=00000002 D2=2222271B A0=0000A000 SR=271B"
EXPECTED_REG_FIELDS[cmp_core_l_absw_native]="D0=00000000 D2=22222711 SR=2711"
EXPECTED_REG_FIELDS[cmp_core_b_absl_special_native]="D0=A5A5007F D2=2222271B SR=271B"
EXPECTED_REG_FIELDS[cmp_core_w_pc_d16_native]="D0=A5A58000 D2=22222712 SR=2712"
EXPECTED_REG_FIELDS[cmp_core_l_pc_index_native]="D0=00000000 D1=FFFFFFEE D2=22222711 SR=2711"
EXPECTED_REG_FIELDS[cmp_core_b_postinc_noflags_native]="D2=00000000 D3=33332714 A0=0000A001 SR=2714"
EXPECTED_REG_FIELDS[cmpm_core_b_distinct_native]="D2=22222710 A0=0000A001 A1=0000A101 SR=2710"
EXPECTED_REG_FIELDS[cmpm_core_w_distinct_native]="D2=2222271B A0=0000A002 A1=0000A102 SR=271B"
EXPECTED_REG_FIELDS[cmpm_core_l_distinct_native]="D2=22222711 A0=0000A004 A1=0000A104 SR=2711"
EXPECTED_REG_FIELDS[cmpm_core_b_same_a0_native]="D2=22222714 A0=0000A002 SR=2714"
EXPECTED_REG_FIELDS[cmpm_core_b_same_a7_native]="D2=22222710 A7=0000A004 SR=2710"
EXPECTED_REG_FIELDS[cmpm_core_w_special_native]="D2=22222719 A0=0000A002 A1=0000A102 SR=2719"
EXPECTED_REG_FIELDS[cmpm_core_l_noflags_native]="D2=00000000 D3=33332714 A0=0000A004 A1=0000A104 SR=2714"
EXPECTED_REG_FIELDS[cmpa_core_w_imm_negative_native]="D2=22222711 A0=00000000 SR=2711"
EXPECTED_REG_FIELDS[cmpa_core_w_postinc_alias_native]="D2=22222710 A0=0000A002 SR=2710"
EXPECTED_REG_FIELDS[cmpa_core_w_d16_negative_native]="D2=22222711 A0=0000A000 A1=00007FFF SR=2711"
EXPECTED_REG_FIELDS[cmpa_core_l_areg_alias_native]="D2=22222714 A0=80000000 SR=2714"
EXPECTED_REG_FIELDS[cmpa_core_l_aind_special_native]="D2=22222711 A0=0000A000 A1=00000000 SR=2711"
EXPECTED_REG_FIELDS[cmpa_core_w_pc_index_native]="D1=FFFFFFEE D2=22222711 A0=00000000 SR=2711"
EXPECTED_REG_FIELDS[cmpa_core_l_postinc_noflags_native]="D2=00000000 D3=33332714 A0=0000A004 SR=2714"

TEST_MEMORY_BYTES[cmp_core_b_aind_special_native]="A000 80"
TEST_MEMORY_BYTES[cmp_core_w_postinc_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[cmp_core_l_predec_native]="A000 00 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[cmp_core_b_d16_native]="A010 01"
TEST_MEMORY_BYTES[cmp_core_w_index_special_native]="A002 80 A003 00"
TEST_MEMORY_BYTES[cmp_core_l_absw_native]="6000 FF 6001 FF 6002 FF 6003 FF"
TEST_MEMORY_BYTES[cmp_core_b_absl_special_native]="A000 80"
TEST_MEMORY_BYTES[cmp_core_w_pc_d16_native]="0FF0 00 0FF1 01"
TEST_MEMORY_BYTES[cmp_core_l_pc_index_native]="0FF0 FF 0FF1 FF 0FF2 FF 0FF3 FF"
TEST_MEMORY_BYTES[cmp_core_b_postinc_noflags_native]="A000 7E"
TEST_MEMORY_BYTES[cmpm_core_b_distinct_native]="A000 01 A100 02"
TEST_MEMORY_BYTES[cmpm_core_w_distinct_native]="A000 80 A001 00 A100 7F A101 FF"
TEST_MEMORY_BYTES[cmpm_core_l_distinct_native]="A000 FF A001 FF A002 FF A003 FF A100 00 A101 00 A102 00 A103 00"
TEST_MEMORY_BYTES[cmpm_core_b_same_a0_native]="A000 01 A001 01"
TEST_MEMORY_BYTES[cmpm_core_b_same_a7_native]="A000 01 A002 02"
TEST_MEMORY_BYTES[cmpm_core_w_special_native]="A000 00 A001 01 A100 00 A101 00"
TEST_MEMORY_BYTES[cmpm_core_l_noflags_native]="A000 12 A001 34 A002 56 A003 78 A100 87 A101 65 A102 43 A103 21"
TEST_MEMORY_BYTES[cmpa_core_w_postinc_alias_native]="A000 00 A001 01"
TEST_MEMORY_BYTES[cmpa_core_w_d16_negative_native]="A010 80 A011 00"
TEST_MEMORY_BYTES[cmpa_core_l_aind_special_native]="A000 FF A001 FF A002 FF A003 FF"
TEST_MEMORY_BYTES[cmpa_core_w_pc_index_native]="0FF0 FF 0FF1 FF"
TEST_MEMORY_BYTES[cmpa_core_l_postinc_noflags_native]="A000 12 A001 34 A002 56 A003 78"

# Exact-native MOVE lifecycle matrix. Register/immediate forms publish NZ from
# the selected width, clear VC, preserve X and retain untouched Dn upper lanes.
TESTS[move_core_b_reg_negative_native]="1001"
TESTS[move_core_b_reg_zero_native]="1001"
TESTS[move_core_w_reg_negative_native]="3001"
TESTS[move_core_w_reg_zero_native]="3001"
TESTS[move_core_l_reg_negative_native]="2001"
TESTS[move_core_l_reg_zero_native]="2001"
TESTS[move_core_b_self_alias_native]="1000"
TESTS[move_core_w_self_alias_native]="3000"
TESTS[move_core_b_imm_negative_native]="103C 0080"
TESTS[move_core_w_imm_negative_native]="303C 8001"
TESTS[move_core_l_imm_zero_native]="203C 0000 0000"
# Primitive-attribution probes for mov_l_rr's self-copy and constant-source paths.
TESTS[mov_l_rr_self_native]="2000"
TESTS[mov_l_rr_const_movea_native]="207C 89AB CDEF"
EXPECTED_REG_FIELDS[move_core_b_reg_negative_native]="D0=A5A50080 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_reg_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[move_core_w_reg_negative_native]="D0=A5A58001 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_reg_zero_native]="D0=A5A50000 SR=2714"
EXPECTED_REG_FIELDS[move_core_l_reg_negative_native]="D0=80000001 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_reg_zero_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[move_core_b_self_alias_native]="D0=A5A50080 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_self_alias_native]="D0=A5A58001 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_imm_negative_native]="D0=A5A50080 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_imm_negative_native]="D0=A5A58001 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_imm_zero_native]="D0=00000000 SR=2714"
EXPECTED_REG_FIELDS[mov_l_rr_self_native]="D0=DEADBEEF SR=2718"
EXPECTED_REG_FIELDS[mov_l_rr_const_movea_native]="A0=89ABCDEF SR=271F"

# Every readable source EA is represented. Memory forms snapshot SR before any
# later verification access; forced-special duplicates exercise helper routing.
TESTS[move_core_b_aind_to_dn_special_native]="1011 40C2"
TESTS[move_core_w_postinc_to_dn_native]="3019 40C2"
TESTS[move_core_l_predec_to_dn_native]="2021 40C2"
TESTS[move_core_b_d16_to_dn_native]="1029 0010 40C2"
TESTS[move_core_w_index_to_dn_special_native]="3031 2000 40C3"
TESTS[move_core_l_absw_to_dn_native]="2038 6000 40C2"
TESTS[move_core_b_absl_to_dn_special_native]="1039 0000 A000 40C2"
TESTS[move_core_w_pc16_to_dn_native]="303A 0002 40C2"
TESTS[move_core_l_pcindex_to_dn_native]="203B 2002 40C3 4E71"
EXPECTED_REG_FIELDS[move_core_b_aind_to_dn_special_native]="D0=A5A50080 D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_postinc_to_dn_native]="D0=A5A50000 D2=00002714 A1=0000A002 SR=2714"
EXPECTED_REG_FIELDS[move_core_l_predec_to_dn_native]="D0=80000001 D2=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_d16_to_dn_native]="D0=A5A5007F D2=00002710 A1=0000A000 SR=2710"
EXPECTED_REG_FIELDS[move_core_w_index_to_dn_special_native]="D0=A5A58001 D2=00000002 D3=00002718 A1=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_absw_to_dn_native]="D0=00000000 D2=00002714 SR=2714"
EXPECTED_REG_FIELDS[move_core_b_absl_to_dn_special_native]="D0=A5A500FF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_pc16_to_dn_native]="D0=A5A540C2 D2=00002710 SR=2710"
EXPECTED_REG_FIELDS[move_core_l_pcindex_to_dn_native]="D0=40C34E71 D2=00000000 D3=00002710 SR=2710"
TEST_MEMORY_BYTES[move_core_b_aind_to_dn_special_native]="A000 80"
TEST_MEMORY_BYTES[move_core_w_postinc_to_dn_native]="A000 00 A001 00"
TEST_MEMORY_BYTES[move_core_l_predec_to_dn_native]="A000 80 A001 00 A002 00 A003 01"
TEST_MEMORY_BYTES[move_core_b_d16_to_dn_native]="A010 7F"
TEST_MEMORY_BYTES[move_core_w_index_to_dn_special_native]="A002 80 A003 01"
TEST_MEMORY_BYTES[move_core_l_absw_to_dn_native]="6000 00 6001 00 6002 00 6003 00"
TEST_MEMORY_BYTES[move_core_b_absl_to_dn_special_native]="A000 FF"

# Every writable destination EA is represented, including source/base aliases
# and A7's two-byte byte stride. Verification loads occur only after SR capture.
TESTS[move_core_b_dn_to_aind_special_native]="1080 40C2 1239 0000 A000"
TESTS[move_core_w_dn_to_postinc_native]="30C0 40C2 3239 0000 A000"
TESTS[move_core_l_dn_to_predec_native]="2100 40C2 2239 0000 A000"
TESTS[move_core_b_dn_to_d16_native]="1140 0010 40C2 1228 0010"
TESTS[move_core_w_dn_to_index_special_native]="3180 1000 40C2 3230 1000"
TESTS[move_core_l_dn_to_absw_native]="21C0 6000 40C2 2238 6000"
TESTS[move_core_b_dn_to_absl_special_native]="13C0 0000 A000 40C2 1239 0000 A000"
TESTS[move_core_l_areg_postinc_alias_native]="20C8 40C2 2239 0000 A000"
TESTS[move_core_l_memmem_postinc_alias_native]="20D8 40C2 2039 0000 A000 2239 0000 A004"
TESTS[move_core_b_a7_postinc_dst_native]="1EC0 40C2 122F FFFE"
TESTS[move_core_b_a7_postinc_src_native]="101F 40C2"
EXPECTED_REG_FIELDS[move_core_b_dn_to_aind_special_native]="D0=A5A50080 D1=00000080 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_w_dn_to_postinc_native]="D0=A5A58001 D1=11118001 D2=00002718 A0=0000A002 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_dn_to_predec_native]="D0=DEADBEEF D1=DEADBEEF D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_dn_to_d16_native]="D0=A5A5007F D1=1111007F D2=00002710 A0=0000A000 SR=2710"
EXPECTED_REG_FIELDS[move_core_w_dn_to_index_special_native]="D0=A5A58001 D1=00008001 D2=00002718 A0=0000A000 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_dn_to_absw_native]="D0=DEADBEEF D1=DEADBEEF D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_dn_to_absl_special_native]="D0=A5A50080 D1=11110080 D2=00002718 SR=2718"
EXPECTED_REG_FIELDS[move_core_l_areg_postinc_alias_native]="D1=0000A000 D2=00002710 A0=0000A004 SR=2710"
EXPECTED_REG_FIELDS[move_core_l_memmem_postinc_alias_native]="D0=11223344 D1=11223344 D2=00002710 A0=0000A008 SR=2710"
EXPECTED_REG_FIELDS[move_core_b_a7_postinc_dst_native]="D0=A5A50080 D1=11110080 D2=00002718 A7=0000A002 SR=2718"
EXPECTED_REG_FIELDS[move_core_b_a7_postinc_src_native]="D0=A5A50000 D2=00002714 A7=0000A002 SR=2714"
TEST_MEMORY_BYTES[move_core_b_dn_to_aind_special_native]="A000 00"
TEST_MEMORY_BYTES[move_core_w_dn_to_postinc_native]="A000 00 A001 00"
TEST_MEMORY_BYTES[move_core_l_dn_to_predec_native]="A000 00 A001 00 A002 00 A003 00"
TEST_MEMORY_BYTES[move_core_b_dn_to_d16_native]="A010 00"
TEST_MEMORY_BYTES[move_core_w_dn_to_index_special_native]="A002 00 A003 00"
TEST_MEMORY_BYTES[move_core_l_dn_to_absw_native]="6000 00 6001 00 6002 00 6003 00"
TEST_MEMORY_BYTES[move_core_b_dn_to_absl_special_native]="A000 00"
TEST_MEMORY_BYTES[move_core_l_areg_postinc_alias_native]="A000 DE A001 AD A002 BE A003 EF"
TEST_MEMORY_BYTES[move_core_l_memmem_postinc_alias_native]="A000 11 A001 22 A002 33 A003 44 A004 AA A005 BB A006 CC A007 DD"
TEST_MEMORY_BYTES[move_core_b_a7_postinc_dst_native]="A000 00"
TEST_MEMORY_BYTES[move_core_b_a7_postinc_src_native]="A000 00"

# MOVEA word/long extension, no-flags and writeback-alias contracts.
TESTS[movea_core_w_dreg_native]="3040"
TESTS[movea_core_w_imm_native]="307C 8001"
TESTS[movea_core_l_dreg_native]="2040"
TESTS[movea_core_w_aind_special_native]="3051"
TESTS[movea_core_w_postinc_alias_native]="3058"
TESTS[movea_core_w_predec_alias_native]="3060"
TESTS[movea_core_l_postinc_alias_native]="2058"
TESTS[movea_core_l_a7_postinc_native]="205F"
TESTS[movea_core_w_index_special_native]="3071 2000"
TESTS[movea_core_w_pc16_native]="307A 0002 4E71"
EXPECTED_REG_FIELDS[movea_core_w_dreg_native]="A0=FFFF8001 SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_imm_native]="A0=FFFF8001 SR=271F"
EXPECTED_REG_FIELDS[movea_core_l_dreg_native]="A0=DEADBEEF SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_aind_special_native]="A0=00007FFF A1=0000A000 SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_postinc_alias_native]="A0=FFFF8001 SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_predec_alias_native]="A0=00007FFF SR=271F"
EXPECTED_REG_FIELDS[movea_core_l_postinc_alias_native]="A0=12345678 SR=271F"
EXPECTED_REG_FIELDS[movea_core_l_a7_postinc_native]="A0=DEADBEEF A7=0000A004 SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_index_special_native]="D2=00000002 A0=FFFF8001 A1=0000A000 SR=271F"
EXPECTED_REG_FIELDS[movea_core_w_pc16_native]="A0=00004E71 SR=271F"
TEST_MEMORY_BYTES[movea_core_w_aind_special_native]="A000 7F A001 FF"
TEST_MEMORY_BYTES[movea_core_w_postinc_alias_native]="A000 80 A001 01"
TEST_MEMORY_BYTES[movea_core_w_predec_alias_native]="A000 7F A001 FF"
TEST_MEMORY_BYTES[movea_core_l_postinc_alias_native]="A000 12 A001 34 A002 56 A003 78"
TEST_MEMORY_BYTES[movea_core_l_a7_postinc_native]="A000 DE A001 AD A002 BE A003 EF"
TEST_MEMORY_BYTES[movea_core_w_index_special_native]="A002 80 A003 01"

# MOVE16 copies four ordered longwords from aligned addresses. D4 snapshots the
# untouched CCR before the verification loads; register updates use unaligned
# architectural values, while transfer addresses mask low four bits.
_MOVE16_PATTERN="A000 11 A001 22 A002 33 A003 44 A004 55 A005 66 A006 77 A007 88 A008 99 A009 AA A00A BB A00B CC A00C DD A00D EE A00E FF A00F 00 B000 00 B001 00 B002 00 B003 00 B004 00 B005 00 B006 00 B007 00 B008 00 B009 00 B00A 00 B00B 00 B00C 00 B00D 00 B00E 00 B00F 00"
_MOVE16_VERIFY_B="40C4 2039 0000 B000 2239 0000 B004 2439 0000 B008 2639 0000 B00C"
_MOVE16_VERIFY_A="40C4 2039 0000 A000 2239 0000 A004 2439 0000 A008 2639 0000 A00C"
TESTS[move16_core_postinc_to_absl_native]="F600 0000 B007 $_MOVE16_VERIFY_B"
TESTS[move16_core_absl_to_postinc_native]="F609 0000 A003 $_MOVE16_VERIFY_B"
TESTS[move16_core_aind_to_absl_native]="F610 0000 B007 $_MOVE16_VERIFY_B"
TESTS[move16_core_absl_to_aind_native]="F619 0000 A003 $_MOVE16_VERIFY_B"
TESTS[move16_core_postpost_distinct_native]="F620 1000 $_MOVE16_VERIFY_B"
TESTS[move16_core_postpost_same_native]="F620 0000 $_MOVE16_VERIFY_A"
TESTS[move16_core_postpost_special_native]="F620 1000 $_MOVE16_VERIFY_B"
for _move16_name in "${MOVE16_NATIVE_MATRIX_NAMES[@]}"; do
    TEST_MEMORY_BYTES["$_move16_name"]="$_MOVE16_PATTERN"
done
unset _move16_name _MOVE16_PATTERN _MOVE16_VERIFY_A _MOVE16_VERIFY_B
EXPECTED_REG_FIELDS[move16_core_postinc_to_absl_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A0=0000A013 SR=2718"
EXPECTED_REG_FIELDS[move16_core_absl_to_postinc_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A1=0000B017 SR=2718"
EXPECTED_REG_FIELDS[move16_core_aind_to_absl_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A0=0000A003 SR=2718"
EXPECTED_REG_FIELDS[move16_core_absl_to_aind_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A1=0000B007 SR=2718"
EXPECTED_REG_FIELDS[move16_core_postpost_distinct_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A0=0000A013 A1=0000B017 SR=2718"
EXPECTED_REG_FIELDS[move16_core_postpost_same_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A0=0000A013 SR=2718"
EXPECTED_REG_FIELDS[move16_core_postpost_special_native]="D0=11223344 D1=55667788 D2=99AABBCC D3=DDEEFF00 D4=4444271F A0=0000A013 A1=0000B017 SR=2718"

# ADDX_BASIC: ORI #0x10,CCR (set X); MOVEQ #5,D0; MOVEQ #3,D1; ADDX.L D1,D0
# 5 + 3 + X(1) = 9
# ORI.B #0x10,CCR = 003C 0010; MOVEQ #5,D0 = 7005; MOVEQ #3,D1 = 7203; ADDX.L D1,D0 = D181
TESTS[addx_basic]="003C 0010 7005 7203 D181"
# SUBX_BASIC: ORI #0x10,CCR (set X); MOVEQ #10,D0; MOVEQ #3,D1; SUBX.L D1,D0
# 10 - 3 - X(1) = 6
# ORI.B #0x10,CCR = 003C 0010; MOVEQ #10,D0 = 700A; MOVEQ #3,D1 = 7203; SUBX.L D1,D0 = 9181
TESTS[subx_basic]="003C 0010 700A 7203 9181"
# EXT_WORD: MOVEQ #-1,D0 (0xFF in low byte); EXT.W D0
# EXT.W sign-extends byte to word: 0xFF → 0xFFFF in low word, upper word cleared by MOVEQ
# MOVEQ #-1,D0 = 70FF; EXT.W D0 = 4880
TESTS[ext_word]="70FF 4880"
# EXT_LONG: MOVE.L #0x0000FF80,D0; EXT.W D0; EXT.L D0
# EXT.W: byte 0x80 → word 0xFF80; EXT.L: word 0xFF80 → long 0xFFFFFF80
# MOVE.L #0x0000FF80,D0 = 203C 0000 FF80; EXT.W D0 = 4880; EXT.L D0 = 48C0
TESTS[ext_long]="203C 0000 FF80 4880 48C0"
# --- MEMORY-INDIRECT AND REGISTER-PRESSURE VECTORS ---
# MOVE_TO_MEM_AND_BACK: LEA $2000,A0; MOVE.L #$DEADBEEF,D0; MOVE.L D0,(A0); CLR.L D0; MOVE.L (A0),D1
# Tests basic memory store/load via register indirect
# LEA $2000,A0 = 41F9 0000 2000; MOVE.L #$DEADBEEF,D0 = 203C DEAD BEEF;
# MOVE.L D0,(A0) = 2080; CLR.L D0 = 4280; MOVE.L (A0),D1 = 2210
TESTS[move_to_mem_and_back]="41F9 0000 2000 203C DEAD BEEF 2080 4280 2210"
# MOVEM_PREDEC_POSTINC: set D0-D3, MOVEM.L D0-D3,-(A0), clear regs, MOVEM.L (A0)+,D4-D7
# LEA $3000,A0; MOVEQ #1,D0; MOVEQ #2,D1; MOVEQ #3,D2; MOVEQ #4,D3;
# MOVEM.L D0-D3,-(A0); MOVEQ #0,D0; MOVEQ #0,D1; MOVEQ #0,D2; MOVEQ #0,D3;
# MOVEM.L (A0)+,D4-D7
# LEA $3000,A0 = 41F9 0000 3000
# MOVEM.L D0-D3,-(A0) = 48E0 F000 (mask: D0-D3 reversed for predec = bits 15-12)
# Wait - MOVEM predecrement reverses the register mask. D0-D3 = bits 0-3 in normal,
# but predecrement uses reversed bit ordering: bit 15=D0, bit 14=D1, etc.
# Actually: MOVEM.L reg-list,-(An): register mask is normal (D0=bit0..A7=bit15),
# but registers are stored in reverse order (A7 first, D0 last). The mask itself
# for D0-D3 is 0x000F. But wait, for -(An) the mask encoding reverses:
# bit 0=A7, bit 1=A6, ..., bit 8=D7, ..., bit 15=D0
# So D0-D3 in predec mask: D0=bit15, D1=bit14, D2=bit13, D3=bit12 = 0xF000
# MOVEM.L (A0)+,D4-D7: normal mask, D4=bit4..D7=bit7 = 0x00F0
# 48E0 F000 = MOVEM.L D0-D3,-(A0)
# 4CD8 00F0 = MOVEM.L (A0)+,D4-D7
TESTS[movem_predec_postinc]="41F9 0000 3000 7001 7202 7403 7604 48E0 F000 7000 7200 7400 7600 4CD8 00F0"
# MOVEM_NO_WRITEBACK: MOVEM.L (A0),D1-D4 must load through a temporary EA and leave A0 unchanged.
# This covers the control-mode no-writeback form distinct from (A0)+.
# LEA $3000,A0; seed four longwords with MOVE.L #imm,(A0)+; reset A0; MOVEM.L (A0),D1-D4.
TESTS[movem_no_writeback]="41F8 3000 20FC 1111 1111 20FC 2222 2222 20FC 3333 3333 20FC 4444 4444 41F8 3000 4CD0 001E"
# MOVEM_PREDEC_MIXED_ORDER: mixed D/A mask through predecrement + postincrement restore path
# LEA $3000,A0; D0=0x11111111; D1=0x22222222; A1=$3333;
# MOVEM.L D0/D1/A1,-(A0) with reversed predec mask 0xC040;
# clear D2/D3/A2; MOVEM.L (A0)+,D2/D3/A2 (mask 0x040C)
TESTS[movem_predec_mixed_order]="41F9 0000 3000 203C 1111 1111 223C 2222 2222 43F9 0000 3333 48E0 C040 243C 0000 0000 263C 0000 0000 247C 0000 0000 4CD8 040C"
# MOVEM closure: the address cursor must be private from every architectural
# register named by the mask. Postincrement writeback wins over a loaded base;
# predecrement stores the original 68020+ base value and publishes writeback once.
TESTS[movem_l_postinc_base_alias_native]="41F8 3000 20FC 1111 1111 20FC 2222 2222 41F8 3000 003C 0001 4CD8 0300 55C7"
EXPECTED_REG_FIELDS[movem_l_postinc_base_alias_native]="A0=00003008 A1=22222222 D7=000000ff"
TESTS[movem_w_postinc_base_alias_native]="41F8 3000 30FC 8001 30FC 7FFF 30FC FFFF 41F8 3000 4C98 0301"
EXPECTED_REG_FIELDS[movem_w_postinc_base_alias_native]="D0=ffff8001 A0=00003006 A1=ffffffff"
TESTS[movem_l_predec_base_alias_native]="41F8 3000 203C 1111 1111 48E0 8080 43F8 2FF8 4CD1 000C"
EXPECTED_REG_FIELDS[movem_l_predec_base_alias_native]="A0=00002ff8 A1=00002ff8 D2=11111111 D3=00003000"
TESTS[movem_w_predec_base_alias_native]="41F8 3000 203C FFFF 8001 48A0 8080 43F8 2FFC 4C91 000C"
EXPECTED_REG_FIELDS[movem_w_predec_base_alias_native]="A0=00002ffc A1=00002ffc D2=ffff8001 D3=00003000"
# Plain (An) has no implicit writeback, but a base register explicitly present
# in the load mask is still a destination. The second transfer must continue
# from the snapshotted cursor after the first transfer overwrites A0.
TESTS[movem_l_aind_load_base_alias_native]="41F8 3000 20FC 1111 1111 20FC 2222 2222 41F8 3000 4CD0 0300"
EXPECTED_REG_FIELDS[movem_l_aind_load_base_alias_native]="A0=11111111 A1=22222222"
TESTS[movem_l_aind_store_base_alias_native]="41F8 3000 203C 1111 1111 227C 2222 2222 48D0 0301 45F8 3000 4CD2 001C"
EXPECTED_REG_FIELDS[movem_l_aind_store_base_alias_native]="A0=00003000 A1=22222222 D2=11111111 D3=00003000 D4=22222222"
# All 15 non-stack architectural registers remain live across both transfer
# loops. The duplicate vector forces readmem_special/writemem_special.
TESTS[movem_l_all_live_roundtrip_native]="48E5 FFFE 4CDD 7FFF"
EXPECTED_REG_FIELDS[movem_l_all_live_roundtrip_native]="D0=01010101 D7=08080808 A0=11111111 A5=00003400"
TESTS[movem_l_all_live_special_native]="48E5 FFFE 4CDD 7FFF"
EXPECTED_REG_FIELDS[movem_l_all_live_special_native]="D0=01010101 D7=08080808 A0=11111111 A5=00003400"
# Empty masks must not synthesize an update in either update mode.
TESTS[movem_zero_mask_native]="41F8 3000 48E0 0000 4CD8 0000"
EXPECTED_REG_FIELDS[movem_zero_mask_native]="A0=00003000"
# One vector covers d16(An), d8(An,Xn), absolute.W, and absolute.L in both
# directions. D4=0 makes the indexed target exact while keeping the indexed
# generator path distinct.
TESTS[movem_l_control_modes_native]="41F8 3000 203C 1111 1111 223C 2222 2222 48E8 0003 0010 4CE8 000C 0010 7800 48F0 0003 4020 4CF0 0060 4020 48F8 0003 3100 4CF8 0600 3100 48F9 0003 0000 3200 4CF9 1800 0000 3200"
EXPECTED_REG_FIELDS[movem_l_control_modes_native]="D2=11111111 D3=22222222 D5=11111111 D6=22222222 A1=11111111 A2=22222222 A3=11111111 A4=22222222"
# d16(PC) and brief d8(PC,D4.W) both resolve to 0x3000. In each encoding the
# MOVEM mask precedes the EA extension word, exercising generator decode order.
TESTS[movem_l_pc_modes_native]="41F8 3000 20FC 1111 1111 20FC 2222 2222 383C 2000 4CFA 000C 1FE8 4CFB 0060 40E2"
EXPECTED_REG_FIELDS[movem_l_pc_modes_native]="D2=11111111 D3=22222222 D4=00002000 D5=11111111 D6=22222222 A0=00003008"
# ADDX_CHAIN: multi-precision add: set X, then chain ADDX across D0+D2, D1+D3
# ORI #$10,CCR; MOVE.L #$FFFFFFFF,D0; MOVEQ #1,D2; ADDX.L D2,D0;
# MOVE.L #$00000000,D1; MOVEQ #0,D3; ADDX.L D3,D1
# This tests X propagation through a chain: D0 overflows, X should propagate to D1 add
# ORI.B #$10,CCR = 003C 0010
# MOVE.L #$FFFFFFFF,D0 = 203C FFFF FFFF; MOVEQ #1,D2 = 7401; ADDX.L D2,D0 = D182
# MOVE.L #0,D1 = 223C 0000 0000; MOVEQ #0,D3 = 7600; ADDX.L D3,D1 = D383
TESTS[addx_chain]="003C 0010 203C FFFF FFFF 7401 D182 223C 0000 0000 7600 D383"
# FLAG_CHAIN_XZN: exercise X/Z/N flag interaction across a sequence
# MOVEQ #-1,D0; ADD.L D0,D0 (should set X=1,C=1,N=1,Z=0,V=0 for 0xFFFFFFFE+carry)
# Wait: ADD.L D0,D0 = D0 + D0 = 0xFFFFFFFF + 0xFFFFFFFF = 0xFFFFFFFE, C=1, X=1
# Then NEGX.L D0: -(0xFFFFFFFE) - X(1) = 0x00000001
# Then ADDX.L D0,D0 with X from NEGX
# MOVEQ #-1,D0 = 70FF; ADD.L D0,D0 = D080; NEGX.L D0 = 4080; ADDX.L D0,D0 = D180
TESTS[flag_chain_xzn]="70FF D080 4080 D180"
# SHIFT_CHAIN: LSL then ROL with count from register, exercising C/X propagation
# MOVEQ #1,D0; MOVEQ #31,D1; LSL.L D1,D0 (D0=0x80000000, C=0, X=0);
# MOVEQ #1,D2; ROL.L D2,D0 (D0=0x00000001, C=1)
# MOVEQ #1,D0 = 7001; MOVEQ #31,D1 = 721F; LSL.L D1,D0 = E3A8
# MOVEQ #1,D2 = 7401; ROL.L D2,D0 = E5B8
TESTS[shift_chain]="7001 721F E3A8 7401 E5B8"
# ROXL_REG_COUNT_32: ORI #$10,CCR (set X); MOVEQ #1,D0; MOVEQ #32,D1; ROXL.L D1,D0
# Explicitly stress the 32-edge behavior for rotate-left-through-extend.
# ORI.B #$10,CCR = 003C 0010; MOVEQ #1,D0 = 7001; MOVEQ #32,D1 = 7220; ROXL.L D1,D0 = E3B0
TESTS[roxl_reg_count_32]="003C 0010 7001 7220 E3B0"
# ROXL_REG_COUNT_33: ORI #$10,CCR (set X); MOVE.L #$80000001,D0; MOVEQ #33,D1; ROXL.L D1,D0
# Exercises 33-bit ring wrap with both endpoint bits set plus X carry-in.
# ORI.B #$10,CCR = 003C 0010; MOVE.L #$80000001,D0 = 203C 8000 0001; MOVEQ #33,D1 = 7221; ROXL.L D1,D0 = E3B0
TESTS[roxl_reg_count_33]="003C 0010 203C 8000 0001 7221 E3B0"
# ROXR_REG_COUNT_33: ORI #$10,CCR (set X); MOVEQ #1,D0; MOVEQ #33,D1; ROXR.L D1,D0
# Exercises register-count masking/modulo behavior across 32+ edge with X/C propagation.
# ORI.B #$10,CCR = 003C 0010; MOVEQ #1,D0 = 7001; MOVEQ #33,D1 = 7221; ROXR.L D1,D0 = E2B0
TESTS[roxr_reg_count_33]="003C 0010 7001 7221 E2B0"
# ROXR_REG_COUNT_32: ORI #$10,CCR (set X); MOVEQ #1,D0; MOVEQ #32,D1; ROXR.L D1,D0
# Explicitly stress the 32-edge behavior in the 33-bit rotate-through-extend ring.
# ORI.B #$10,CCR = 003C 0010; MOVEQ #1,D0 = 7001; MOVEQ #32,D1 = 7220; ROXR.L D1,D0 = E2B0
TESTS[roxr_reg_count_32]="003C 0010 7001 7220 E2B0"
# ROXR_REG_COUNT_0: ORI #$10,CCR (set X); MOVE.L #$12345678,D0; MOVEQ #0,D1; ROXR.L D1,D0
# Count=0 semantics are special (no data rotation, flag handling edge).
# ORI.B #$10,CCR = 003C 0010; MOVE.L #$12345678,D0 = 203C 1234 5678; MOVEQ #0,D1 = 7200; ROXR.L D1,D0 = E2B0
TESTS[roxr_reg_count_0]="003C 0010 203C 1234 5678 7200 E2B0"
# Effective-zero register-count ROX paths. ORI.CCR seeds X=1 and stale V=1;
# SCS makes C architecturally observable. The full REGDUMP additionally proves
# unchanged X/data, size-correct N/Z, and cleared V. Alternating zero and
# negative operands exercises both Z outcomes without weakening upper-bit checks.
TESTS[roxl_b_reg_count_63_copies_x]="003C 0012 203C 89AB CD00 727F 7C00 E330 55C6"
EXPECTED_REG_FIELDS[roxl_b_reg_count_63_copies_x]="D0=89abcd00 D6=000000ff"
TESTS[roxr_b_reg_count_63_copies_x]="003C 0012 203C 89AB CDEF 727F 7C00 E230 55C6"
EXPECTED_REG_FIELDS[roxr_b_reg_count_63_copies_x]="D0=89abcdef D6=000000ff"
TESTS[roxl_w_reg_count_51_copies_x]="003C 0012 203C 89AB 0000 7233 7C00 E370 55C6"
EXPECTED_REG_FIELDS[roxl_w_reg_count_51_copies_x]="D0=89ab0000 D6=000000ff"
TESTS[roxr_w_reg_count_51_copies_x]="003C 0012 203C 89AB CDEF 7233 7C00 E270 55C6"
EXPECTED_REG_FIELDS[roxr_w_reg_count_51_copies_x]="D0=89abcdef D6=000000ff"
TESTS[roxl_l_reg_count_33_copies_x]="003C 0012 203C 0000 0000 7221 7C00 E3B0 55C6"
EXPECTED_REG_FIELDS[roxl_l_reg_count_33_copies_x]="D0=00000000 D6=000000ff"
TESTS[roxr_l_reg_count_33_copies_x]="003C 0012 203C 89AB CDEF 7221 7C00 E2B0 55C6"
EXPECTED_REG_FIELDS[roxr_l_reg_count_33_copies_x]="D0=89abcdef D6=000000ff"
TESTS[roxl_l_reg_count_0_copies_x]="003C 0012 203C 1234 5678 7200 7C00 E3B0 55C6"
EXPECTED_REG_FIELDS[roxl_l_reg_count_0_copies_x]="D0=12345678 D6=000000ff"
TESTS[roxr_reg_count_0_copies_x]="003C 0012 203C 1234 5678 7200 7C00 E2B0 55C6"
EXPECTED_REG_FIELDS[roxr_reg_count_0_copies_x]="D0=12345678 D6=000000ff"
# Keep D0-D7 and A0-A5 populated in the allocator before the effective-zero
# rotate. MOVEA does not disturb the CCR; ORI.CCR is deliberately last so X=1
# and stale V=1 must be replaced by the rotate's V=0 result.
ROX_PRESSURE_PREFIX="203C 89AB CDEF 7221 7402 7603 7804 7A05 7C06 7E07 207C 0000 2000 227C 0000 2100 247C 0000 2200 267C 0000 2300 287C 0000 2400 2A7C 0000 2500 003C 0012"
TESTS[roxl_l_reg_count_33_pressure]="$ROX_PRESSURE_PREFIX E3B0 55C6"
EXPECTED_REG_FIELDS[roxl_l_reg_count_33_pressure]="D0=89abcdef D6=000000ff"
TESTS[roxr_l_reg_count_33_pressure]="$ROX_PRESSURE_PREFIX E2B0 55C6"
EXPECTED_REG_FIELDS[roxr_l_reg_count_33_pressure]="D0=89abcdef D6=000000ff"
# Keep the allocator populated across a runtime count-zero ASR. The JIT must
# preserve the incoming X binding on the branch that skips carry publication.
SHIFT_COUNT0_PRESSURE_PREFIX="203C 89AB CDEF 7200 7402 7603 7804 7A05 7C06 7E07 207C 0000 2000 227C 0000 2100 247C 0000 2200 267C 0000 2300 287C 0000 2400 2A7C 0000 2500 003C 0012"
TESTS[asr_l_reg_count0_pressure_preserves_x]="$SHIFT_COUNT0_PRESSURE_PREFIX E2A0 40C6"
EXPECTED_REG_FIELDS[asr_l_reg_count0_pressure_preserves_x]="D0=89abcdef D6=00002718"
unset ROX_PRESSURE_PREFIX SHIFT_COUNT0_PRESSURE_PREFIX

# Register-count shift effective-zero contract. Seed X=1 and stale V=1,
# materialise the shift's required C=0 into D5, then consume X with a
# same-width effective-zero ROXL and materialise its required C=X into D6.
# ROXL derives the same N/Z/V result as the shift without obscuring X.
SHIFT_ZERO_PREFIX="003C 0012 203C 89AB CDEF 7200 7A00 7C00"
SHIFT_ZERO_EXPECTED="D0=89abcdef D5=00000000 D6=000000ff"
TESTS[asl_b_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E320 55C5 E330 55C6"
EXPECTED_REG_FIELDS[asl_b_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[asl_w_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E360 55C5 E370 55C6"
EXPECTED_REG_FIELDS[asl_w_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[asl_l_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E3A0 55C5 E3B0 55C6"
EXPECTED_REG_FIELDS[asl_l_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[asr_b_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E220 55C5 E330 55C6"
EXPECTED_REG_FIELDS[asr_b_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[asr_w_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E260 55C5 E370 55C6"
EXPECTED_REG_FIELDS[asr_w_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[asr_l_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E2A0 55C5 E3B0 55C6"
EXPECTED_REG_FIELDS[asr_l_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsl_b_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E328 55C5 E330 55C6"
EXPECTED_REG_FIELDS[lsl_b_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsl_w_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E368 55C5 E370 55C6"
EXPECTED_REG_FIELDS[lsl_w_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsl_l_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E3A8 55C5 E3B0 55C6"
EXPECTED_REG_FIELDS[lsl_l_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsr_b_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E228 55C5 E330 55C6"
EXPECTED_REG_FIELDS[lsr_b_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsr_w_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E268 55C5 E370 55C6"
EXPECTED_REG_FIELDS[lsr_w_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
TESTS[lsr_l_reg_count_0_preserves_x]="$SHIFT_ZERO_PREFIX E2A8 55C5 E3B0 55C6"
EXPECTED_REG_FIELDS[lsr_l_reg_count_0_preserves_x]="$SHIFT_ZERO_EXPECTED"
unset SHIFT_ZERO_PREFIX SHIFT_ZERO_EXPECTED

# ADDX/SUBX register-alias contract. Source and destination may name the same
# architectural register; both source operands must be read before writeback,
# and the incoming X bit must participate exactly once.
TESTS[addx_b_same_reg_consumes_x]="003C 0010 7400 D502"
EXPECTED_REG_FIELDS[addx_b_same_reg_consumes_x]="D2=00000001"
TESTS[addx_w_same_reg_consumes_x]="003C 0010 7400 D542"
EXPECTED_REG_FIELDS[addx_w_same_reg_consumes_x]="D2=00000001"
TESTS[addx_l_same_reg_consumes_x]="003C 0010 7400 D582"
EXPECTED_REG_FIELDS[addx_l_same_reg_consumes_x]="D2=00000001"
TESTS[subx_b_same_reg_consumes_x]="003C 0010 7400 9502"
EXPECTED_REG_FIELDS[subx_b_same_reg_consumes_x]="D2=000000ff"
TESTS[subx_w_same_reg_consumes_x]="003C 0010 7400 9542"
EXPECTED_REG_FIELDS[subx_w_same_reg_consumes_x]="D2=0000ffff"
TESTS[subx_l_same_reg_consumes_x]="003C 0010 7400 9582"
EXPECTED_REG_FIELDS[subx_l_same_reg_consumes_x]="D2=ffffffff"
TESTS[addx_b_distinct_reg_consumes_x]="003C 0010 7400 7600 D503"
EXPECTED_REG_FIELDS[addx_b_distinct_reg_consumes_x]="D2=00000001 D3=00000000"
TESTS[addx_w_distinct_reg_consumes_x]="003C 0010 7400 7600 D543"
EXPECTED_REG_FIELDS[addx_w_distinct_reg_consumes_x]="D2=00000001 D3=00000000"
TESTS[addx_l_distinct_reg_consumes_x]="003C 0010 7400 7600 D583"
EXPECTED_REG_FIELDS[addx_l_distinct_reg_consumes_x]="D2=00000001 D3=00000000"
TESTS[subx_b_distinct_reg_consumes_x]="003C 0010 7400 7600 9503"
EXPECTED_REG_FIELDS[subx_b_distinct_reg_consumes_x]="D2=000000ff D3=00000000"
TESTS[subx_w_distinct_reg_consumes_x]="003C 0010 7400 7600 9543"
EXPECTED_REG_FIELDS[subx_w_distinct_reg_consumes_x]="D2=0000ffff D3=00000000"
TESTS[subx_l_distinct_reg_consumes_x]="003C 0010 7400 7600 9583"
EXPECTED_REG_FIELDS[subx_l_distinct_reg_consumes_x]="D2=ffffffff D3=00000000"
# Sticky-Z controls cover both padding polarities and all widths: carry-in
# propagating into a zero result, no carry-in with a zero result, SBC borrow-in
# ending in zero, and both old-Z states. Register setup precedes CCR seeding
# because MOVE clears N/Z/V/C.
TESTS[addx_b_zero_sticky_z_set]="74FF 7600 003C 0014 D503"
EXPECTED_REG_FIELDS[addx_b_zero_sticky_z_set]="D2=ffffff00 D3=00000000 SR=2715"
TESTS[addx_w_zero_sticky_z_set]="243C 0000 FFFF 7600 003C 0014 D543"
EXPECTED_REG_FIELDS[addx_w_zero_sticky_z_set]="D2=00000000 D3=00000000 SR=2715"
TESTS[addx_l_zero_sticky_z_set]="243C FFFF FFFF 7600 003C 0014 D583"
EXPECTED_REG_FIELDS[addx_l_zero_sticky_z_set]="D2=00000000 D3=00000000 SR=2715"
TESTS[addx_b_zero_without_x_sticky_z_set]="7400 7600 023C 0000 003C 0004 D503"
EXPECTED_REG_FIELDS[addx_b_zero_without_x_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[addx_w_zero_without_x_sticky_z_set]="7400 7600 023C 0000 003C 0004 D543"
EXPECTED_REG_FIELDS[addx_w_zero_without_x_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[addx_l_zero_without_x_sticky_z_set]="7400 7600 023C 0000 003C 0004 D583"
EXPECTED_REG_FIELDS[addx_l_zero_without_x_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[roxl_l_zero_count_copies_cleared_x]="7000 7200 7C00 023C 0000 003C 0004 E3B0 55C6"
EXPECTED_REG_FIELDS[roxl_l_zero_count_copies_cleared_x]="D0=00000000 D1=00000000 D6=00000000 SR=2704"
TESTS[subx_b_zero_sticky_z_set]="7401 7600 003C 0014 9503"
EXPECTED_REG_FIELDS[subx_b_zero_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[subx_w_zero_sticky_z_set]="7401 7600 003C 0014 9543"
EXPECTED_REG_FIELDS[subx_w_zero_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[subx_l_zero_sticky_z_set]="7401 7600 003C 0014 9583"
EXPECTED_REG_FIELDS[subx_l_zero_sticky_z_set]="D2=00000000 D3=00000000 SR=2704"
TESTS[addx_b_zero_sticky_z_clear]="243C 0000 00FF 7600 023C 0000 003C 0010 D503"
EXPECTED_REG_FIELDS[addx_b_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2711"
TESTS[addx_w_zero_sticky_z_clear]="243C 0000 FFFF 7600 023C 0000 003C 0010 D543"
EXPECTED_REG_FIELDS[addx_w_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2711"
TESTS[addx_l_zero_sticky_z_clear]="243C FFFF FFFF 7600 023C 0000 003C 0010 D583"
EXPECTED_REG_FIELDS[addx_l_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2711"
TESTS[subx_b_zero_sticky_z_clear]="7401 7600 023C 0000 003C 0010 9503"
EXPECTED_REG_FIELDS[subx_b_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2700"
TESTS[subx_w_zero_sticky_z_clear]="7401 7600 023C 0000 003C 0010 9543"
EXPECTED_REG_FIELDS[subx_w_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2700"
TESTS[subx_l_zero_sticky_z_clear]="7401 7600 023C 0000 003C 0010 9583"
EXPECTED_REG_FIELDS[subx_l_zero_sticky_z_clear]="D2=00000000 D3=00000000 SR=2700"

# Signed-overflow and no-X controls complete the result/N/V/C/X contract for
# each active byte/word/long legacy helper.
TESTS[addx_b_overflow_with_x]="747F 7600 023C 0000 003C 0010 D503"
EXPECTED_REG_FIELDS[addx_b_overflow_with_x]="D2=00000080 D3=00000000 SR=270a"
TESTS[addx_w_overflow_with_x]="243C 0000 7FFF 7600 023C 0000 003C 0010 D543"
EXPECTED_REG_FIELDS[addx_w_overflow_with_x]="D2=00008000 D3=00000000 SR=270a"
TESTS[addx_l_overflow_with_x]="243C 7FFF FFFF 7600 023C 0000 003C 0010 D583"
EXPECTED_REG_FIELDS[addx_l_overflow_with_x]="D2=80000000 D3=00000000 SR=270a"
TESTS[subx_b_overflow_with_x]="7480 7600 023C 0000 003C 0010 9503"
EXPECTED_REG_FIELDS[subx_b_overflow_with_x]="D2=ffffff7f D3=00000000 SR=2702"
TESTS[subx_w_overflow_with_x]="243C 0000 8000 7600 023C 0000 003C 0010 9543"
EXPECTED_REG_FIELDS[subx_w_overflow_with_x]="D2=00007fff D3=00000000 SR=2702"
TESTS[subx_l_overflow_with_x]="243C 8000 0000 7600 023C 0000 003C 0010 9583"
EXPECTED_REG_FIELDS[subx_l_overflow_with_x]="D2=7fffffff D3=00000000 SR=2702"
TESTS[subx_b_without_x]="7405 7603 023C 0000 9503"
EXPECTED_REG_FIELDS[subx_b_without_x]="D2=00000002 D3=00000003 SR=2700"
TESTS[subx_w_without_x]="7405 7603 023C 0000 9543"
EXPECTED_REG_FIELDS[subx_w_without_x]="D2=00000002 D3=00000003 SR=2700"
TESTS[subx_l_without_x]="7405 7603 023C 0000 9583"
EXPECTED_REG_FIELDS[subx_l_without_x]="D2=00000002 D3=00000003 SR=2700"

# ORI/ANDI/EORI to CCR consume the guest immediate at translation time. Exact
# masks prove all five bits; borrow-produced flags prove physical-C polarity is
# normalized before the logical merge.
TESTS[ccr_ori_exact_bits]="023C 0000 003C 001F"
EXPECTED_REG_FIELDS[ccr_ori_exact_bits]="SR=271f"
TESTS[ccr_andi_exact_mask]="023C 0000 003C 001F 023C 000A"
EXPECTED_REG_FIELDS[ccr_andi_exact_mask]="SR=270a"
TESTS[ccr_eori_exact_toggle]="023C 0000 003C 001F 0A3C 0015"
EXPECTED_REG_FIELDS[ccr_eori_exact_toggle]="SR=270a"
TESTS[ccr_ori_after_borrow_flags]="7000 7201 9001 003C 0006"
EXPECTED_REG_FIELDS[ccr_ori_after_borrow_flags]="D0=000000ff D1=00000001 SR=271f"
TESTS[ccr_andi_after_borrow_flags]="7000 7201 9001 023C 0011"
EXPECTED_REG_FIELDS[ccr_andi_after_borrow_flags]="D0=000000ff D1=00000001 SR=2711"
TESTS[ccr_eori_after_borrow_flags]="7000 7201 9001 0A3C 001F"
EXPECTED_REG_FIELDS[ccr_eori_after_borrow_flags]="D0=000000ff D1=00000001 SR=2706"

# ABCD/SBCD/NBCD share C->X and sticky-Z semantics. Clear the five defined
# CCR bits before installing each incoming X/Z state so witnesses are exact.
TESTS[bcd_abcd_zero_sticky_set]="7000 7200 023C 00E0 003C 0004 C101"
EXPECTED_REG_FIELDS[bcd_abcd_zero_sticky_set]="D0=00000000 D1=00000000 SR=2704"
TESTS[bcd_abcd_zero_sticky_clear]="7000 7200 023C 00E0 C101"
EXPECTED_REG_FIELDS[bcd_abcd_zero_sticky_clear]="D0=00000000 D1=00000000 SR=2700"
TESTS[bcd_abcd_nonzero_clears_sticky]="7001 7201 023C 00E0 003C 0004 C101"
EXPECTED_REG_FIELDS[bcd_abcd_nonzero_clears_sticky]="D0=00000002 D1=00000001 SR=2700"
TESTS[bcd_abcd_carry_zero]="203C 0000 0099 7201 023C 00E0 003C 0004 C101"
EXPECTED_REG_FIELDS[bcd_abcd_carry_zero]="D0=00000000 D1=00000001 SR=2715"
TESTS[bcd_abcd_same_reg_with_x]="203C A5A5 0099 023C 00E0 003C 0014 C100"
EXPECTED_REG_FIELDS[bcd_abcd_same_reg_with_x]="D0=a5a50099 SR=2711"

TESTS[bcd_sbcd_zero_sticky_set]="7000 7200 023C 00E0 003C 0004 8101"
EXPECTED_REG_FIELDS[bcd_sbcd_zero_sticky_set]="D0=00000000 D1=00000000 SR=2704"
TESTS[bcd_sbcd_zero_sticky_clear]="7000 7200 023C 00E0 8101"
EXPECTED_REG_FIELDS[bcd_sbcd_zero_sticky_clear]="D0=00000000 D1=00000000 SR=2700"
TESTS[bcd_sbcd_borrow]="7000 7201 023C 00E0 003C 0004 8101"
EXPECTED_REG_FIELDS[bcd_sbcd_borrow]="D0=00000099 D1=00000001 SR=2711"
TESTS[bcd_sbcd_same_reg_with_x]="203C A5A5 0000 023C 00E0 003C 0014 8100"
EXPECTED_REG_FIELDS[bcd_sbcd_same_reg_with_x]="D0=a5a50099 SR=2711"

TESTS[bcd_nbcd_zero_sticky_set]="7000 023C 00E0 003C 0004 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_zero_sticky_set]="D0=00000000 SR=2704"
TESTS[bcd_nbcd_zero_sticky_clear]="7000 023C 00E0 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_zero_sticky_clear]="D0=00000000 SR=2700"
TESTS[bcd_nbcd_nonzero]="7001 023C 00E0 003C 0004 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_nonzero]="D0=00000099 SR=2711"
TESTS[bcd_nbcd_with_x]="7000 023C 00E0 003C 0014 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_with_x]="D0=00000099 SR=2711"

# Decimal boundaries plus non-decimal nibbles distinguish the authoritative
# 68040 correction equations from a superficially plausible per-digit rewrite.
# The two-ABCD vector also proves that the first decimal carry is consumed as X
# by the next native instruction and then replaced by that instruction's carry.
TESTS[bcd_abcd_decimal_09_plus_01]="7009 7201 023C 00E0 C101"
EXPECTED_REG_FIELDS[bcd_abcd_decimal_09_plus_01]="D0=00000010 D1=00000001 SR=2700"
TESTS[bcd_abcd_invalid_nibble_exact]="700A 720F 023C 00E0 003C 0010 C101"
EXPECTED_REG_FIELDS[bcd_abcd_invalid_nibble_exact]="D0=00000020 D1=0000000f SR=2700"
TESTS[bcd_abcd_extend_chain]="203C 0000 0099 7201 7400 7600 023C 00E0 003C 0004 C101 C503"
EXPECTED_REG_FIELDS[bcd_abcd_extend_chain]="D0=00000000 D1=00000001 D2=00000001 D3=00000000 SR=2700"
TESTS[bcd_sbcd_decimal_10_minus_01]="7010 7201 023C 00E0 8101"
EXPECTED_REG_FIELDS[bcd_sbcd_decimal_10_minus_01]="D0=00000009 D1=00000001 SR=2700"
TESTS[bcd_sbcd_invalid_nibble_exact]="7000 720A 023C 00E0 003C 0010 8101"
EXPECTED_REG_FIELDS[bcd_sbcd_invalid_nibble_exact]="D0=0000008f D1=0000000a SR=2711"
TESTS[bcd_nbcd_decimal_10]="7010 023C 00E0 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_decimal_10]="D0=00000090 SR=2711"
TESTS[bcd_nbcd_invalid_nibble_exact]="700A 023C 00E0 003C 0010 4800"
EXPECTED_REG_FIELDS[bcd_nbcd_invalid_nibble_exact]="D0=0000008f SR=2711"

# Opcode-first replay vectors anchor NATEXEC at the audited instruction itself.
# INIT_REGS supplies the exact state seen at native entry. The invalid-nibble
# cases distinguish the 68040 correction model from the old per-digit path.
TESTS[bcd_native_abcd_zero_sticky]="C101"
EXPECTED_REG_FIELDS[bcd_native_abcd_zero_sticky]="D0=00000000 D1=00000000 SR=2704"
TESTS[bcd_native_abcd_invalid_extend]="C101"
EXPECTED_REG_FIELDS[bcd_native_abcd_invalid_extend]="D0=00000020 D1=0000000f SR=2700"
TESTS[bcd_native_sbcd_invalid_borrow]="8101"
EXPECTED_REG_FIELDS[bcd_native_sbcd_invalid_borrow]="D0=0000008f D1=0000000a SR=2711"
TESTS[bcd_native_nbcd_invalid_borrow]="4800"
EXPECTED_REG_FIELDS[bcd_native_nbcd_invalid_borrow]="D0=0000008f SR=2711"

# ABCD/SBCD predecrement encode source and destination address registers
# independently. A7 must decrement by two for each byte access, including both
# decrements when source and destination are the same A7. NBCD provides the
# generic single-EA A7 control.
TESTS[bcd_abcd_predec_src_a7]="43F9 0000 2080 12FC 0001 45F9 0000 2040 14FC 0099 41F9 0000 2041 4FF9 0000 2082 023C 00E0 003C 0004 C10F"
EXPECTED_REG_FIELDS[bcd_abcd_predec_src_a7]="A0=00002040 A7=00002080 SR=2715"
TESTS[bcd_abcd_predec_dst_a7]="43F9 0000 2080 12FC 0001 45F9 0000 2040 14FC 0099 41F9 0000 2081 4FF9 0000 2042 023C 00E0 003C 0004 CF08"
EXPECTED_REG_FIELDS[bcd_abcd_predec_dst_a7]="A0=00002080 A7=00002040 SR=2715"
TESTS[bcd_abcd_predec_a7_alias]="43F9 0000 2082 12FC 0001 45F9 0000 2080 14FC 0099 4FF9 0000 2084 023C 00E0 003C 0004 CF0F"
EXPECTED_REG_FIELDS[bcd_abcd_predec_a7_alias]="A7=00002080 SR=2715"
TESTS[bcd_sbcd_predec_src_a7]="43F9 0000 2080 12FC 0001 45F9 0000 2040 14FC 0000 41F9 0000 2041 4FF9 0000 2082 023C 00E0 003C 0004 810F"
EXPECTED_REG_FIELDS[bcd_sbcd_predec_src_a7]="A0=00002040 A7=00002080 SR=2711"
TESTS[bcd_sbcd_predec_dst_a7]="43F9 0000 2080 12FC 0001 45F9 0000 2040 14FC 0000 41F9 0000 2081 4FF9 0000 2042 023C 00E0 003C 0004 8F08"
EXPECTED_REG_FIELDS[bcd_sbcd_predec_dst_a7]="A0=00002080 A7=00002040 SR=2711"
TESTS[bcd_sbcd_predec_a7_alias]="43F9 0000 2082 12FC 0001 45F9 0000 2080 14FC 0000 4FF9 0000 2084 023C 00E0 003C 0004 8F0F"
EXPECTED_REG_FIELDS[bcd_sbcd_predec_a7_alias]="A7=00002080 SR=2711"
TESTS[bcd_nbcd_predec_a7]="43F9 0000 2040 12FC 0001 4FF9 0000 2042 023C 00E0 003C 0004 4827"
EXPECTED_REG_FIELDS[bcd_nbcd_predec_a7]="A7=00002040 SR=2711"

# ROXL_REG_COUNT_63: ORI #$10,CCR (set X); MOVE.L #$A5A55A5A,D0; MOVEQ #63,D1; ROXL.L D1,D0
# Stresses masked high register-count behavior near the 6-bit limit.
# ORI.B #$10,CCR = 003C 0010; MOVE.L #$A5A55A5A,D0 = 203C A5A5 5A5A; MOVEQ #63,D1 = 723F; ROXL.L D1,D0 = E3B0
TESTS[roxl_reg_count_63]="003C 0010 203C A5A5 5A5A 723F E3B0"
# ROXR_REG_COUNT_63: ORI #$10,CCR (set X); MOVE.L #$5A5AA5A5,D0; MOVEQ #63,D1; ROXR.L D1,D0
# Companion masked-high-count stress for right rotate-through-extend.
# ORI.B #$10,CCR = 003C 0010; MOVE.L #$5A5AA5A5,D0 = 203C 5A5A A5A5; MOVEQ #63,D1 = 723F; ROXR.L D1,D0 = E2B0
TESTS[roxr_reg_count_63]="003C 0010 203C 5A5A A5A5 723F E2B0"
# ROXR_ROXL_CHAIN_X: ORI #$10,CCR; MOVE.L #1,D0; MOVEQ #1,D1; ROXR.L D1,D0; ROXL.L D1,D0
# Chained opposite-direction rotate-through-X operations stress carry/extend handoff.
# ORI.B #$10,CCR = 003C 0010; MOVE.L #1,D0 = 203C 0000 0001; MOVEQ #1,D1 = 7201; ROXR.L D1,D0 = E2B0; ROXL.L D1,D0 = E3B0
TESTS[roxr_roxl_chain_x]="003C 0010 203C 0000 0001 7201 E2B0 E3B0"
# ROXL_LSR_CHAIN_X: ORI #$10,CCR; MOVE.L #$80000001,D0; MOVEQ #1,D1; ROXL.L D1,D0; LSR.L D1,D0
# Mixed rotate+shift chain stresses X/C handoff into logical shifts.
# ORI.B #$10,CCR = 003C 0010; MOVE.L #$80000001,D0 = 203C 8000 0001; MOVEQ #1,D1 = 7201; ROXL.L D1,D0 = E3B0; LSR.L D1,D0 = E2A8
TESTS[roxl_lsr_chain_x]="003C 0010 203C 8000 0001 7201 E3B0 E2A8"
# MULU_LARGE: MOVE.L #$FFFF,D0; MOVE.L #$FFFF,D1; MULU D1,D0
# 0xFFFF * 0xFFFF = 0xFFFE0001 — tests large unsigned multiply result
# MOVE.L #$FFFF,D0 = 203C 0000 FFFF; MOVE.L #$FFFF,D1 = 223C 0000 FFFF; MULU D1,D0 = C0C1
TESTS[mulu_large]="203C 0000 FFFF 223C 0000 FFFF C0C1"
# DIVU_REMAINDER: MOVE.L #$00070005,D0; MOVEQ #3,D1; DIVU D1,D0
# 0x70005 = 458757; 458757/3 = quotient 152919 (too large for 16 bits? No: 152919 > 65535 → overflow)
# Let me use a smaller dividend: MOVE.L #$00030005,D0; MOVEQ #2,D1; DIVU D1,D0
# 0x30005 = 196613; 196613/2 = 98306 > 65535 → overflow. Let me think...
# MOVE.L #$0001FFFF,D0; MOVEQ #2,D1; DIVU D1,D0
# 0x1FFFF = 131071; 131071/2 = quotient 65535 remainder 1
# Result: D0 = (rem << 16) | quot = 0x0001FFFF
# MOVE.L #$0001FFFF,D0 = 203C 0001 FFFF; MOVEQ #2,D1 = 7202; DIVU D1,D0 = 80C1
TESTS[divu_remainder]="203C 0001 FFFF 7202 80C1"
# ABCD_WITH_CARRY: test ABCD with X flag set
# ORI #$10,CCR; MOVEQ #$99,D0; MOVEQ #$01,D1; ABCD D1,D0
# BCD: 99+01+X(1) = 01 with carry (X=1, C=1 after)
# Wait: 0x99 via MOVEQ is sign-extended: MOVEQ #$99 doesn't work (>127 signed).
# Use: MOVE.L #$99,D0 = 203C 0000 0099; but MOVEQ #-103 = 0x99...no.
# MOVEQ range is -128 to 127, so 0x99 = 153 is out of range.
# Use MOVE.B #$99,D0 — but that's not a single simple encoding. 
# Better: MOVEQ #0,D0; ORI.B #$99,D0
# ORI.B #$99,D0 = 0000 0099
# Full: ORI #$10,CCR; MOVEQ #0,D0; ORI.B #$99,D0; MOVEQ #1,D1; ABCD D1,D0
# 003C 0010 7000 0000 0099 7201 C101
TESTS[abcd_with_carry]="003C 0010 7000 0000 0099 7201 C101"
# NBCD_BASIC: MOVEQ #0,D0; ORI.B #$42,D0; NBCD D0
# NBCD: 0 - D0 - X(0) in BCD = 0 - 0x42 = 0x58 (BCD complement)
# Wait: NBCD with X=0: result = (0x9A - D0) if D0 != 0, or 0 if D0 == 0
# Actually NBCD = 0 - src - X in BCD
# With X=0: 0 - 0x42 in BCD: borrow from tens: 10-2=8 for units, 9-4=5 for tens -> 0x58
# But the real M68K behavior: if zero result with no borrow, Z unchanged; else Z cleared
# MOVEQ #0,D0 = 7000; ORI.B #$42,D0 = 0000 0042; NBCD D0 = 4800
TESTS[nbcd_basic]="7000 0000 0042 4800"
# BSR_RTS: BSR to subroutine that sets D0=#$55, then RTS back
# MOVEQ #1,D0; BSR.B +4; MOVEQ #2,D1; BRA.B +4; MOVEQ #$55,D0; RTS
TESTS[bsr_rts]="7001 6104 7202 6004 7055 4E75"
# LINK_UNLK: LINK A5,#-8 / UNLK A5 frame pointer test
# LEA $4000,A0; MOVEA.L A0,A7; LINK A5,#-8; MOVEQ #$42,D0; MOVE.L D0,(A5);
# CLR.L D0; MOVE.L (A5),D1; UNLK A5
TESTS[link_unlk]="41F9 0000 4000 2E48 4E55 FFF8 7042 2A80 4280 2215 4E5D"
# INDEXED_ADDR_MODE: MOVE.L #$DEADBEEF to (4,A0), read back via (0,A0,D1.L)
# LEA $5000,A0; MOVE.L #$DEADBEEF,(4,A0); CLR.L D0; MOVEQ #4,D1; MOVE.L (0,A0,D1.L),D0
TESTS[indexed_addr_mode]="41F9 0000 5000 217C DEAD BEEF 0004 4280 7204 2030 1800"
# INDEXED_FULL_NEG_BASE: first execute BSR.B/RTS so constant register-sourced
# PC_P addition exercises the pointer-width contract, then use a 68020
# full-format (bd,A0,D1.L) EA with a negative word base displacement and a
# sign-bit-set guest address. Guest EA arithmetic must remain modulo 2^32;
# treating the displacement as a host-pointer marker leaves dirty upper X bits
# and makes correctness depend on every later consumer re-applying UXTW.
# BSR.B sub; RTS; LEA $E0000010,A0; D0=0; D1=0;
# MOVE.L (-16,A0,D1.L),D0.
TESTS[indexed_full_neg_base]="7001 6104 7202 6004 7055 4E75 41F9 E000 0010 7000 7200 2030 1920 FFF0"
# IO_BYTE_WRITE_ROUNDTRIP: direct JIT stores must use the same byte value as
# interpreter put_byte(). The old ARM64 helper transformed every 0x50xxxxxx
# write except two scanner offsets, so 0x11 read back as 0xDE. A1 targets the
# low-NuBus/JIT-cache alias gap: byte/word/long writes must be ignored and reads
# must return width-correct all-ones open bus values. Native replay resets the
# architectural input and executes this straight-line block a second time after
# forcing immediate RAM L2 promotion.
TESTS[io_byte_write_roundtrip]="7011 1080 4281 1210 1280 3280 2280 1411 3611 2811"
# BYTE_POSTINC: write 4 bytes via (A0)+, read back via (A1)+
# LEA $6000,A0; LEA $6000,A1; MOVEQ #$11,D4; MOVE.B D4,(A0)+;
# MOVEQ #$22,D5; MOVE.B D5,(A0)+; MOVEQ #$33,D6; MOVE.B D6,(A0)+;
# MOVEQ #$44,D7; MOVE.B D7,(A0)+; MOVE.B (A1)+,D0; MOVE.B (A1)+,D1;
# MOVE.B (A1)+,D2; MOVE.B (A1)+,D3
TESTS[byte_postinc]="41F9 0000 6000 43F9 0000 6000 7811 10C4 7A22 10C5 7C33 10C6 7E44 10C7 1019 1219 1419 1619"
# CMPM_EQUAL: CMPM.B (A0)+,(A1)+ on equal bytes should set Z=1
# LEA $7000,A0; LEA $7010,A1; MOVEQ #-85,D0 ($AB); MOVE.B D0,(A0); MOVE.B D0,(A1); CMPM.B (A0)+,(A1)+
TESTS[cmpm_equal]="41F9 0000 7000 43F9 0000 7010 70AB 1080 1280 B308"
# MOVE_SR_ROUNDTRIP: MOVE.W #$2710,SR then MOVE.W SR,D0 — SR read/write roundtrip
TESTS[move_sr_roundtrip]="46FC 2710 40C0 7242"
# DBRA_LOOP_100: MOVEQ #99,D0; MOVEQ #0,D1; ADDQ.L #1,D1; DBRA D0,-4
# After 100 iterations: D0.W=$FFFF, D1=100=0x64
# This is a multi-block loop that exercises JIT block re-execution and DBRA compilation
TESTS[dbra_loop_100]="7063 7200 5281 51C8 FFFC"
# MOVE: MOVEQ #0x42,D0; MOVE.L D0,D1; MOVEQ #-1,D2; MOVE.W D2,D3
TESTS[move]="7042 2200 74FF 3602"
# MOVEQ_SIGNEXT: verify MOVEQ sign-extension with CMPI.L and CMPI.W checks
TESTS[moveq_signext]="70FF 0C80 FFFF FFFF 0C40 FFFF 2200"
# ALU: MOVEQ #5,D0; MOVEQ #3,D1; ADD.L D1,D0; SUB.L D1,D0; AND.L D1,D0
TESTS[alu]="7005 7203 D081 9081 C081"
# ALU_OVERFLOW: MOVEQ #0x7f,D0; ADDQ.L #1,D0; SUBQ.L #1,D0
TESTS[alu_overflow]="707F 5280 5180"
# ADDI_SUBI_LONG: MOVEQ #5,D0; ADDI.L #3,D0; SUBI.L #1,D0
TESTS[addi_subi_long]="7005 0680 0000 0003 0480 0000 0001"
# ADDI_SUBI_LONG_WRAP: long arithmetic around 0x7fffffff/0x80000000 boundary with explicit CMPI.L check
TESTS[addi_subi_long_wrap]="203C 7FFF FFFF 0680 0000 0001 0480 0000 0001 0C80 7FFF FFFF"
# ADDI_SUBI_WORD: MOVEQ #0,D0; ADDI.W #0x1234,D0; SUBI.W #0x20,D0
TESTS[addi_subi_word]="7000 0640 1234 0440 0020"
# ADDI_SUBI_WORD_WRAP: word arithmetic around 0x7fff/0x8000 boundary with explicit CMPI.W check
TESTS[addi_subi_word_wrap]="7000 0640 7FFF 0640 0001 0440 0001 0C40 7FFF"
# ADDI_SUBI_BYTE: byte-sized immediate arithmetic with explicit CMPI.B verification
TESTS[addi_subi_byte]="7000 0600 007F 0400 0001 0C00 007E"
# ADDI_SUBI_BYTE_WRAP: byte arithmetic around 0x7f/0x80 boundary with explicit CMPI.B check
TESTS[addi_subi_byte_wrap]="7000 0600 007F 0600 0001 0400 0001 0C00 007F"
# SHIFT: MOVEQ #8,D0; LSL.L #1,D0; LSR.L #2,D0; ASR.L #1,D0; ROL.L #1,D0
TESTS[shift]="7008 E388 E888 E080 E398"
# BITOPS: MOVEQ #0,D0; BSET #3,D0; BTST #3,D0; BCLR #3,D0; BTST #3,D0
TESTS[bitops]="7000 08C0 0003 0800 0003 0880 0003 0800 0003"
# BITOPS_CHG: toggle bit 0 twice with BCHG and verify BTST executes
TESTS[bitops_chg]="7000 0840 0000 0840 0000 0800 0000"
# BITOPS_HIGHBIT: exercise immediate bit operations on bit 31 (long-width boundary)
TESTS[bitops_highbit]="7000 08C0 001F 0800 001F 0880 001F 0800 001F"
# BITOPS_CHG_HIGHBIT: toggle bit 31 twice with BCHG immediate and verify BTST executes
TESTS[bitops_chg_highbit]="7000 0840 001F 0840 001F 0800 001F"
# BRANCH: MOVEQ #0,D0; CMP.L D0,D0; BEQ.S +2; MOVEQ #1,D0 (should skip); MOVEQ #2,D1
TESTS[branch]="7000 B080 6702 7001 7202"
# BRANCH_CHAIN: BEQ taken then BNE not-taken under same flags (Z remains set)
TESTS[branch_chain]="7001 B080 6702 7207 6602 7408"
# COMPARE: MOVEQ #5,D0; MOVEQ #3,D1; CMP.L D1,D0; TST.L D0; CMPI.L #5,D0
TESTS[compare]="7005 7203 B081 4A80 0C80 0000 0005"
# COMPARE_NEGATIVE: compare against -1 and verify BNE not-taken path
TESTS[compare_negative]="70FF 0C80 FFFF FFFF 6602 7207"
# CMPI_SIZES: run CMPI.B/W/L forms against D0 to exercise immediate size decoding
TESTS[cmpi_sizes]="7001 0C00 0001 0C40 0001 0C80 0000 0001"
# CMPI_SIZES_ZERO: run CMPI.B/W/L zero-immediate forms against zeroed D0
TESTS[cmpi_sizes_zero]="7000 0C00 0000 0C40 0000 0C80 0000 0000"
# CMPI_BYTE_NEGATIVE: verify CMPI.B sign/boundary behavior against 0xff and BEQ taken path
TESTS[cmpi_byte_negative]="70FF 0C00 00FF 6702 7207 7408"
# CMPI_WORD_NEGATIVE: verify CMPI.W sign/boundary behavior against 0xffff and BEQ taken path
TESTS[cmpi_word_negative]="70FF 0C40 FFFF 6702 7207 7408"
# CMPI_LONG_NEGATIVE: verify CMPI.L sign/boundary behavior against 0xffffffff and BEQ taken path
TESTS[cmpi_long_negative]="70FF 0C80 FFFF FFFF 6702 7207 7408"
# CMPI_BEQ_TAKEN: compare equal immediate then take BEQ short path
TESTS[cmpi_beq_taken]="7000 0C80 0000 0000 6702 7207 7408"
# MULDIV: MOVEQ #7,D0; MULU.W #3,D0; MOVEQ #21,D1; DIVU.W #3,D1
TESTS[muldiv]="7007 C0FC 0003 7215 82FC 0003"
# MOVEM: setup stack; MOVEM.L D0-D3,-(SP); MOVEM.L (SP)+,D4-D7
TESTS[movem]="7011 7213 7415 7617 48E7 F000 4CDF 000F"
# MISC: MOVEQ #0x5A,D0; SWAP D0; EXT.L D0; CLR.W D1; NEG.L D0
TESTS[misc]="705A 4840 4880 4241 4480"
# CLR_SIZES: verify CLR.B/W/L execution paths and immediate compares on resulting zeros
TESTS[clr_sizes]="203C FFFF FFFF 4200 0C00 0000 4240 0C40 0000 4280 0C80 0000 0000"
# CLR_BYTE_PRESERVE_UPPER: CLR.B should clear low byte while preserving upper 24 bits
TESTS[clr_byte_preserve_upper]="203C 1234 5678 4200 0C80 1234 5600"
# CLR_WORD_PRESERVE_UPPER: CLR.W should clear low word while preserving upper 16 bits
TESTS[clr_word_preserve_upper]="203C 89AB CDEF 4240 0C80 89AB 0000"
# NEG_SIZES: verify NEG.B/W/L execution paths against -1 results in each size domain
TESTS[neg_sizes]="7001 4400 0C00 00FF 7201 4441 0C41 FFFF 7401 4482 0C82 FFFF FFFF"
# NEG_ZERO_SIZES: verify NEG.B/W/L on zero value keeps result at zero across size forms
TESTS[neg_zero_sizes]="7000 4400 4440 4480 0C80 0000 0000"
# SWAP_ROUNDTRIP: SWAP applied twice should restore original long value
TESTS[swap_roundtrip]="7012 4840 4840 0C80 0000 0012"
# FLAGS: MOVE #0x2700,SR; ORI #0x10,CCR; ANDI #0xEF,CCR; MOVE SR,D0
TESTS[flags]="46FC 2700 003C 0010 023C 00EF 40C0"
# FLAGS_EORI_CCR: verify EORI to CCR path under supervisor SR setup
TESTS[flags_eori_ccr]="46FC 2700 003C 0011 0A3C 0010 40C0"
# EXG: MOVEQ #1,D0; MOVEQ #2,D1; EXG D0,D1
TESTS[exg]="7001 7202 C141"
# EXG_ROUNDTRIP: two EXG operations should restore original D0/D1 values
TESTS[exg_roundtrip]="7001 7202 C141 C141"
# IMM_LOGIC: MOVEQ #0,D0; ORI.B #0x0f,D0; EORI.B #0xf0,D0; ANDI.B #0x3c,D0
TESTS[imm_logic]="7000 0000 000F 0A00 00F0 0200 003C"
# IMM_LOGIC_ALT: alternate immediate-byte logic sequence for edge mask patterns
TESTS[imm_logic_alt]="7000 0000 00AA 0200 000F 0A00 0005"
# IMM_LOGIC_BYTE_HIGHBIT: byte-width OR/EOR around 0x80 edge, then normalize with ANDI.B/CMPI.B
TESTS[imm_logic_byte_highbit]="7000 0000 0080 0A00 0080 0200 00FF 0C00 0000"
# IMM_LOGIC_WORD: immediate word-width OR/EOR/AND sequence to cover non-byte forms
TESTS[imm_logic_word]="7000 0040 00FF 0A40 0F0F 0240 00F0"
# IMM_LOGIC_LONG: immediate long-width OR/EOR/AND sequence to cover .L forms
TESTS[imm_logic_long]="7000 0080 00FF 00FF 0A80 0F0F 0F0F 0280 00F0 00F0"
# IMM_LOGIC_LONG_ALT: alternate immediate long masks to exercise non-trivial bit patterns
TESTS[imm_logic_long_alt]="203C F0F0 F0F0 0080 0F0F 0F0F 0A80 00FF 00FF 0280 0F0F 0F0F"
# TST_SIZES: exercise TST.B/W/L decode+flag paths on a negative value
TESTS[tst_sizes]="70FF 4A00 4A40 4A80"
# TST_ZERO: exercise TST.B/W/L decode+flag paths on zero value
TESTS[tst_zero]="7000 4A00 4A40 4A80"
# TST_POSITIVE: exercise TST.B/W/L decode+flag paths on positive non-zero value
TESTS[tst_positive]="7001 4A00 4A40 4A80"
# BRA_TAKEN: unconditional branch should skip MOVEQ #9,D1
TESTS[bra_taken]="7001 6002 7209 7402"
# BRA_W_TAKEN: unconditional word-displacement branch should skip MOVEQ #9,D1
TESTS[bra_w_taken]="7001 6000 0002 7209 7402"
# BNE_NOT_TAKEN: CMP.L D0,D0 sets Z=1; BNE should not branch
TESTS[bne_not_taken]="7001 B080 6602 7207"
# BNE_TAKEN: CMPI.L #2,D0 sets Z=0; BNE should branch and skip MOVEQ #7,D1
TESTS[bne_taken]="7001 0C80 0000 0002 6602 7207 7408"
# BNE_W_NOT_TAKEN: CMP.L D0,D0 sets Z=1; BNE.W should not branch
TESTS[bne_w_not_taken]="7001 B080 6600 0002 7207"
# BNE_W_TAKEN: CMPI.L #2,D0 sets Z=0; BNE.W should branch and skip MOVEQ #7,D1
TESTS[bne_w_taken]="7001 0C80 0000 0002 6600 0002 7207 7408"
# BEQ_TAKEN: CMP.L D0,D0 sets Z=1; BEQ should branch and skip MOVEQ #7,D1
TESTS[beq_taken]="7001 B080 6702 7207 7408"
# BEQ_NOT_TAKEN: CMPI.L #2,D0 sets Z=0; BEQ should not branch
TESTS[beq_not_taken]="7001 0C80 0000 0002 6702 7207"
# BEQ_W_TAKEN: CMP.L D0,D0 sets Z=1; BEQ.W should branch and skip MOVEQ #7,D1
TESTS[beq_w_taken]="7001 B080 6700 0002 7207 7408"
# BEQ_W_NOT_TAKEN: CMPI.L #2,D0 sets Z=0; BEQ.W should not branch
TESTS[beq_w_not_taken]="7001 0C80 0000 0002 6700 0002 7207"
# BPL_TAKEN: N=0 so BPL should branch and skip MOVEQ #9,D1
TESTS[bpl_taken]="7001 6A02 7209 7402"
# BPL_NOT_TAKEN: N=1 (MOVEQ #-1) so BPL should not branch
TESTS[bpl_not_taken]="70FF 6A02 7203"
# BPL_W_TAKEN: word-displacement BPL with N=0 should branch and skip MOVEQ #9,D1
TESTS[bpl_w_taken]="7001 6A00 0002 7209 7402"
# BPL_W_NOT_TAKEN: word-displacement BPL with N=1 should not branch
TESTS[bpl_w_not_taken]="70FF 6A00 0002 7203"
# BMI_TAKEN: N=1 (MOVEQ #-1) so BMI should branch and skip MOVEQ #9,D1
TESTS[bmi_taken]="70FF 6B02 7209 7402"
# BMI_NOT_TAKEN: N=0 so BMI should not branch
TESTS[bmi_not_taken]="7001 6B02 7203"
# BMI_W_TAKEN: word-displacement BMI with N=1 should branch and skip MOVEQ #9,D1
TESTS[bmi_w_taken]="70FF 6B00 0002 7209 7402"
# BMI_W_NOT_TAKEN: word-displacement BMI with N=0 should not branch
TESTS[bmi_w_not_taken]="7001 6B00 0002 7203"
# BVC_TAKEN: V=0 in this sequence, so BVC should branch and skip MOVEQ #9,D1
TESTS[bvc_taken]="7001 6802 7209 7402"
# BVC_NOT_TAKEN_OVERFLOW: 0x7fffffff + 1 sets V=1; BVC should not branch
TESTS[bvc_not_taken_overflow]="203C 7FFF FFFF 5280 6802 7207"
# BVC_W_TAKEN: word-displacement BVC with V=0 should branch and skip MOVEQ #9,D1
TESTS[bvc_w_taken]="7001 6800 0002 7209 7402"
# BVC_W_NOT_TAKEN_OVERFLOW: word-displacement BVC with V=1 should not branch
TESTS[bvc_w_not_taken_overflow]="203C 7FFF FFFF 5280 6800 0002 7207"
# BVS_TAKEN_OVERFLOW: 0x7fffffff + 1 sets V=1; BVS should branch and skip MOVEQ #7,D1
TESTS[bvs_taken_overflow]="203C 7FFF FFFF 5280 6902 7207 7408"
# BVS_NOT_TAKEN: V=0 in this sequence, so BVS should not branch
TESTS[bvs_not_taken]="7001 6902 7203"
# BVS_W_TAKEN_OVERFLOW: word-displacement BVS with V=1 should branch and skip MOVEQ #7,D1
TESTS[bvs_w_taken_overflow]="203C 7FFF FFFF 5280 6900 0002 7207 7408"
# BVS_W_NOT_TAKEN: word-displacement BVS with V=0 should not branch
TESTS[bvs_w_not_taken]="7001 6900 0002 7203"
# BGE_TAKEN: N==V==0, so BGE should branch and skip MOVEQ #9,D1
TESTS[bge_taken]="7001 6C02 7209 7402"
# BGE_NOT_TAKEN: CMPI.L #2,D0 yields N=1,V=0; BGE should not branch
TESTS[bge_not_taken]="7001 0C80 0000 0002 6C02 7207"
# BGE_W_TAKEN: word-displacement BGE with N==V==0 should branch and skip MOVEQ #9,D1
TESTS[bge_w_taken]="7001 6C00 0002 7209 7402"
# BGE_W_NOT_TAKEN: word-displacement BGE with N!=V should not branch
TESTS[bge_w_not_taken]="7001 0C80 0000 0002 6C00 0002 7207"
# BLT_TAKEN: CMPI.L #2,D0 yields N=1,V=0; BLT should branch and skip MOVEQ #7,D1
TESTS[blt_taken]="7001 0C80 0000 0002 6D02 7207 7408"
# BLT_NOT_TAKEN: N==V==0, so BLT should not branch
TESTS[blt_not_taken]="7001 6D02 7203"
# BLT_W_TAKEN: word-displacement BLT with N!=V should branch and skip MOVEQ #7,D1
TESTS[blt_w_taken]="7001 0C80 0000 0002 6D00 0002 7207 7408"
# BLT_W_NOT_TAKEN: word-displacement BLT with N==V==0 should not branch
TESTS[blt_w_not_taken]="7001 6D00 0002 7203"
# BGT_TAKEN: Z==0 and N==V==0, so BGT should branch and skip MOVEQ #9,D1
TESTS[bgt_taken]="7001 6E02 7209 7402"
# BGT_NOT_TAKEN: CMP.L D0,D0 sets Z=1; BGT should not branch
TESTS[bgt_not_taken]="7001 B080 6E02 7207"
# BGT_W_TAKEN: word-displacement BGT with Z==0,N==V==0 should branch and skip MOVEQ #9,D1
TESTS[bgt_w_taken]="7001 6E00 0002 7209 7402"
# BGT_W_NOT_TAKEN: word-displacement BGT with Z=1 should not branch
TESTS[bgt_w_not_taken]="7001 B080 6E00 0002 7207"
# BLE_TAKEN: CMP.L D0,D0 sets Z=1; BLE should branch and skip MOVEQ #7,D1
TESTS[ble_taken]="7001 B080 6F02 7207 7408"
# BLE_NOT_TAKEN: Z==0 and N==V==0, so BLE should not branch
TESTS[ble_not_taken]="7001 6F02 7203"
# BLE_W_TAKEN: word-displacement BLE with Z=1 should branch and skip MOVEQ #7,D1
TESTS[ble_w_taken]="7001 B080 6F00 0002 7207 7408"
# BLE_W_NOT_TAKEN: word-displacement BLE with Z==0,N==V==0 should not branch
TESTS[ble_w_not_taken]="7001 6F00 0002 7203"
# BCC_TAKEN: CMPI.L #0,D0 sets C=0; BCC should branch and skip MOVEQ #7,D1
TESTS[bcc_taken]="7001 0C80 0000 0000 6402 7207 7408"
# BCC_NOT_TAKEN: CMPI.L #2,D0 sets C=1; BCC should not branch
TESTS[bcc_not_taken]="7001 0C80 0000 0002 6402 7207"
# BCC_W_TAKEN: word-displacement BCC with C=0 should branch and skip MOVEQ #7,D1
TESTS[bcc_w_taken]="7001 0C80 0000 0000 6400 0002 7207 7408"
# BCC_W_NOT_TAKEN: word-displacement BCC with C=1 should not branch
TESTS[bcc_w_not_taken]="7001 0C80 0000 0002 6400 0002 7207"
# BCS_TAKEN: CMPI.L #2,D0 sets C=1; BCS should branch and skip MOVEQ #7,D1
TESTS[bcs_taken]="7001 0C80 0000 0002 6502 7207 7408"
# BCS_NOT_TAKEN: CMPI.L #0,D0 sets C=0; BCS should not branch
TESTS[bcs_not_taken]="7001 0C80 0000 0000 6502 7207"
# BCS_W_TAKEN: word-displacement BCS with C=1 should branch and skip MOVEQ #7,D1
TESTS[bcs_w_taken]="7001 0C80 0000 0002 6500 0002 7207 7408"
# BCS_W_NOT_TAKEN: word-displacement BCS with C=0 should not branch
TESTS[bcs_w_not_taken]="7001 0C80 0000 0000 6500 0002 7207"
# BHI_TAKEN: CMPI.L #0,D0 sets C=0,Z=0; BHI should branch and skip MOVEQ #7,D1
TESTS[bhi_taken]="7001 0C80 0000 0000 6202 7207 7408"
# BHI_NOT_TAKEN: CMP.L D0,D0 sets Z=1; BHI should not branch
TESTS[bhi_not_taken]="7001 B080 6202 7207"
# BHI_W_TAKEN: word-displacement BHI with C=0,Z=0 should branch and skip MOVEQ #7,D1
TESTS[bhi_w_taken]="7001 0C80 0000 0000 6200 0002 7207 7408"
# BHI_W_NOT_TAKEN: word-displacement BHI with Z=1 should not branch
TESTS[bhi_w_not_taken]="7001 B080 6200 0002 7207"
# BLS_TAKEN: CMP.L D0,D0 sets Z=1; BLS should branch and skip MOVEQ #7,D1
TESTS[bls_taken]="7001 B080 6302 7207 7408"
# BLS_NOT_TAKEN: CMPI.L #0,D0 sets C=0,Z=0; BLS should not branch
TESTS[bls_not_taken]="7001 0C80 0000 0000 6302 7207"
# BLS_W_TAKEN: word-displacement BLS with Z=1 should branch and skip MOVEQ #7,D1
TESTS[bls_w_taken]="7001 B080 6300 0002 7207 7408"
# BLS_W_NOT_TAKEN: word-displacement BLS with C=0,Z=0 should not branch
TESTS[bls_w_not_taken]="7001 0C80 0000 0000 6300 0002 7207"
# SCC_BASIC: MOVEQ #0,D0/D1; ST D0 (set true); SF D1 (set false)
TESTS[scc_basic]="7000 7200 50C0 51C1"
# SCC_EQ_NE: set Z=1, then SNE should be false and SEQ should be true
TESTS[scc_eq_ne]="7001 7200 7400 B080 56C1 57C2"
# SCC_CARRY: set C=1, then SCC should be false and SCS should be true
TESTS[scc_carry]="7001 7200 7400 0C80 0000 0002 54C1 55C2"
# SCC_HI_LS: set C=0,Z=0; SHI should be true and SLS should be false
TESTS[scc_hi_ls]="7001 7200 7400 0C80 0000 0000 52C1 53C2"
# SCC_HI_LS_Z: set Z=1; SHI should be false and SLS should be true
TESTS[scc_hi_ls_z]="7001 7200 7400 B080 52C1 53C2"
# SCC_VC_VS: force V=1 via overflow; SVC should be false and SVS should be true
TESTS[scc_vc_vs]="203C 7FFF FFFF 5280 58C1 59C2"
# SCC_PL_MI: set N=1 via MOVEQ #-1; SPL should be false and SMI should be true
TESTS[scc_pl_mi]="70FF 5AC1 5BC2"
# SCC_GE_LT: CMPI.L #2,D0 with D0=1 gives N=1,V=0; SGE false, SLT true
TESTS[scc_ge_lt]="7001 0C80 0000 0002 5CC1 5DC2"
# SCC_GT_LE: CMP.L D0,D0 gives Z=1; SGT false, SLE true
TESTS[scc_gt_le]="7001 B080 5EC1 5FC2"
# SCC_CCR_PRESERVE_BLT: SLT should not clobber CCR; BLT must still branch from prior CMPI flags
TESTS[scc_ccr_preserve_blt]="7001 0C80 0000 0002 5DC1 6D02 7407 7608"
# SCC_CCR_PRESERVE_BCS: SCS should not clobber CCR; BCS must still branch from prior CMPI carry flag
TESTS[scc_ccr_preserve_bcs]="7001 0C80 0000 0002 55C1 6502 7407 7608"
# SCC_CCR_PRESERVE_BNE_NOT_TAKEN: SNE should not clobber CCR; BNE should remain not-taken when Z=1
TESTS[scc_ccr_preserve_bne_not_taken]="7001 B080 56C1 6602 7407 7608"
# SCC_CCR_PRESERVE_BEQ_TAKEN: SEQ should not clobber CCR; BEQ should remain taken when Z=1
TESTS[scc_ccr_preserve_beq_taken]="7001 B080 57C1 6702 7407 7608"
# QUICK_OPS: MOVEQ #5,D0; ADDQ.L #1,D0; SUBQ.L #1,D0; MOVE.L D0,D1
TESTS[quick_ops]="7005 5280 5180 2200"
# QUICK_OPS_LONG_NEG_ROUNDTRIP: start at -1, addq/subq roundtrip through zero and verify long result
TESTS[quick_ops_long_neg_roundtrip]="70FF 5280 5180 0C80 FFFF FFFF"
# QUICK_OPS_WORD: word-sized add/sub quick on D0 low word, then move.w to D1
TESTS[quick_ops_word]="70FF 5240 5140 3200"
# QUICK_OPS_WORD_WRAP: ADDQ/SUBQ word across 0x7fff/0x8000 boundary with explicit CMPI.W check
TESTS[quick_ops_word_wrap]="7000 0640 7FFF 5240 5140 0C40 7FFF"
# QUICK_OPS_LONG_WRAP: ADDQ/SUBQ long across 0x7fffffff/0x80000000 boundary with explicit CMPI.L check
TESTS[quick_ops_long_wrap]="203C 7FFF FFFF 5280 5180 0C80 7FFF FFFF"
# QUICK_OPS_BYTE: byte-sized add/sub quick on D0 low byte with explicit CMPI.B validation
TESTS[quick_ops_byte]="7000 5200 5100 0C00 0000"
# QUICK_OPS_BYTE_WRAP: ADDQ/SUBQ byte across 0x7f/0x80 boundary with explicit CMPI.B check
TESTS[quick_ops_byte_wrap]="707F 5200 5100 0C00 007F"
# QUICK_OPS_ADDR: addq/subq on A0 uses address-register execution path
TESTS[quick_ops_addr]="207C 0000 0100 5288 5188"
# DBRA: MOVEQ #1,D0; DBRA D0,+2 (taken once, skips MOVEQ #9,D1); NOP
TESTS[dbra]="7001 51C8 0002 7209 4E71"
# DBRA_NOT_TAKEN: MOVEQ #0,D0; DBRA D0,+2 should not branch (counter reaches -1)
TESTS[dbra_not_taken]="7000 51C8 0002 7207"
# DBRA_START_MINUS1_BRANCH: start at D0=-1 (0xFFFF low word) and verify DBRA still decrements and branches
# MOVEQ #-1,D0; DBRA D0,+2; MOVEQ #7,D1 (skipped if branch); MOVEQ #8,D2
TESTS[dbra_start_minus1_branch]="70FF 51C8 0002 7207 7408"
# DBRA_START_8000_BRANCH: start at D0=0x8000 and verify DBRA decrements to 0x7fff and branches
# MOVE.L #0x00008000,D0; DBRA D0,+2; MOVEQ #7,D1 (skipped if branch); MOVEQ #8,D2
TESTS[dbra_start_8000_branch]="203C 0000 8000 51C8 0002 7207 7408"
# DBT_TRUE_NOT_TAKEN: condition true should never decrement or branch in DBcc form
TESTS[dbt_true_not_taken]="7001 7400 50C8 0002 7207"
# DBRA_THREE_ITER: D0 starts at 2; loop body ADDQ runs three times before fallthrough
TESTS[dbra_three_iter]="7002 7200 5281 51C8 FFFA"
# DBCC_LOOP_C_SET: set C=1 so DBCC condition is false; bounded loop executes exactly twice for D0=1
TESTS[dbcc_loop_c_set]="7001 7201 0C81 0000 0002 4E71 54C8 FFFA"
# DBCS_NOT_TAKEN_C_SET: set C=1 so DBCS condition is true (no decrement/branch)
TESTS[dbcs_not_taken_c_set]="7001 7201 0C81 0000 0002 55C8 0002 7407"
# DBPL_LOOP_N_SET: set N=1 so DBPL condition is false; bounded loop executes exactly twice for D0=1
TESTS[dbpl_loop_n_set]="7001 74FF 4E71 5AC8 FFFA"
# DBMI_NOT_TAKEN_N_SET: set N=1 so DBMI condition is true (no decrement/branch)
TESTS[dbmi_not_taken_n_set]="7001 74FF 5BC8 0002 7608"
# DBHI_NOT_TAKEN_HI_SET: set C=0,Z=0 so DBHI condition is true (no decrement/branch)
TESTS[dbhi_not_taken_hi_set]="7001 7201 0C81 0000 0000 52C8 0002 7407"
# DBLS_NOT_TAKEN_LS_SET: set Z=1 so DBLS condition is true (no decrement/branch)
TESTS[dbls_not_taken_ls_set]="7001 B080 53C8 0002 7407"
# DBGE_NOT_TAKEN_N_EQ_V: set N==V so DBGE condition is true (no decrement/branch)
TESTS[dbge_not_taken_n_eq_v]="7001 7201 0C81 0000 0000 5CC8 0002 7407"
# DBLT_NOT_TAKEN_N_NE_V: set N!=V so DBLT condition is true (no decrement/branch)
TESTS[dblt_not_taken_n_ne_v]="7001 7201 0C81 0000 0002 5DC8 0002 7407"
# DBGT_NOT_TAKEN_GT_SET: set Z=0,N==V so DBGT condition is true (no decrement/branch)
TESTS[dbgt_not_taken_gt_set]="7001 7201 0C81 0000 0000 5EC8 0002 7407"
# DBLE_NOT_TAKEN_LE_SET: set Z=1 so DBLE condition is true (no decrement/branch)
TESTS[dble_not_taken_le_set]="7001 B080 5FC8 0002 7407"
# DBHI_FALSE_DEC_TERMINAL_LS_SET: set LS=true so DBHI is false; D0=0 forces one decrement-to-terminal path
TESTS[dbhi_false_dec_terminal_ls_set]="7000 B080 52C8 0002 7407"
# DBLS_FALSE_DEC_TERMINAL_HI_SET: set HI=true so DBLS is false; D0=0 forces one decrement-to-terminal path
TESTS[dbls_false_dec_terminal_hi_set]="7000 7201 0C81 0000 0000 53C8 0002 7407"
# DBGE_FALSE_DEC_TERMINAL_N_NE_V: set N!=V so DBGE is false; D0=0 forces one decrement-to-terminal path
TESTS[dbge_false_dec_terminal_n_ne_v]="7000 7201 0C81 0000 0002 5CC8 0002 7407"
# DBLT_FALSE_DEC_TERMINAL_N_EQ_V: set N==V so DBLT is false; D0=0 forces one decrement-to-terminal path
TESTS[dblt_false_dec_terminal_n_eq_v]="7000 7201 0C81 0000 0000 5DC8 0002 7407"
# DBGT_FALSE_DEC_TERMINAL_Z_SET: set Z=1 so DBGT is false; D0=0 forces one decrement-to-terminal path
TESTS[dbgt_false_dec_terminal_z_set]="7000 B080 5EC8 0002 7407"
# DBLE_FALSE_DEC_TERMINAL_GT_SET: set Z=0,N==V so DBLE is false; D0=0 forces one decrement-to-terminal path
TESTS[dble_false_dec_terminal_gt_set]="7000 7201 0C81 0000 0000 5FC8 0002 7407"
# DBCC_CCR_PRESERVE_BEQ_TAKEN: DBEQ (condition true) should not clobber Z; subsequent BEQ must remain taken
TESTS[dbcc_ccr_preserve_beq_taken]="7001 B080 57C8 0002 6702 7207 7408"
# DBRA's host-only terminal test must not replace a preceding architectural Z.
# Counter zero makes the temporary TST set Z while MOVEQ #9 left guest Z clear.
TESTS[dbra_ccr_preserve_z_clear]="7200 7009 51C9 0002 6602 7407 7608"
# Counter nonzero makes the temporary TST clear Z while MOVEQ #0 left guest Z set.
TESTS[dbra_ccr_preserve_z_set]="7201 7000 51C9 0002 6702 7407 7608"
# DBCC_CCR_PRESERVE_BNE_TAKEN: DBNE (condition true) should not clobber Z=0; subsequent BNE must remain taken
TESTS[dbcc_ccr_preserve_bne_taken]="7001 7201 0C81 0000 0002 56C8 0002 6602 7407 7608"
# DBCC_CCR_PRESERVE_BCS_TAKEN: DBCS (condition true) should not clobber C=1; subsequent BCS must remain taken
TESTS[dbcc_ccr_preserve_bcs_taken]="7001 7201 0C81 0000 0002 55C8 0002 6502 7407 7608"
# DBCC_CCR_PRESERVE_BVC_TAKEN: DBVC (condition true) should not clobber V=0; subsequent BVC must remain taken
TESTS[dbcc_ccr_preserve_bvc_taken]="7001 7201 0C81 0000 0000 58C8 0002 6802 7407 7608"
# DBCC_CCR_PRESERVE_BVS_TAKEN: DBVS (condition true) should not clobber V=1; subsequent BVS must remain taken
TESTS[dbcc_ccr_preserve_bvs_taken]="7001 243C 7FFF FFFF 5282 59C8 0002 6902 7407 7608"
# DBCC_CCR_PRESERVE_BHI_TAKEN: DBHI (condition true) should not clobber C/Z; subsequent BHI must remain taken
TESTS[dbcc_ccr_preserve_bhi_taken]="7001 7201 0C81 0000 0000 52C8 0002 6202 7407 7608"
# DBCC_CCR_PRESERVE_BLS_TAKEN: DBLS (condition true) should not clobber C/Z; subsequent BLS must remain taken
TESTS[dbcc_ccr_preserve_bls_taken]="7001 B080 53C8 0002 6302 7407 7608"
# DBCC_CCR_PRESERVE_BGE_TAKEN: DBGE (condition true) should not clobber N/V; subsequent BGE must remain taken
TESTS[dbcc_ccr_preserve_bge_taken]="7001 7201 0C81 0000 0000 5CC8 0002 6C02 7407 7608"
# DBCC_CCR_PRESERVE_BLT_TAKEN: DBLT (condition true) should not clobber N/V; subsequent BLT must remain taken
TESTS[dbcc_ccr_preserve_blt_taken]="7001 7201 0C81 0000 0002 5DC8 0002 6D02 7407 7608"
# DBCC_CCR_PRESERVE_BGT_TAKEN: DBGT (condition true) should not clobber Z/N/V; subsequent BGT must remain taken
TESTS[dbcc_ccr_preserve_bgt_taken]="7001 7201 0C81 0000 0000 5EC8 0002 6E02 7407 7608"
# DBCC_CCR_PRESERVE_BLE_TAKEN: DBLE (condition true) should not clobber Z/N/V; subsequent BLE must remain taken
TESTS[dbcc_ccr_preserve_ble_taken]="7001 B080 5FC8 0002 6F02 7407 7608"
# DBVC_LOOP_V_SET: force V=1; DBVC condition is false so bounded DBcc loop should execute twice for D0=1
TESTS[dbvc_loop_v_set]="7001 243C 7FFF FFFF 5282 4E71 58C8 FFFA"
# DBVS_LOOP_V_CLEAR: force V=0; DBVS condition is false so bounded DBcc loop should execute twice for D0=1
TESTS[dbvs_loop_v_clear]="7001 7400 4E71 59C8 FFFA"
# DBVC_NOT_TAKEN_V_CLEAR: V=0 makes DBVC condition true (no decrement/branch)
TESTS[dbvc_not_taken_v_clear]="7001 7400 58C8 0002 7207"
# DBVS_NOT_TAKEN_V_SET: V=1 makes DBVS condition true (no decrement/branch)
TESTS[dbvs_not_taken_v_set]="7001 243C 7FFF FFFF 5282 59C8 0002 7207"
# DBNE_LOOP_Z_SET: with Z=1, DBNE decrements and loops exactly twice for D0=1
TESTS[dbne_loop_z_set]="7001 B080 4E71 56C8 FFFA"
# DBEQ_LOOP_Z_CLEAR: with Z=0, DBEQ decrements and loops exactly twice for D0=1
TESTS[dbeq_loop_z_clear]="7001 0C80 0000 0002 4E71 57C8 FFFA"
# DBEQ_X_CLOBBER: DBcc must NOT touch the 68k X flag. ORI.B #0x10,CCR sets X=1;
# CMP.L D1,D0 (both 0) sets C=0,Z=1; DBEQ D5 sees Z=1 and exits, running the
# block-end save_and_discard path; ADDX.L D3,D2 consumes X so D2=1 iff X survived.
# Regression guard for f348dc9e (save_and_discard_flags_in_nzcv X-clobber).
TESTS[dbeq_x_clobber]="003C 0010 B081 57CD 0002 D583"
# MOVEQ_EDGES: verify MOVEQ sign-extension for -128 and positive edge 127
TESTS[moveq_edges]="7080 0C80 FFFF FF80 707F 0C80 0000 007F"
# ALU_NEGATIVE_ROUNDTRIP: D0=-1, add/sub 1 roundtrip should restore -1
TESTS[alu_negative_roundtrip]="70FF 7201 D081 9081 0C80 FFFF FFFF"
# IMM_LOGIC_WORD_HIGHBIT: ORI/EORI/ANDI.W around 0x8000 high-bit edge should normalize back to zero
TESTS[imm_logic_word_highbit]="7000 0040 8000 0A40 8000 0240 FFFF 0C40 0000"
# BRANCH_CHAIN_Z_CLEAR: BNE taken then BEQ not-taken under persistent Z=0
TESTS[branch_chain_z_clear]="7001 0C80 0000 0002 6602 7207 6702 7408"
# BRANCH_CHAIN_CARRY_SET: BCS taken then BCC not-taken while carry remains set
TESTS[branch_chain_carry_set]="7001 0C80 0000 0002 6502 7207 6402 7408"
# BRANCH_CHAIN_OVERFLOW_SET: BVS taken then BVC not-taken while overflow remains set
TESTS[branch_chain_overflow_set]="203C 7FFF FFFF 5280 6902 7207 6802 7408"
# SCC_CCR_PRESERVE_BVS_TAKEN: SVS should not clobber CCR; BVS must remain taken from prior overflow
TESTS[scc_ccr_preserve_bvs_taken]="203C 7FFF FFFF 5280 59C1 6902 7407 7608"
# DBRA_FOUR_ITER: D0 starts at 3; loop body ADDQ runs four times before fallthrough
TESTS[dbra_four_iter]="7003 7200 5281 51C8 FFFA"
# SCC_CCR_PRESERVE_BVC_TAKEN: SVC should not clobber CCR; BVC must remain taken when V=0
TESTS[scc_ccr_preserve_bvc_taken]="7001 58C1 6802 7407 7608"
# SCC_CCR_PRESERVE_BHI_TAKEN: SHI should not clobber CCR; BHI must remain taken when C=0,Z=0
TESTS[scc_ccr_preserve_bhi_taken]="7001 0C80 0000 0000 52C1 6202 7407 7608"
# SCC_CCR_PRESERVE_BLS_TAKEN: SLS should not clobber CCR; BLS must remain taken when Z=1
TESTS[scc_ccr_preserve_bls_taken]="7001 B080 53C1 6302 7407 7608"
# DBRA_FIVE_ITER: D0 starts at 4; loop body ADDQ runs five times before fallthrough
TESTS[dbra_five_iter]="7004 7200 5281 51C8 FFFA"
# BRANCH_CHAIN_EQ_THEN_NE: BEQ taken then BNE not-taken under persistent Z=1
TESTS[branch_chain_eq_then_ne]="70FF 0C80 FFFF FFFF 6702 7207 6602 7408"
# BRANCH_CHAIN_CARRY_CLEAR: BCC taken then BCS not-taken while carry remains clear
TESTS[branch_chain_carry_clear]="7001 0C80 0000 0000 6402 7207 6502 7408"
# IMM_LOGIC_LONG_HIGHBIT: ORI/EORI/ANDI.L around 0x80000000 high-bit edge should normalize back to zero
TESTS[imm_logic_long_highbit]="7000 0080 8000 0000 0A80 8000 0000 0280 FFFF FFFF 0C80 0000 0000"
# DBRA_SIX_ITER: D0 starts at 5; loop body ADDQ runs six times before fallthrough
TESTS[dbra_six_iter]="7005 7200 5281 51C8 FFFA"
# NOT_SIZES: verify NOT.B/W/L transitions on D0 across byte/word/long domains
TESTS[not_sizes]="7000 4600 0C80 0000 00FF 4640 0C80 0000 FF00 4680 0C80 FFFF 00FF"
# NOT_WORD_PRESERVE_UPPER: NOT.W should affect only low word and preserve upper 16 bits
TESTS[not_word_preserve_upper]="203C 1234 5678 4640 0C80 1234 A987"
# NOT_BYTE_PRESERVE_UPPER: NOT.B should affect only low byte and preserve upper 24 bits
TESTS[not_byte_preserve_upper]="203C 1234 5678 4600 0C80 1234 5687"
# SCC_CCR_PRESERVE_BPL_TAKEN: SPL should not clobber CCR; BPL must remain taken when N=0
TESTS[scc_ccr_preserve_bpl_taken]="7001 5AC1 6A02 7407 7608"
# SCC_CCR_PRESERVE_BMI_TAKEN: SMI should not clobber CCR; BMI must remain taken when N=1
TESTS[scc_ccr_preserve_bmi_taken]="70FF 5BC1 6B02 7407 7608"
# SCC_CCR_PRESERVE_BGE_TAKEN: SGE should not clobber CCR; BGE must remain taken when N==V
TESTS[scc_ccr_preserve_bge_taken]="7001 5CC1 6C02 7407 7608"
# SCC_CCR_PRESERVE_BGT_TAKEN: SGT should not clobber CCR; BGT must remain taken when Z=0 and N==V
TESTS[scc_ccr_preserve_bgt_taken]="7001 5EC1 6E02 7407 7608"
# SCC_CCR_PRESERVE_BLE_TAKEN: SLE should not clobber CCR; BLE must remain taken when Z=1
TESTS[scc_ccr_preserve_ble_taken]="7001 B080 5FC1 6F02 7407 7608"
# --- Multi-block and ROM-like pattern vectors ---
# DBNE_LOOP_CMPI: DBNE with CMPI condition, exits when D1==3
TESTS[dbne_loop_cmpi]="7005 7200 5281 0C81 0000 0003 56C8 FFF6"
# BSR_IN_DBRA_LOOP: BSR to subroutine inside DBRA loop, 4 iterations
TESTS[bsr_in_dbra_loop]="7003 7200 6108 51C8 FFFC 6006 4E71 5281 4E75"
# TABLE_LOOKUP: PC-relative table read via scaled index
TESTS[table_lookup]="41F9 0000 9000 20BC 1111 1111 217C 2222 2222 0004 217C 3333 3333 0008 7202 E589 2430 1800"
# DBRA_LOOP_1000: 1000-iteration loop
TESTS[dbra_loop_1000]="203C 0000 03E7 7200 5281 51C8 FFFC"
# SWAP_PACK: pack two words into a long via SWAP+MOVE.W+SWAP
TESTS[swap_pack]="203C 0000 AABB 4840 303C CCDD 4840"
# LEA_SCALED_INDEX: LEA (0,A0,D1.L*4) scaled indexed addressing
TESTS[lea_scaled_index]="41F9 0000 7000 7203 43F0 1C00 2009"
# MULTI_BRANCH: sequential BEQ+BNE with flag propagation
TESTS[multi_branch]="7005 0C80 0000 0005 6702 72FF 7403 6602 76FF"
# ANDI_L_DN: AND.L immediate with register
TESTS[andi_l_dn]="203C DEAD BEEF 0280 FF00 FF00"
# EOR_SELF: EOR.L Dn,Dn (self-XOR = clear, Z=1)
TESTS[eor_self]="203C DEAD BEEF B180"
TESTS[asl_w_vflag]="203C 0000 6000 E540"
TESTS[asl_b_overflow]="203C 0000 0060 E700"
TESTS[lsr_w_regcount]="203C FFFF 8001 720F E368"
TESTS[asr_w_preserve]="203C FFFF 8000 E240"
TESTS[movem_w_signext]="41F9 0000 A000 30FC FF80 317C 0042 0002 41F9 0000 A000 4C98 0003"
TESTS[cmpm_l_equal]="41F9 0000 B000 43F9 0000 B010 20BC DEAD BEEF 22BC DEAD BEEF 45F9 0000 B000 47F9 0000 B010 B78A"
TESTS[cmpm_b_unequal]="41F9 0000 C000 43F9 0000 C010 10FC 00AA 12FC 00BB 45F9 0000 C000 47F9 0000 C010 B70A"
TESTS[addx_64bit]="70FF 72FF 7401 7600 D482 D383"
TESTS[subx_64bit]="203C 0000 0000 223C 0000 0001 7401 7600 9482 9383"
TESTS[muls_boundary]="203C 0000 8000 223C 0000 8000 C1C1"
TESTS[divu_max_quotient]="203C 0000 FFFE 7202 80C1"
TESTS[move_b_preserve_flags]="203C AABB CCDD 103C 0011 4A00"
TESTS[byte_logic_chain]="203C AABB CCDD 0000 000F 0200 00F0 0A00 00FF"
TESTS[bchg_imm_high]="4280 0840 001F"
TESTS[neg_w_partial]="203C AABB 0005 4440"
TESTS[clr_b_tst]="203C DEAD BEEF 4200 4A00"
TESTS[all_regs_alive]="7001 7202 7403 7604 7805 7A06 7C07 7E08 41F9 0000 0100 43F9 0000 0200 45F9 0000 0300 47F9 0000 0400 49F9 0000 0500 4BF9 0000 0600 D081"
TESTS[scaled_index_word]="41F9 0000 D000 20BC 1111 1111 217C 2222 2222 0004 217C 3333 3333 0008 7202 2430 1200"
TESTS[byte_indexed_load]="41F9 0000 E000 10FC 00AA 117C 00BB 0001 117C 00CC 0002 117C 00DD 0003 7203 1030 1800"
TESTS[indexed_store_load]="41F9 0000 E100 7042 7204 2180 1800 4280 2430 1800"
TESTS[addq_subq_sizes]="203C AABB CCDD 5600 5340 5E80"
TESTS[x_flag_chain]="70FF 0680 0000 0001 7200 D181 E391"
TESTS[sub_w_subx_chain]="7001 7200 7402 7600 9442 9381"
TESTS[exg_dn_an]="7011 41F9 0000 2222 C148"
TESTS[push_pop_a0]="41F9 0000 F100 70FF 2100 4280 2218"
TESTS[dbeq_loop_50]="7031 7200 5281 0C81 0000 001E 57C8 FFF6"
TESTS[dbmi_loop_neg]="700A 223C 0000 5000 0441 2000 5BC8 FFF8"
TESTS[lsl_l_count0]="203C DEAD BEEF E188"
TESTS[asr_l_8_neg]="203C 8000 0001 E080"
TESTS[rol_l_16]="203C AABB CCDD 7210 E3B8"
TESTS[lsl_b_7]="203C FF00 FF01 EF00"
TESTS[asr_b_1_sign]="203C 0000 0080 E200"
TESTS[move_b_flags]="203C AABB CC80 1200"
TESTS[move_w_zero]="203C DEAD BEEF 303C 0000"
TESTS[add_l_an_dn]="41F9 0000 A000 20BC 0000 0005 7003 D090"
TESTS[sub_w_dn_an]="41F9 0000 A100 30FC 0010 7005 9150 3010"
TESTS[cmp_b]="203C 0000 00FF 223C 0000 0001 B001"
TESTS[cmp_w]="203C 0000 8000 223C 0000 7FFF B041"
TESTS[ori_w_mem]="41F9 0000 A200 30FC 0F0F 0050 F0F0 3010"
TESTS[andi_b_mem]="41F9 0000 A300 10FC 00AB 0210 000F 1010"
TESTS[link_neg16]="41F9 0000 B000 2E48 4E55 FFF0 7042 2B40 FFF4 4280 222D FFF4 4E5D"
TESTS[mulu_max]="203C 0000 FFFF 223C 0000 FFFF C0C1"
TESTS[divs_neg_rem]="203C FFFF FFF9 7202 81C1"
TESTS[negx_64bit]="7000 7201 4480 4081"
TESTS[cmpi_l_abs_short_eq]="41F9 0000 0DB0 20BC 5A93 2BC7 0CB8 5A93 2BC7 0DB0"
TESTS[cmpi_l_abs_short_ne]="41F9 0000 0DB0 20BC DEAD BEEF 0CB8 5A93 2BC7 0DB0"
TESTS[cmpi_bne_w_not_taken]="41F9 0000 0DB0 20BC 5A93 2BC7 0CB8 5A93 2BC7 0DB0 6600 0004 7277"
TESTS[cmpi_bne_w_taken]="41F9 0000 0DB0 20BC DEAD BEEF 0CB8 5A93 2BC7 0DB0 6600 0004 7277"
TESTS[cmpi_b_abs_short_blt]="41F9 0000 012F 10FC 0003 0C38 0004 012F 6D02 72FF"
TESTS[movem_save_modify_restore]="7042 7201 7402 7603 7804 7A05 41F9 0000 0100 43F9 0000 0200 45F9 0000 0300 47F9 0000 0400 49F9 0000 0500 4BF9 0000 0600 48F8 3FFF 0C30 70FF 4CF8 3FFF 0C30"
TESTS[bsr_l_long]="61FF 0000 0008 7222 6004 7055 4E75"
TESTS[jmp_d8_pc_dn_w]="7004 4EFB 0002 70FF 70FE 7242"
TESTS[pea_movem_stack]="41F9 0000 E000 2E48 7001 7202 7403 7604 4879 0000 C000 48E7 F000 7000 7200 7400 7600 4CDF 000F 205F"
TESTS[subq_sp_movea_write]="41F9 0000 E000 2E48 554F 204F 30BC 1234 3017"
TESTS[tst_bne_after_bsr_rts]="6108 4A40 6602 7277 6004 7000 4E75"
TESTS[tst_bne_after_jsr_an]="43FA 000C 4E91 4A40 6602 7277 6004 7000 4E75"
TESTS[save_clear_slot_restore_tst]="700C 48F8 0001 0C30 42B8 0C30 4CF8 0001 0C30 4A40"
TESTS[movec_cacr_roundtrip]="9080 08C0 001F 4E7B 0002 4E7A 0002 0800 001F"
TESTS[cache_init_sequence]="9080 08C0 001F 4E7B 0002 4E7A 0002 0800 001F F4D8 9080 4E7B 0002 4E7B 0003 203C 807F C040 4E7B 0006 203C 500F C040 4E7B 0007"
TESTS[move_l_neg_disp_a5]="4BF9 0000 F000 203C DEAD BEEF 2B40 FF40 2238 EF40"
TESTS[sr_barrier_cache_init]="46FC 2700 9080 08C0 001F 4E7B 0002 4E7A 0002 0800 001F"
TESTS[divs_word_hardfail]="203C 0000 002A 223C 0000 0005 81C1"
TESTS[divu_word_hardfail]="203C 0000 002A 223C 0000 0005 80C1"
TESTS[mull_32_hardfail]="203C 0000 0064 223C 0000 0003 4C01 0000"
TESTS[divl_32_hardfail]="203C 0000 012C 223C 0000 000A 4C41 0000"
TESTS[aslw_mem_hardfail]="41F9 0000 A000 30FC 4000 E1D0 3010"
TESTS[lsrw_mem_hardfail]="41F9 0000 A000 30FC 8001 E2D0 3010"
TESTS[rolw_mem_hardfail]="41F9 0000 A000 30FC 8001 E7D0 3010"
TESTS[ori_sr_hardfail]="007C 0700"
TESTS[andi_sr_hardfail]="027C 27FF"
TESTS[eori_sr_hardfail]="0A7C 0010"
TESTS[move_from_sr_hardfail]="40C0"
TESTS[move_to_sr_hardfail]="46FC 2500 40C0"
TESTS[divs_neg_by_neg_edge]="203C FFFF FFF1 72FD 81C1"
TESTS[divs_by_minus_one_edge]="203C FFFF FFFE 72FF 81C1"
TESTS[divs_zero_dividend_edge]="7000 7205 81C1"
TESTS[divs_overflow_edge]="203C 0001 0000 7201 81C1"
TESTS[divu_exact_edge]="203C 0000 000C 7203 80C1"
TESTS[divu_with_remainder_edge]="203C 0000 000D 7205 80C1"
TESTS[divu_overflow_edge]="203C 0001 0000 7201 80C1"
TESTS[mull_unsigned_32]="203C 0001 0000 223C 0001 0000 4C01 0000"
TESTS[mull_signed_32]="203C FFFF FFFF 223C 0000 0002 4C01 0800"
TESTS[divl_unsigned_32]="203C 0000 012C 223C 0000 000A 4C41 0000"
TESTS[divl_signed_32]="203C FFFF FFF6 223C 0000 0003 4C41 0800"
TESTS[asrw_mem_edge]="41F9 0000 A000 30FC 8001 E0D0 3010"
TESTS[roxlw_mem_edge]="41F9 0000 A000 30FC 0001 003C 0010 E5D0 3010"
TESTS[roxrw_mem_edge]="41F9 0000 A000 30FC 8000 003C 0010 E4D0 3010"
TESTS[abcd_99_plus_01_edge]="7000 0000 0099 7201 C101"
TESTS[sbcd_with_x_edge]="003C 0010 7000 7201 8101"
TESTS[nbcd_99_edge]="7000 0000 0099 4800"
TESTS[bfextu_reg_edge]="203C ABCD EF01 E9C0 0200"
TESTS[bfexts_reg_edge]="203C ABCD EF01 EBC0 0200"
TESTS[bfffo_reg_edge]="203C 0000 0100 EDC0 0200"
TESTS[bfset_reg_edge]="203C FF00 00FF EEC0 0208"
TESTS[bfclr_reg_edge]="203C FFFF FFFF ECC0 0208"
TESTS[bfchg_reg_edge]="203C FF00 FF00 EAC0 0208"
TESTS[bftst_reg_edge]="203C 8000 0000 E8C0 0008"
TESTS[bfins_reg_edge]="7042 203C FFFF 0000 EFC0 0200"
# All eight bitfield operations share one runtime transaction and raw 32-bit EA contract.
TESTS[bitfield_mem_an_family]="41F9 0000 9100 20BC 89AB CDEF E8D0 0008 E9D0 1008 EAD0 0008 EBD0 2008 ECD0 0008 EDD0 3008 EED0 0008 283C 0000 005A EFD0 4008 2410"
TESTS[bitfield_d16_an]="41F9 0000 9100 217C 8000 0000 0002 E8E8 0008 0002 2428 0002"
TESTS[bitfield_indexed_an]="7000 41F9 0000 9100 20BC 8000 0000 E8F0 0008 0000 2410"
TESTS[bitfield_absw]="41F8 1100 20BC 8000 0000 E8F8 0008 1100 2410"
TESTS[bitfield_absl]="41F9 0000 9100 20BC 8000 0000 E8F9 0008 0000 9100 2410"
# Read-only PC-relative forms branch over their inline field data after the test.
TESTS[bitfield_pc_d16]="E8FA 0008 0004 6004 8000 0000"
TESTS[bitfield_pc_indexed]="7000 E8FB 0008 0004 6004 8000 0000"
TESTS[pack_dn_edge]="203C 0000 1234 8140 0000"
# PACK -(A7),-(A7) exercises A7's two-byte byte-step, source/destination
# register aliasing, independent source reads, and ordered dual writeback.
TESTS[pack_predec_a7_alias]="207C 0000 9204 20BC 1200 3400 2E7C 0000 9208 8F4F 0000 7000 1017"
TESTS[unpk_dn_edge]="203C 0000 0012 8180 0000"
# UNPK -(A7),-(A7) has a two-byte source decrement and an additional
# two-byte destination decrement when both encoded operands alias A7.
TESTS[unpk_predec_a7_alias]="207C 0000 9306 20BC 1200 0000 2E7C 0000 9308 8F8F 0000 7000 3017"
# CHK2.W equality sets Z, clears C, and must preserve the seeded X/N/V bits.
TESTS[chk2_w_equal_preserve_ccr]="207C 0000 9400 20BC FFF6 000A 700A 44FC 001A 02D0 0000 40C1"
# CHK2.B with an address-register selector must compare all 32 bits, while the
# adjacent byte bounds are sign-extended; d16 also checks EA extension order.
TESTS[chk2_b_areg_fullwidth_d16]="247C 0000 9504 34BC 807F 207C 0000 9500 227C 1000 0050 44FC 001A 00E8 9000 0004 40C2"
# Reversed long bounds use CHK2's wrapped-range rule; equality with the lower
# bound deliberately leaves both Z and C set. Absolute-long covers a distinct EA.
TESTS[chk2_l_wrapped_absl]="207C 0000 9600 20FC 0000 0064 20BC FFFF FF9C 7064 44FC 001A 04F9 0000 0000 9600 40C1"
# Install a local vector-6 handler, request CHK2 trapping, and make the handler
# the sole path that sets D7=$66 before joining the harness sentinel.
TESTS[chk2_w_trap_vector6]="7000 4E7B 0801 23FC 0000 102A 0000 0018 207C 0000 9700 20BC 0000 000A 7014 44FC 001A 02D0 0800 60FE 4E71 7E66"
# Brief indexed CHK2.W reaches an interior value and clears Z/C while
# preserving seeded X/N/V; D1.W participates in effective-address formation.
TESTS[chk2_w_indexed_inrange]="207C 0000 9900 20BC FFF6 000A 207C 0000 98F0 223C 0000 0010 7005 44FC 001A 02F0 0000 1000 40C2"
# Full-format indexed CHK2.L uses a signed word base displacement before the
# two ordered long bound reads; -50 lies strictly inside [-100,100].
TESTS[chk2_l_fullindexed_inrange]="207C 0000 9A00 20FC FFFF FF9C 20BC 0000 0064 207C 0000 9A10 7200 203C FFFF FFCE 44FC 001A 04F0 0000 1920 FFF0 40C2"
# PC-relative CHK2.W resolves its d16 base from opcode+4, reads inline bounds,
# and rejoins before a branch skips the embedded data.
TESTS[chk2_w_pcrel_inrange]="7005 44FC 001A 02FA 0000 000A 40C1 6008 4E71 4E71 FFF6 000A"
# Exercise both MOVEP directions and sizes from a negative displacement. The
# word read must preserve D5's upper half; the long read must replace all D7;
# byte reads retain an independent check of the four interleaved write lanes.
TESTS[movep_l_roundtrip]="41F9 0000 9104 203C 1234 5678 01C8 FFFC 2A3C AAAA 5555 0B08 FFFC 7E00 0F48 FFFC 1228 FFFC 1428 FFFE 1610 1828 0002"
TESTS[sr_ops_combo]="46FC 2700 007C 0010 027C F7FF 0A7C 0004 40C0"
TESTS[moves_write_read]="41F9 0000 A000 203C DEAD BEEF 0E90 0800 2010"
# MOVES snapshots register sources before auto-update; successful reads update
# An before an aliased address-register destination, which therefore wins.
TESTS[moves_predec_store_alias]="41F9 0000 9801 0E20 8800 1210"
TESTS[moves_predec_read_alias]="41F9 0000 9804 317C 8001 FFFE 0E60 8000"
TESTS[moves_l_indexed_store]="7000 41F9 0000 9800 203C DEAF BEEF 0EB0 0800 0000 2410"
# MOVES.B (A0)+,A0 reads before postincrement and then lets the aliased
# address-register destination win; byte loads into An are sign-extended.
TESTS[moves_b_postinc_areg_alias]="207C 0000 9800 10BC 0080 0E18 8000 2008"
# MOVES must privilege-trap before consuming the extension or touching memory.
# Vector 8 is the sole route from the MOVES instruction to D7=$68 and sentinel;
# IPL7 masks asynchronous guest interrupts throughout the user-mode window.
TESTS[moves_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 0E90 0800 60FE 4E71 7E68"
# FDBF decrements only D0.W, preserves its upper word, and branches relative
# to the displacement-word PC while the postdecrement value is not -1.
TESTS[fdbcc_false_decrement_branch]="203C 1234 0001 F248 0000 0008 7201 6004 7202"
# FTRAPT without an optional operand must deliver vector 7 with the opcode PC;
# the installed handler is the sole route past the local spin to D7=$67.
TESTS[ftrapcc_true_vector7]="7000 4E7B 0801 23FC 0000 1018 0000 001C F27C 000F 60FE 4E71 7E67"
# False FTRAPcc.W/L forms still fetch and skip their optional word/long
# operands before execution continues at the exact architectural successor.
TESTS[ftrapcc_false_operand_lengths]="F27A 0000 DEAD F27B 0000 DEAD BEEF 7005"
# General FPP execution consumes its extension word and performs the canonical
# arithmetic service before control resumes at the exact successor.
TESTS[fpp_semantic_successor]="7001 F200 0000 7005"
# FSF writes a false condition byte through the canonical FPU condition path
# while preserving the upper 24 bits of the destination data register.
TESTS[fscc_false_byte]="70FF F240 0000"
# False FBcc.W/L forms consume their signed displacement widths and rejoin at
# the exact successor without allowing either embedded value to become code.
TESTS[fbcc_false_operand_lengths]="F280 DEAD F2C0 DEAD BEEF 7005"
# CAS2.W/L semantic boundary: successful dual commit, first/second compare
# failures, partial-word compare-register updates, and aliased compare fields.
# Extension words encode Rn1/Du1/Dc1 then Rn2/Du2/Dc2.
# CAS owns extension fetch, EA updates, compare-register failure updates and
# successor-PC writes as one transaction. Predecrement commits after the read.
TESTS[cas_b_success]="41F9 0000 A200 10BC 00AA 203C 1234 56AA 223C 8765 4355 0AD0 0040 1410"
TESTS[cas_b_fail]="41F9 0000 A200 10BC 00AA 203C 1234 56BB 223C 8765 4355 0AD0 0040 1410"
TESTS[cas_b_predec]="43F9 0000 A200 12BC 00AA 5289 203C 0000 00AA 223C 0000 0055 0AE1 0040 1411"
TESTS[cas_w_postinc]="41F9 0000 A200 30BC 1234 203C AAAA 1234 223C BBBB 5678 0CD8 0040 3428 FFFE"
TESTS[cas_l_d16]="41F9 0000 A200 217C 1122 3344 0004 203C 1122 3344 223C 5566 7788 0EE8 0040 0004 2428 0004"
TESTS[cas2_w_success]="207C 0000 A100 227C 0000 A104 20BC 1111 AAAA 22BC 2222 BBBB 203C CAFE 1111 223C BABE 2222 243C 0000 3333 263C 0000 4444 0CFC 8080 90C1 2810 2A11"
TESTS[cas2_w_fail_first]="207C 0000 A100 227C 0000 A104 20BC 1111 AAAA 22BC 2222 BBBB 203C CAFE 9999 223C DEAD 7777 243C 0000 3333 263C 0000 4444 0CFC 8080 90C1 2810 2A11"
TESTS[cas2_w_fail_second]="207C 0000 A100 227C 0000 A104 20BC 1111 AAAA 22BC 2222 BBBB 203C CAFE 1111 223C DEAD 7777 243C 0000 3333 263C 0000 4444 0CFC 8080 90C1 2810 2A11"
TESTS[cas2_l_success]="207C 0000 A100 227C 0000 A104 20BC 1111 2222 22BC 3333 4444 203C 1111 2222 223C 3333 4444 243C 5555 6666 263C 7777 8888 0EFC 8080 90C1 2810 2A11"
TESTS[cas2_l_fail_second]="207C 0000 A100 227C 0000 A104 20BC 1111 2222 22BC 3333 4444 203C 1111 2222 223C 9999 AAAA 243C 5555 6666 263C 7777 8888 0EFC 8080 90C1 2810 2A11"
TESTS[cas2_l_alias_compare]="207C 0000 A100 227C 0000 A104 20BC 1111 2222 22BC 3333 4444 203C 1111 2222 223C 5555 6666 243C 7777 8888 0EFC 8040 9080 2810 2A11"
TESTS[adda_w_cov]="41F9 0000 1000 D0FC 0500"
TESTS[adda_l_cov]="41F9 0000 1000 D1FC 0000 0500"
TESTS[adda_w_neg_cov]="41F9 0000 1000 D0FC FF00"
TESTS[eori_ccr_cov]="003C 001F 0A3C 0010"
TESTS[rtr_cov]="41F9 0000 E000 2E48 610C 40C1 6008 4E71 4E71 4E71 3F3C 0010 4E77"
TESTS[mvr2usp_cov]="41F9 0000 1234 4E60 4E69 2009"
TESTS[move_b_d16_an_cov]="41F9 0000 A000 117C 0042 0010 1028 0010"
TESTS[move_w_d16_an_cov]="41F9 0000 A000 317C 1234 0010 3028 0010"
TESTS[move_l_d16_an_cov]="41F9 0000 A000 217C DEAD BEEF 0010 2028 0010"
# MOVE.L (d8,A0,D1.L),(abs.w): prove the generated indexed source and shared
# long read/write primitives natively, without the former runtime override.
TESTS[move_l_idx_absw_native]="207C 0000 9000 223C 0000 0004 217C DEAD BEEF 0004 21F0 1800 A000 2438 A000"
TESTS[move_b_idx_cov]="41F9 0000 A000 117C 0042 0004 7204 1030 1000"
TESTS[move_l_idx_scale_cov]="41F9 0000 A000 217C DEAD BEEF 0008 7202 2030 1400"
TESTS[move_l_pc_rel_cov]="203A 0002 4E71 4E71"
TESTS[move_l_abs_w_cov]="21FC CAFE BABE 0A00 2038 0A00"
TESTS[move_l_abs_l_cov]="23FC DEAD BEEF 0000 A100 2039 0000 A100"
TESTS[predec_postinc_cov]="41F9 0000 A010 3F3C 1234 3F3C 5678 43F9 0000 A00C 3219 3419"
TESTS[imm_to_mem_b_cov]="41F9 0000 A000 10FC 00AB 1010"
TESTS[imm_to_mem_w_cov]="41F9 0000 A000 30FC CAFE 3010"
TESTS[imm_to_mem_l_cov]="41F9 0000 A000 20BC DEAD BEEF 2010"
TESTS[add_b_overflow_cov]="103C 007F 0600 0001"
TESTS[sub_w_borrow_cov]="303C 0000 0440 0001"
TESTS[cmp_l_equal_cov]="203C 1234 5678 0C80 1234 5678"
TESTS[and_l_zero_cov]="203C FFFF FFFF 0280 0000 0000"
TESTS[or_l_allones_cov]="7000 0080 FFFF FFFF"
TESTS[eor_self_cov]="203C ABCD EF01 B180"
TESTS[neg_b_overflow_cov]="103C 0080 4400"
TESTS[not_b_cov]="103C 00AA 4600"
TESTS[odd_addr_cov]="41F9 0000 A001 20BC CAFE BABE 41F9 0000 A001 2010"
TESTS[a7_byte_postinc_cov]="41F9 0000 E000 2E48 3F3C ABCD 101F"

# --- ADDITIONAL OPCODE COVERAGE VECTORS ---
# CHK.W: check register against upper bound (in-range = no trap)
# MOVEQ #10,D0; MOVEQ #20,D1; CHK.W D1,D0
TESTS[chk_w_in_range]="7008 7214 4181"
# CHK.W zero: D0=0 against D1=100
TESTS[chk_w_zero]="7000 7264 4181"
# CHK.W equal: D0=D1=50
TESTS[chk_w_equal]="7032 7232 4181"
# CHK.W negative trap: vector 6 copies the stacked SR, frame PC, and format-2
# instruction address to D6/D4/D5. N starts clear and must be set before the
# frame is built; both frame addresses must identify the CHK opcode at $1018.
TESTS[chk_w_negative_trap_n]="7000 4E7B 0801 23FC 0000 101E 0000 0018 70FF 7214 44FC 0015 4181 60FE 4E71 3C17 282F 0002 2A2F 0008 7E66"
# CHK.W upper-bound trap: seed X/N/Z/C, exceed the bound by one, and require
# the frame to clear only N and identify the CHK opcode at $1018.
TESTS[chk_w_upper_trap_n_clear]="7000 4E7B 0801 23FC 0000 101E 0000 0018 7015 7214 44FC 001D 4181 60FE 4E71 3C17 282F 0002 2A2F 0008 7E66"
# CHK.L negative trap: a full-width negative D0 must take vector 6, publish N,
# preserve X/Z/C, and identify the CHK opcode at $1018 in both frame fields.
TESTS[chk_l_negative_trap_n]="7000 4E7B 0801 23FC 0000 101E 0000 0018 70FF 7214 44FC 0015 4101 60FE 4E71 3C17 282F 0002 2A2F 0008 7E66"
# CHK.L upper-bound trap: $00010000 exceeds $0000ffff only in a full 32-bit
# comparison. The frame must clear only N and identify the opcode at $1020.
TESTS[chk_l_upper_trap_n_clear]="7000 4E7B 0801 23FC 0000 1026 0000 0018 203C 0001 0000 223C 0000 FFFF 44FC 001D 4101 60FE 4E71 3C17 282F 0002 2A2F 0008 7E66"
# CHK.L non-trap: compare full-width positive values and snapshot the seeded
# X/N/Z/C state after CHK to prove that the in-range path changes no flags.
TESTS[chk_l_in_range_preserve_ccr]="203C 0001 0000 223C 0002 0000 44FC 001D 4101 40C6"

# DIVU.W divide-by-zero: vector 5 copies stacked SR, frame PC, and format-2
# instruction address to D6/D4/D5. The interpreter clears only V before entry;
# the frame PC is the successor at $101e and the instruction address is $101c.
TESTS[divu_w_zero_frame]="7000 4E7B 0801 23FC 0000 1022 0000 0014 203C 1234 5678 7200 44FC 001F 80C1 60FE 4E71 3C17 282F 0002 2A2F 0008 7E65"
EXPECTED_REG_FIELDS[divu_w_zero_frame]="D0=12345678 D4=0000101e D5=0000101c D6=0000271d"
# DIVS.W zero: preserve X/N/Z/C, clear V, retain D0, and publish the
# successor/opcode pair in the vector-5 format-2 frame.
TESTS[divs_w_zero_frame]="7000 4E7B 0801 23FC 0000 1022 0000 0014 203C 8765 4321 7200 44FC 001F 81C1 60FE 4E71 3C17 282F 0002 2A2F 0008 7E66"
EXPECTED_REG_FIELDS[divs_w_zero_frame]="D0=87654321 D4=0000101e D5=0000101c D6=0000271d"
# Signed word overflow must preserve incoming Z even though its ARM64 fit test
# uses ANDS/CMP, while publishing N/V and clearing C.
TESTS[divs_w_overflow_preserve_z]="203C 0001 0000 7201 44FC 0015 81C1 40C6"
EXPECTED_REG_FIELDS[divs_w_overflow_preserve_z]="D0=00010000 D6=0000271e"
TESTS[divs_w_imm_overflow_preserve_z]="203C 0001 0000 44FC 0015 81FC 0001 40C6"
EXPECTED_REG_FIELDS[divs_w_imm_overflow_preserve_z]="D0=00010000 D6=0000271e"
# Unsigned DIVL zero: preserve the complete CCR and dividend registers; the
# stacked PC follows the four-byte opcode+extension while oldpc names opcode.
TESTS[divu_l_zero_frame]="7000 4E7B 0801 23FC 0000 1024 0000 0014 203C 1357 9BDF 7200 44FC 001F 4C41 0000 60FE 4E71 3C17 282F 0002 2A2F 0008 7E67"
EXPECTED_REG_FIELDS[divu_l_zero_frame]="D0=13579bdf D4=00001020 D5=0000101c D6=0000271f"
# Signed DIVL zero exercises the same four-byte frame/lifecycle contract via
# the distinct signed midfunc family.
TESTS[divs_l_zero_frame]="7000 4E7B 0801 23FC 0000 1024 0000 0014 203C 89AB CDEF 7200 44FC 001F 4C41 0800 60FE 4E71 3C17 282F 0002 2A2F 0008 7E68"
EXPECTED_REG_FIELDS[divs_l_zero_frame]="D0=89abcdef D4=00001020 D5=0000101c D6=0000271f"
# Unsigned 64/32 DIVL zero retains both dividend halves and observes the same
# precise frame contract through jnf_DIVLU64.
TESTS[divu_l64_zero_frame]="7000 4E7B 0801 23FC 0000 102A 0000 0014 243C 1357 9BDF 263C 2468 ACE0 7200 44FC 001F 4C41 2403 60FE 4E71 3C17 282F 0002 2A2F 0008 7E6B"
EXPECTED_REG_FIELDS[divu_l64_zero_frame]="D2=13579bdf D3=2468ace0 D4=00001026 D5=00001022 D6=0000271f"
# Signed 64/32 DIVL zero closes the separate jnf_DIVLS64 path.
TESTS[divs_l64_zero_frame]="7000 4E7B 0801 23FC 0000 102A 0000 0014 243C 89AB CDEF 263C FFFF FFFF 7200 44FC 001F 4C41 2C03 60FE 4E71 3C17 282F 0002 2A2F 0008 7E6C"
EXPECTED_REG_FIELDS[divs_l64_zero_frame]="D2=89abcdef D3=ffffffff D4=00001026 D5=00001022 D6=0000271f"
# When quotient and remainder name the same register, m68k_divl writes the
# remainder first and the quotient second. These native 64/32 paths must retain
# that architectural quotient rather than accidentally leaving the remainder.
TESTS[divu_l64_same_dq_dr]="203C 0000 0001 223C 0000 0002 44FC 001F 4C41 0400 40C6"
EXPECTED_REG_FIELDS[divu_l64_same_dq_dr]="D0=80000000 D6=00002718"
TESTS[divs_l64_same_dq_dr]="203C FFFF FFFF 223C 0000 0002 44FC 001F 4C41 0C00 40C6"
EXPECTED_REG_FIELDS[divs_l64_same_dq_dr]="D0=00000000 D6=00002714"
# MOVEQ overwrites NZVC before the block boundary, selecting the no-flags
# DIVL form while preserving an observable, deterministic final CCR.
TESTS[divu_l64_same_dq_dr_nf]="203C 0000 0001 223C 0000 0002 44FC 001F 4C41 0400 7E00 40C6"
EXPECTED_REG_FIELDS[divu_l64_same_dq_dr_nf]="D0=80000000 D6=00002714 D7=00000000"
TESTS[divs_l64_same_dq_dr_nf]="203C FFFF FFFF 223C 0000 0002 44FC 001F 4C41 0C00 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l64_same_dq_dr_nf]="D0=00000000 D6=00002714 D7=00000000"
# The only overflowing signed 32/32 quotient is INT32_MIN / -1. DIVL must set
# N/V, clear C, preserve X/Z, and leave both quotient and remainder registers
# untouched. The no-flags form remains observable through the unchanged D2.
TESTS[divs_l32_overflow]="203C 8000 0000 223C FFFF FFFF 243C 1234 5678 44FC 0015 4C41 0802 40C6"
EXPECTED_REG_FIELDS[divs_l32_overflow]="D0=80000000 D2=12345678 D6=0000271e"
TESTS[divs_l32_overflow_nf]="203C 8000 0000 223C FFFF FFFF 243C 1234 5678 44FC 0015 4C41 0802 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l32_overflow_nf]="D0=80000000 D2=12345678 D6=00002714 D7=00000000"
# Distinct-remainder divide-by-zero vectors expose pure-write allocation bugs:
# neither Dq nor Dr may change before the exact vector-5 format-2 frame.
TESTS[divu_l32_zero_distinct]="7000 4E7B 0801 23FC 0000 102A 0000 0014 203C 1357 9BDF 243C 2468 ACE0 7200 44FC 001F 4C41 0002 60FE 4E71 3C17 282F 0002 2A2F 0008 7E6D"
EXPECTED_REG_FIELDS[divu_l32_zero_distinct]="D0=13579bdf D2=2468ace0 D4=00001026 D5=00001022 D6=0000271f"
TESTS[divs_l32_zero_distinct]="7000 4E7B 0801 23FC 0000 102A 0000 0014 203C 89AB CDEF 243C 7654 3210 7200 44FC 001F 4C41 0802 60FE 4E71 3C17 282F 0002 2A2F 0008 7E6E"
EXPECTED_REG_FIELDS[divs_l32_zero_distinct]="D0=89abcdef D2=76543210 D4=00001026 D5=00001022 D6=0000271f"
# Successful no-flags DIVL still has observable quotient/remainder and alias
# ordering even though MOVEQ deliberately kills the instruction's NZVC result.
TESTS[divu_l32_success_nf]="203C 0000 0064 223C 0000 0007 243C A5A5 5A5A 44FC 0015 4C41 0002 7E00 40C6"
EXPECTED_REG_FIELDS[divu_l32_success_nf]="D0=0000000e D2=00000002 D6=00002714 D7=00000000"
TESTS[divs_l32_success_nf]="203C FFFF FF9C 223C 0000 0007 243C A5A5 5A5A 44FC 0015 4C41 0802 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l32_success_nf]="D0=fffffff2 D2=fffffffe D6=00002714 D7=00000000"
# Quotient/remainder aliasing must retain the quotient, while a source/Dr alias
# must consume the divisor before the ordered remainder write.
TESTS[divu_l32_same_dq_dr_nf]="203C 0000 0064 223C 0000 0007 44FC 0015 4C41 0000 7E00 40C6"
EXPECTED_REG_FIELDS[divu_l32_same_dq_dr_nf]="D0=0000000e D6=00002714 D7=00000000"
TESTS[divs_l32_same_dq_dr_nf]="203C FFFF FF9C 223C 0000 0007 44FC 0015 4C41 0800 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l32_same_dq_dr_nf]="D0=fffffff2 D6=00002714 D7=00000000"
TESTS[divu_l32_src_dr_alias_nf]="203C 0000 0064 243C 0000 0007 44FC 0015 4C42 0002 7E00 40C6"
EXPECTED_REG_FIELDS[divu_l32_src_dr_alias_nf]="D0=0000000e D2=00000002 D6=00002714 D7=00000000"
TESTS[divs_l32_src_dr_alias_nf]="203C FFFF FF9C 243C 0000 0007 44FC 0015 4C42 0802 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l32_src_dr_alias_nf]="D0=fffffff2 D2=fffffffe D6=00002714 D7=00000000"
# 64/32 overflow leaves both halves untouched. Live forms prove N/V/C/Z/X;
# no-flags forms prove that the result path skips both architectural stores.
TESTS[divu_l64_overflow]="203C 0000 0000 223C 0000 0001 243C 0000 0001 44FC 0015 4C41 0402 40C6"
EXPECTED_REG_FIELDS[divu_l64_overflow]="D0=00000000 D2=00000001 D6=0000271e"
TESTS[divu_l64_overflow_nf]="203C 0000 0000 223C 0000 0001 243C 0000 0001 44FC 0015 4C41 0402 7E00 40C6"
EXPECTED_REG_FIELDS[divu_l64_overflow_nf]="D0=00000000 D2=00000001 D6=00002714 D7=00000000"
TESTS[divs_l64_overflow]="203C 8000 0000 223C 0000 0001 243C 0000 0000 44FC 0015 4C41 0C02 40C6"
EXPECTED_REG_FIELDS[divs_l64_overflow]="D0=80000000 D2=00000000 D6=0000271e"
TESTS[divs_l64_overflow_nf]="203C 8000 0000 223C 0000 0001 243C 0000 0000 44FC 0015 4C41 0C02 7E00 40C6"
EXPECTED_REG_FIELDS[divs_l64_overflow_nf]="D0=80000000 D2=00000000 D6=00002714 D7=00000000"
# Register-count shifts use the low six count bits. Counts at and above the
# operand width saturate ASR and zero logical shifts; they must not wrap modulo
# the host W-form variable-shift width.
TESTS[asl_b_reg_count32_boundary]="203C A5A5 0081 7220 44FC 0015 E320 40C6"
TESTS[asl_w_reg_count32_boundary]="203C A5A5 8001 7220 44FC 0015 E360 40C6"
TESTS[asl_l_reg_count32_boundary]="203C 8000 0001 7220 44FC 0015 E3A0 40C6"
TESTS[asl_l_reg_zero_count32_v_clear]="203C 0000 0000 7220 44FC 0015 E3A0 40C6"
# Replay the complete generated block with an in-block constant producer.  This
# guards the generated path if constant propagation reaches the register helper;
# the structural audit separately owns the helper's constant-count contract.
TESTS[asl_l_reg_zero_count32_const_v_clear]="7000 7220 E3A0 6804 7401 6002 7402"
EXPECTED_REG_FIELDS[asl_l_reg_zero_count32_const_v_clear]="D0=00000000 D2=00000002"
TESTS[asl_b_reg_zero_count63_v_clear]="203C A5A5 0000 723F 44FC 0015 E320 40C6"
TESTS[asl_w_reg_zero_count33_v_clear]="203C A5A5 0000 7221 44FC 0015 E360 40C6"
TESTS[asr_b_reg_count32_boundary]="203C A5A5 007F 7220 44FC 0015 E220 40C6"
TESTS[asr_w_reg_count32_boundary]="203C A5A5 7FFF 7220 44FC 0015 E260 40C6"
TESTS[asr_l_reg_count32_boundary]="203C 7FFF FFFF 7220 44FC 0015 E2A0 40C6"
TESTS[lsl_b_reg_count32_boundary]="203C A5A5 0081 7220 44FC 0015 E328 40C6"
TESTS[lsl_w_reg_count32_boundary]="203C A5A5 8001 7220 44FC 0015 E368 40C6"
TESTS[lsl_l_reg_count32_boundary]="203C 8000 0001 7220 44FC 0015 E3A8 40C6"
TESTS[lsr_b_reg_count32_boundary]="203C A5A5 0081 7220 44FC 0015 E228 40C6"
TESTS[lsr_w_reg_count32_boundary]="203C A5A5 8001 7220 44FC 0015 E268 40C6"
TESTS[lsr_l_reg_count32_boundary]="203C 8000 0001 7220 44FC 0015 E2A8 40C6"
TESTS[lsr_l_reg_count33_boundary]="203C 8000 0001 7221 44FC 0015 E2A8 40C6"
# Replay the corresponding in-block constant producer for LSR.L.  Current
# allocation may still materialise the count; the source audit independently
# requires the immediate helper to saturate count 32.
TESTS[lsr_l_reg_const_count32]="70FF 7220 E2A8 6504 7401 6002 7402"
EXPECTED_REG_FIELDS[lsr_l_reg_const_count32]="D0=00000000 D2=00000002"
TESTS[asl_b_reg_count32_nf]="203C A5A5 0081 7220 44FC 0015 E320 2400"
TESTS[asl_w_reg_count32_nf]="203C A5A5 8001 7220 44FC 0015 E360 2400"
TESTS[asl_l_reg_count32_nf]="203C 8000 0001 7220 44FC 0015 E3A0 2400"
TESTS[asr_b_reg_count32_nf]="203C A5A5 007F 7220 44FC 0015 E220 2400"
TESTS[asr_w_reg_count32_nf]="203C A5A5 7FFF 7220 44FC 0015 E260 2400"
TESTS[asr_l_reg_count32_nf]="203C 8000 0001 7220 44FC 0015 E2A0 2400"
TESTS[lsl_b_reg_count32_nf]="203C A5A5 0081 7220 44FC 0015 E328 2400"
TESTS[lsl_w_reg_count32_nf]="203C A5A5 8001 7220 44FC 0015 E368 2400"
TESTS[lsl_l_reg_count32_nf]="203C 0000 0001 7220 44FC 0015 E3A8 2400"
TESTS[lsr_b_reg_count32_nf]="203C A5A5 0081 7220 44FC 0015 E228 2400"
TESTS[lsr_w_reg_count32_nf]="203C A5A5 8001 7220 44FC 0015 E268 2400"
TESTS[lsr_l_reg_count32_nf]="203C 8000 0001 7220 44FC 0015 E2A8 2400"
TESTS[asl_b_reg_same_count_data]="203C A5A5 00A1 44FC 0015 E120 40C6"
TESTS[asl_w_reg_same_count_data]="203C A5A5 8021 44FC 0015 E160 40C6"
TESTS[asl_l_reg_same_count_data]="203C 8000 0021 44FC 0015 E1A0 40C6"
TESTS[asr_b_reg_same_count_data]="203C A5A5 00A1 44FC 0015 E020 40C6"
TESTS[asr_w_reg_same_count_data]="203C A5A5 8021 44FC 0015 E060 40C6"
TESTS[asr_l_reg_same_count_data]="203C 8000 0021 44FC 0015 E0A0 40C6"
TESTS[lsl_b_reg_same_count_data]="203C A5A5 00A1 44FC 0015 E128 40C6"
TESTS[lsl_w_reg_same_count_data]="203C A5A5 8021 44FC 0015 E168 40C6"
TESTS[lsl_l_reg_same_count_data]="203C 8000 0021 44FC 0015 E1A8 40C6"
TESTS[lsr_b_reg_same_count_data]="203C A5A5 00A1 44FC 0015 E028 40C6"
TESTS[lsr_w_reg_same_count_data]="203C A5A5 8021 44FC 0015 E068 40C6"
TESTS[lsr_l_reg_same_count_data]="203C 8000 0021 44FC 0015 E0A8 40C6"
TESTS[asl_b_reg_same_count_data_nf]="203C A5A5 00A1 44FC 0015 E120 2400"
TESTS[asl_w_reg_same_count_data_nf]="203C A5A5 8021 44FC 0015 E160 2400"
TESTS[asl_l_reg_same_count_data_nf]="203C 8000 0021 44FC 0015 E1A0 2400"
TESTS[asr_b_reg_same_count_data_nf]="203C A5A5 00A1 44FC 0015 E020 2400"
TESTS[asr_w_reg_same_count_data_nf]="203C A5A5 8021 44FC 0015 E060 2400"
TESTS[asr_l_reg_same_count_data_nf]="203C 8000 0021 44FC 0015 E0A0 2400"
TESTS[lsl_b_reg_same_count_data_nf]="203C A5A5 00A1 44FC 0015 E128 2400"
TESTS[lsl_w_reg_same_count_data_nf]="203C A5A5 8021 44FC 0015 E168 2400"
TESTS[lsl_l_reg_same_count_data_nf]="203C 8000 0021 44FC 0015 E1A8 2400"
TESTS[lsr_b_reg_same_count_data_nf]="203C A5A5 00A1 44FC 0015 E028 2400"
TESTS[lsr_w_reg_same_count_data_nf]="203C A5A5 8021 44FC 0015 E068 2400"
TESTS[lsr_l_reg_same_count_data_nf]="203C 8000 0021 44FC 0015 E0A8 2400"
declare -A _SHIFT_BOUNDARY_OPCODES=(
    [asl_b]=E320 [asl_w]=E360 [asl_l]=E3A0
    [asr_b]=E220 [asr_w]=E260 [asr_l]=E2A0
    [lsl_b]=E328 [lsl_w]=E368 [lsl_l]=E3A8
    [lsr_b]=E228 [lsr_w]=E268 [lsr_l]=E2A8
)
declare -A _SHIFT_BOUNDARY_DATA=(
    [b]="A5A5 0081" [w]="A5A5 8001" [l]="8000 0001"
)
for _shift_op in asl asr lsl lsr; do
    for _shift_width in b w l; do
        _shift_opcode="${_SHIFT_BOUNDARY_OPCODES[${_shift_op}_${_shift_width}]}"
        _shift_data="${_SHIFT_BOUNDARY_DATA[$_shift_width]}"
        for _shift_count in 31 33 63; do
            printf -v _shift_count_hex '%02X' "$_shift_count"
            _shift_name="${_shift_op}_${_shift_width}_reg_count${_shift_count}_boundary"
            TESTS["$_shift_name"]="203C ${_shift_data} 72${_shift_count_hex} 44FC 0015 ${_shift_opcode} 40C6"
            TESTS["${_shift_name}_nf"]="203C ${_shift_data} 72${_shift_count_hex} 44FC 0015 ${_shift_opcode} 2400"
        done
    done
done
unset _shift_op _shift_width _shift_opcode _shift_data _shift_count _shift_count_hex _shift_name
unset _SHIFT_BOUNDARY_OPCODES _SHIFT_BOUNDARY_DATA

declare -A _ROTATE_REGISTER_OPCODES=(
    [rol_b]=E338 [rol_w]=E378 [rol_l]=E3B8
    [ror_b]=E238 [ror_w]=E278 [ror_l]=E2B8
)
declare -A _ROTATE_ALIAS_OPCODES=(
    [rol_b]=E138 [rol_w]=E178 [rol_l]=E1B8
    [ror_b]=E038 [ror_w]=E078 [ror_l]=E0B8
)
for _rotate_op in rol ror; do
    for _rotate_width in b w l; do
        _rotate_key="${_rotate_op}_${_rotate_width}"
        _rotate_opcode="${_ROTATE_REGISTER_OPCODES[$_rotate_key]}"
        _rotate_alias_opcode="${_ROTATE_ALIAS_OPCODES[$_rotate_key]}"
        for _rotate_count in 0 31 32 33 63; do
            _rotate_name="${_rotate_op}_${_rotate_width}_reg_count${_rotate_count}_boundary"
            TESTS["$_rotate_name"]="${_rotate_opcode} 40C6"
            TESTS["${_rotate_name}_nf"]="${_rotate_opcode} 7E00 40C6"
        done
        _rotate_alias_name="${_rotate_op}_${_rotate_width}_reg_same_count_data"
        TESTS["$_rotate_alias_name"]="${_rotate_alias_opcode} 40C6"
        TESTS["${_rotate_alias_name}_nf"]="${_rotate_alias_opcode} 7E00 40C6"
    done
done
TESTS[rol_l_reg_const_count64]="203C 8000 0001 7240 44FC 0015 E3B8 40C6"
TESTS[rol_l_reg_const_count64_nf]="203C 8000 0001 7240 44FC 0015 E3B8 7E00 40C6"
TESTS[ror_l_reg_const_count64]="203C 8000 0001 7240 44FC 0015 E2B8 40C6"
TESTS[ror_l_reg_const_count64_nf]="203C 8000 0001 7240 44FC 0015 E2B8 7E00 40C6"
TESTS[rol_b_imm_count8]="E118 40C6"
TESTS[rol_b_imm_count8_nf]="E118 7E00 40C6"
TESTS[rol_w_imm_count8]="E158 40C6"
TESTS[rol_w_imm_count8_nf]="E158 7E00 40C6"
TESTS[rol_l_imm_count8]="E198 40C6"
TESTS[rol_l_imm_count8_nf]="E198 7E00 40C6"
TESTS[ror_b_imm_count8]="E018 40C6"
TESTS[ror_b_imm_count8_nf]="E018 7E00 40C6"
TESTS[ror_w_imm_count8]="E058 40C6"
TESTS[ror_w_imm_count8_nf]="E058 7E00 40C6"
TESTS[ror_l_imm_count8]="E098 40C6"
TESTS[ror_l_imm_count8_nf]="E098 7E00 40C6"
TESTS[rolw_mem_native]="E7D0 40C6 3010"
TESTS[rolw_mem_native_nf]="E7D0 7E00 3010 40C6"
TESTS[rorw_mem_native]="E6D0 40C6 3010"
TESTS[rorw_mem_native_nf]="E6D0 7E00 3010 40C6"
# Fixed-count memory shifts have distinct flag-producing and no-flags wrappers.
# The nf forms overwrite the complete CCR, including X, before observing state.
TESTS[aslw_mem_native]="E1D0 40C6 3010"
TESTS[aslw_mem_native_nf]="E1D0 44FC 0015 3010 40C6"
TESTS[asrw_mem_native]="E0D0 40C6 3010"
TESTS[asrw_mem_native_nf]="E0D0 44FC 0015 3010 40C6"
TESTS[lslw_mem_native]="E3D0 40C6 3010"
TESTS[lslw_mem_native_nf]="E3D0 44FC 0015 3010 40C6"
TESTS[lsrw_mem_native]="E2D0 40C6 3010"
TESTS[lsrw_mem_native_nf]="E2D0 44FC 0015 3010 40C6"
TESTS[roxlw_mem_x_native]="E5D0 40C6 3010"
TESTS[roxrw_mem_x_native]="E4D0 40C6 3010"
EXPECTED_REG_FIELDS[rol_l_reg_const_count64]="D0=80000001 D6=00002718"
EXPECTED_REG_FIELDS[ror_l_reg_const_count64]="D0=80000001 D6=00002718"
EXPECTED_REG_FIELDS[rolw_mem_native]="D0=00000003 D6=00002711"
EXPECTED_REG_FIELDS[rorw_mem_native]="D0=0000C000 D6=00002719"
EXPECTED_REG_FIELDS[aslw_mem_native]="D0=00008000 D6=0000270A"
EXPECTED_REG_FIELDS[aslw_mem_native_nf]="D0=00008000 D6=00002718"
EXPECTED_REG_FIELDS[asrw_mem_native]="D0=0000C000 D6=00002719"
EXPECTED_REG_FIELDS[asrw_mem_native_nf]="D0=0000C000 D6=00002718"
EXPECTED_REG_FIELDS[lslw_mem_native]="D0=00000002 D6=00002711"
EXPECTED_REG_FIELDS[lslw_mem_native_nf]="D0=00000002 D6=00002710"
EXPECTED_REG_FIELDS[lsrw_mem_native]="D0=00004000 D6=00002711"
EXPECTED_REG_FIELDS[lsrw_mem_native_nf]="D0=00004000 D6=00002710"
EXPECTED_REG_FIELDS[roxlw_mem_x_native]="D0=00000003 D6=00002711"
EXPECTED_REG_FIELDS[roxrw_mem_x_native]="D0=0000C000 D6=00002708"
EXPECTED_REG_FIELDS[rol_l_reg_count32_boundary]="D0=80000001 D6=00002719"
EXPECTED_REG_FIELDS[rol_l_reg_same_count_data]="D0=00000043 D6=00002711"
unset _rotate_op _rotate_width _rotate_key _rotate_opcode _rotate_alias_opcode
unset _rotate_count _rotate_name _rotate_alias_name
unset _ROTATE_REGISTER_OPCODES _ROTATE_ALIAS_OPCODES
# Taken TRAPV preserves all CCR bits and uses the same successor/opcode
# format-2 address split as vector-5 arithmetic traps.
TESTS[trapv_taken_frame]="7000 4E7B 0801 23FC 0000 101A 0000 001C 44FC 001F 4E76 60FE 4E71 3C17 282F 0002 2A2F 0008 7E69"
EXPECTED_REG_FIELDS[trapv_taken_frame]="D4=00001016 D5=00001014 D6=0000271f"
# Non-taken TRAPV must suppress vector 7, clear no CCR bit, and retire its
# sequential successor natively. MOVE SR,D6 snapshots the preserved CCR before
# the test hook's terminal state transition.
TESTS[trapv_not_taken_preserve]="44FC 001D 4E76 40C6 7E6A"
EXPECTED_REG_FIELDS[trapv_not_taken_preserve]="D6=0000271d"

# SBCD borrow chain: 0x00 - 0x01 with X=0 → 0x99, borrow
# ANDI #$EF,CCR; MOVEQ #0,D0; MOVEQ #1,D1; SBCD D1,D0
TESTS[sbcd_borrow_chain]="023C 00EF 7000 7201 8101"
# SBCD zero: 0-0 with X=0 → 0
TESTS[sbcd_zero_zero]="023C 00EF 7000 7200 8101"

# NBCD zero with X=0: NBCD of 0 → 0, no borrow
TESTS[nbcd_zero_no_x]="023C 00EF 7000 4800"
# NBCD with X=1: NBCD of 0 → 0x99, borrow
TESTS[nbcd_with_x]="003C 0010 7000 4800"

# BFINS: insert D0 low 8 bits into D1{0:8}
# MOVE.L #$AB,D0; CLR.L D1; BFINS D0,D1{0:8}
TESTS[bfins_low8]="203C 0000 00AB 4281 EFC1 0008"
# BFINS: insert D0 into D1{16:8} (mid-field)
TESTS[bfins_mid8]="203C 0000 00CD 4281 EFC1 0410"

# MOVEC VBR roundtrip: write then read VBR
# MOVE.L #$12340000,D0; MOVEC D0,VBR; MOVEC VBR,D1
TESTS[movec_vbr_roundtrip]="203C 1234 0000 4E7B 0801 4E7A 1801"
# MOVEC SFC: write SFC=5, read back
# MOVEQ #5,D0; MOVEC D0,SFC; MOVEC SFC,D1
TESTS[movec_sfc_roundtrip]="7005 4E7B 0000 4E7A 1000"
# MOVEC DFC: write DFC=3, read back
TESTS[movec_dfc_roundtrip]="7003 4E7B 0001 4E7A 1001"

# Full-SR operations privilege-trap from the opcode, before immediate fetch or
# destination modification. IPL7 keeps these user-mode windows deterministic.
TESTS[fullsr_orsr_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 007C DEAD 60FE 4E71 7E80"
TESTS[fullsr_andsr_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 027C DEAD 60FE 4E71 7E81"
TESTS[fullsr_eorsr_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 0A7C DEAD 60FE 4E71 7E82"
TESTS[fullsr_mv2sr_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 46FC DEAD 60FE 4E71 7E83"
TESTS[fullsr_mvsr_privilege_vector8]="7000 4E7B 0801 23FC 0000 101A 0000 0020 46FC 0700 40C0 60FE 4E71 7E84"

# Privileged integer control families use one exact-opcode-PC semantic service.
# Successful USP moves round-trip A0 through USP and expose the result in D0.
TESTS[system_usp_roundtrip]="207C 1234 5678 4E60 207C 0000 0000 4E68 2008"
# Each user-mode vector installs a local vector-8 handler and retains IPL7 while
# clearing S, preventing an asynchronous 60 Hz interrupt from racing the short
# user-mode window. The spin is reached only if privilege is checked late or
# omitted; extension-bearing forms carry deliberately non-semantic data.
TESTS[reset_privilege_vector8]="7000 4E7B 0801 23FC 0000 101A 0000 0020 46FC 0700 4E70 60FE 4E71 7E70"
TESTS[usp_privilege_vector8]="7000 4E7B 0801 23FC 0000 101A 0000 0020 46FC 0700 4E68 60FE 4E71 7E68"
# A supervisor STOP that clears S traps from the successor without committing
# SR or entering the stopped state; user STOP traps from the opcode before use
# of its immediate word.
TESTS[stop_clear_s_vector8]="7000 4E7B 0801 23FC 0000 1018 0000 0020 4E72 0000 60FE 4E71 7E72"
TESTS[stop_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 4E72 DEAD 60FE 4E71 7E71"
TESTS[movec_privilege_vector8]="7000 4E7B 0801 23FC 0000 101C 0000 0020 46FC 0700 4E7A 1FFF 60FE 4E71 7E7A"
TESTS[rte_privilege_vector8]="7000 4E7B 0801 23FC 0000 101A 0000 0020 46FC 0700 4E73 60FE 4E71 7E73"
TESTS[cache_privilege_vector8]="7000 4E7B 0801 23FC 0000 101A 0000 0020 46FC 0700 F428 60FE 4E71 7E42"
# Data-cache-only and instruction-cache CPUSH forms must both advance exactly
# once; only the latter invalidates host translations.
TESTS[cache_supervisor_successors]="F428 F4A8 7C42"

# MULL unsigned 64-bit: D0 * D1 → D2:D3 (64-bit result)
# MOVE.L #$FFFFFFFF,D0; MOVE.L #2,D1; MULL.L D0,D2:D3
# MULL encoding: 4C00 + EA(D0) + ext_word (D3=Dl bits15-12, D2=Dh bits2-0, unsigned=0, 64=0x400)
# ext word: 0011_0_0_00000_010 = 0x3402
TESTS[mull_u64]="203C FFFF FFFF 223C 0000 0002 4C01 3402"
# MULL signed 32-bit: -1 * -1 → 1
# MOVE.L #$FFFFFFFF,D0; MOVE.L #$FFFFFFFF,D1; MULL.L D0,D1 (signed 32)
# ext word: 0001_1_0_00000_000 = 0x1800 — wait, let me recalc
# ext word: bit11=signed(1), bit10=64(0), bits15-12=Dl(1), bits2-0=Dh(x)
# = 0001_1_0_00000_000 = 0x1800
TESTS[mull_s32_neg]="203C FFFF FFFF 223C FFFF FFFF 4C00 1800"

# DIVL unsigned 32-bit: 100 / 7 → quot=14, rem=2
# MOVE.L #100,D0; MOVE.L #7,D1; DIVL.L D1,D2:D0
# DIVL encoding: 4C41 (EA=D1) + ext word
# ext word: bits15-12=Dq(0), bit11=signed(0), bit10=32bit(0), bits2-0=Dr(2)
# = 0000_0_0_00000_010 = 0x0002
TESTS[divl_u32_rem]="203C 0000 0064 223C 0000 0007 4C41 0002"
# DIVL signed: -100 / 7 → quot=-14, rem=-2
TESTS[divl_s32_neg]="203C FFFF FF9C 223C 0000 0007 4C41 0802"
# DIVUL.L D1,D2:D0 — max unsigned: 0xFFFFFFFF / 16 = 0x0FFFFFFF rem 15
TESTS[divl_u32_max]="203C FFFF FFFF 223C 0000 0010 4C41 0002"
# DIVSL.L D1,D2:D0 — negative divisor: 100 / -7 = -14 rem 2
TESTS[divl_s32_neg_divisor]="203C 0000 0064 223C FFFF FFF9 4C41 0802"
# MULSL.L D1,D3:D2 — 64-bit signed negative: -100 * 1000 = -100000
TESTS[mull_s64_neg]="243C FFFF FF9C 223C 0000 03E8 4C01 2C03"

# Opcode-first native MULL closure vectors.  BVC makes the signed/unsigned
# 32/64 flag-producing handlers observable; MOVEQ D7 selects the no-flags
# handler for alias-only vectors after the multiply result has been consumed.
# MULL.S32 D0,D1: -1 * 2 = -2 fits in 32 bits, so V must stay clear.
TESTS[mulls32_negative_fit_v_native]="4C00 1800 6802 7401 7602"
EXPECTED_REG_FIELDS[mulls32_negative_fit_v_native]="D0=00000002 D1=fffffffe D2=00000000 D3=00000002 SR=2700"
# MULL.U64 D0,D2:D1: D0 is a read-only source and must survive 0xffffffff * 2.
TESTS[mullu64_source_preserve_v_native]="4C00 1402 6802 7601 7802"
EXPECTED_REG_FIELDS[mullu64_source_preserve_v_native]="D0=00000002 D1=fffffffe D2=00000001 D3=00000000 D4=00000002 SR=2700"
# Source D0 is also the low result.  The product must be staged before either
# architectural result register is published.
TESTS[mullu64_source_low_alias_native]="4C00 0402 7E01"
EXPECTED_REG_FIELDS[mullu64_source_low_alias_native]="D0=00000001 D2=fffffffe D7=00000001 SR=2700"
# Dh == Dl is legal.  m68k_mull writes high first and low second, so low wins.
TESTS[mullu64_same_result_alias_native]="4C00 1401 7E01"
EXPECTED_REG_FIELDS[mullu64_same_result_alias_native]="D0=00000002 D1=fffffffe D7=00000001 SR=2700"

# For a selected 32-bit result, m68k_mull still derives N/Z from the full
# product.  The branch markers make N/Z/V independently observable before a
# final MOVEQ normalises the dump-time CCR.
TESTS[mullu32_low_sign_full_flags_native]="4C00 1000 6A02 7401 6602 7601 6802 7801 7A02"
EXPECTED_REG_FIELDS[mullu32_low_sign_full_flags_native]="D0=80000000 D1=80000000 D2=00000000 D3=00000000 D4=00000000 D5=00000002 SR=2700"
TESTS[mullu32_overflow_low_zero_flags_native]="4C00 1000 6A02 7401 6602 7601 6902 7801 7A02"
EXPECTED_REG_FIELDS[mullu32_overflow_low_zero_flags_native]="D0=00010000 D1=00000000 D2=00000000 D3=00000000 D4=00000000 D5=00000002 SR=2700"
TESTS[mulls32_negative_overflow_low_zero_native]="4C00 1800 6B02 7401 6602 7601 6902 7801 7A02"
EXPECTED_REG_FIELDS[mulls32_negative_overflow_low_zero_native]="D0=00000002 D1=00000000 D2=00000000 D3=00000000 D4=00000000 D5=00000002 SR=2700"
TESTS[mulls32_positive_overflow_low_sign_native]="4C00 1800 6A02 7401 6602 7601 6902 7801 7A02"
EXPECTED_REG_FIELDS[mulls32_positive_overflow_low_sign_native]="D0=00000002 D1=80000000 D2=00000000 D3=00000000 D4=00000000 D5=00000002 SR=2700"
# Signed and unsigned selected-64 flag paths: N/Z use all 64 result bits and
# V/C are clear because every 32x32 product fits the selected width.
TESTS[mulls64_negative_flags_native]="4C00 1C02 6B02 7601 6602 7801 6802 7A01 7C02"
EXPECTED_REG_FIELDS[mulls64_negative_flags_native]="D0=000003e8 D1=fffe7960 D2=ffffffff D3=00000000 D4=00000000 D5=00000000 D6=00000002 SR=2700"
TESTS[mullu64_zero_flags_native]="4C00 1402 6702 7601 6A02 7801 6802 7A01 7C02"
EXPECTED_REG_FIELDS[mullu64_zero_flags_native]="D0=00001234 D1=00000000 D2=00000000 D3=00000000 D4=00000000 D5=00000000 D6=00000002 SR=2700"
# Complete the legal source/Dl/Dh alias closure and non-register source forms.
TESTS[mullu64_source_high_alias_native]="4C00 1400 7E01"
EXPECTED_REG_FIELDS[mullu64_source_high_alias_native]="D0=00000001 D1=fffffffe D7=00000001 SR=2700"
TESTS[mullu64_all_alias_native]="4C00 0400 7E01"
EXPECTED_REG_FIELDS[mullu64_all_alias_native]="D0=00000001 D7=00000001 SR=2700"
TESTS[mullu32_immediate_nf_native]="4C3C 1000 0000 0003 7E01"
EXPECTED_REG_FIELDS[mullu32_immediate_nf_native]="D1=00000015 D7=00000001 SR=2700"
TESTS[mullu64_memory_nf_native]="4C10 0401 7E01"
EXPECTED_REG_FIELDS[mullu64_memory_nf_native]="D0=fffffffe D1=00000001 D7=00000001 A0=0000a000 SR=2700"

# DIVUL.L D1,D0:D0 — same Dq and Dr (remainder discarded): 100/7=14
TESTS[divl_same_dq_dr]="203C 0000 0064 223C 0000 0007 4C41 0000"
# DIVUL.L D1,D3:D2 — 64-bit unsigned: 0x100000064 / 7 = 0x24924932 rem 6
TESTS[divl_u64]="243C 0000 0064 263C 0000 0001 223C 0000 0007 4C41 2403"
# DIVSL.L D1,D3:D2 — 64-bit signed: -100 / 7 = -14 rem -2
TESTS[divl_s64]="243C FFFF FF9C 263C FFFF FFFF 223C 0000 0007 4C41 2C03"
# BFINS D0,D1{4:8} — insert 0xA5 at offset 4 width 8 into cleared D1
TESTS[bfins_dreg_imm]="203C 0000 00A5 4281 EFC1 0108"
# BFINS D0,D1{8:4} — insert 0xF at offset 8 width 4
TESTS[bfins_dreg_narrow]="203C 0000 000F 2200 EFC1 0204"
# Register field wraps through bit 31 back to bit 0.
TESTS[bfins_dreg_wrap]="203C 0000 00AB 223C 1234 5678 EFC1 0708"
# Offset and width come from D2/D3 at execution time.
TESTS[bfins_dreg_dyn]="203C 0000 00A5 223C 1234 5678 741C 7608 EFC1 08A3"
# A dynamic width of zero denotes 32 bits, including a wrapped destination.
TESTS[bfins_dreg_dyn_width32]="203C 89AB CDEF 223C 1234 5678 7405 7600 EFC1 08A3"
# A 32-bit memory field at bit offset 7 spans five bytes.
TESTS[bfins_mem_span32]="41F9 0000 9100 203C 89AB CDEF 20BC 1122 3344 117C 0055 0004 EFD0 01C0 2410 1628 0004"
# Dynamic memory offsets are signed and retain their byte displacement.
TESTS[bfins_mem_dyn_negative]="41F9 0000 9104 217C 1122 3344 FFFC 20BC 5566 7788 203C 0000 0ABC 72F7 EFD0 084C 2428 FFFC 2610"
# Exact ROM boot form at 0403939c: D0 is both source and dynamic offset, width 32.
TESTS[bfins_dreg_boot_alias]="203C 89AB CDEF 2C3C 1234 5678 EFC6 0800"
# Exact ROM boot family at 04030d30: signed D4 memory offset, width 32.
TESTS[bfins_mem_dyn_neg_width32]="45F9 0000 9104 257C 1122 3344 FFFC 24BC 5566 7788 203C 89AB CDEF 78F7 EFD2 0900 242A FFFC 2612"
TESTS[bfins_mem_dyn_pos_width32]="45F9 0000 9100 24BC 1122 3344 257C 5566 7788 0004 203C 89AB CDEF 781F EFD2 0900 2412 262A 0004"

# ---- Z-flag flow ORACLE MATRIX (cmpl.L -> beq.W/bne.W Z-materialization) -----
# Reproduces the CONT.109 cont14 hypothesis: a stale Z from a preceding flag
# setter (moveq/tst/move/and/sub) must NOT be materialized for a Bcc that
# consumes a later CMP.L's Z. Each vector seeds an adversarial stale Z (opposite
# of the CMP outcome), then CMP.L D0,D1 (B280) feeds BEQ.W/BNE.W (6700/6600 0004,
# which skips the one-word 0x33 marker MOVEQ when taken). Harness compares interp
# vs JIT register dumps: any Z mis-materialization diverges D2.
# Tail BEQ taken (cmp equal d0=d1=7): 7007 7207 B280 6700 0004 7433 7844
# Tail BEQ not-taken (cmp unequal d0=5,d1=3): 7005 7203 B280 6700 0004 7433 7844
# moveq stale Z=1 (d3=0), then cmp equal -> BEQ must take (skip 7433)
TESTS[oracle_zf_moveq_z1_take]="7600 7007 7207 B280 6700 0004 7433 7844"
# moveq stale Z=0 (d3=5), then cmp unequal -> BEQ must NOT take (run 7433)
TESTS[oracle_zf_moveq_z0_notake]="7605 7005 7203 B280 6700 0004 7433 7844"
# moveq stale Z=0, then cmp equal -> BEQ must take
TESTS[oracle_zf_moveq_z0_take]="7605 7007 7207 B280 6700 0004 7433 7844"
# moveq stale Z=1, then cmp unequal -> BEQ must NOT take
TESTS[oracle_zf_moveq_z1_notake]="7600 7005 7203 B280 6700 0004 7433 7844"
# tst.l d3 stale Z=1 (d3=0), cmp equal -> take
TESTS[oracle_zf_tst_z1_take]="7600 4A83 7007 7207 B280 6700 0004 7433 7844"
# tst.l d3 stale Z=0 (d3=5), cmp unequal -> not take
TESTS[oracle_zf_tst_z0_notake]="7605 4A83 7005 7203 B280 6700 0004 7433 7844"
# move.l d5,d3 stale Z=1 (d5=0), cmp equal -> take
TESTS[oracle_zf_move_z1_take]="7A00 2605 7007 7207 B280 6700 0004 7433 7844"
# move.l d5,d3 stale Z=0 (d5=9), cmp unequal -> not take
TESTS[oracle_zf_move_z0_notake]="7A09 2605 7005 7203 B280 6700 0004 7433 7844"
# and.l d3,d3 stale Z=1 (d3=0), cmp equal -> take
TESTS[oracle_zf_and_z1_take]="7600 C683 7007 7207 B280 6700 0004 7433 7844"
# and.l d3,d3 stale Z=0 (d3=6), cmp unequal -> not take
TESTS[oracle_zf_and_z0_notake]="7606 C683 7005 7203 B280 6700 0004 7433 7844"
# sub.l d3,d3 stale Z=1 (d3=4->0), cmp equal -> take
TESTS[oracle_zf_sub_z1_take]="7604 9683 7007 7207 B280 6700 0004 7433 7844"
# sub.l d5,d3 stale Z=0 (d3=5,d5=2->3), cmp unequal -> not take
TESTS[oracle_zf_sub_z0_notake]="7605 7A02 9685 7005 7203 B280 6700 0004 7433 7844"
# bne adversarial: moveq stale Z=1 (looks equal), cmp unequal -> BNE must take
TESTS[oracle_zf_bne_z1_take]="7600 7005 7203 B280 6600 0004 7433 7844"
# bne adversarial: moveq stale Z=0 (looks unequal), cmp equal -> BNE must NOT take
TESTS[oracle_zf_bne_z0_notake]="7605 7007 7207 B280 6600 0004 7433 7844"
# memory-fed cmp (exact cont14 shape: d0 from a load feeds CMP.L D0,D1):
# movea.l #$3000,a0; store 7; reload d0 from (a0); d1=7; cmp equal -> BEQ take
TESTS[oracle_zf_mem_take]="207C 0000 3000 7007 2080 2010 7207 B280 6700 0004 7433 7844"
# store 5; reload d0; d1=3; cmp unequal -> BEQ must NOT take
TESTS[oracle_zf_mem_notake]="207C 0000 3000 7005 2080 2010 7203 B280 6700 0004 7433 7844"
# DBF must preserve CCR from the preceding MOVE.W. MOVE.W #0,D0 sets Z=1;
# DBF D0 exits after decrementing D0.W to -1 and must NOT clobber Z;
# BEQ must therefore skip the D2 marker.
TESTS[oracle_zf_dbf_preserve_take]="7400 303C 0000 51C8 FFFE 6700 0004 7433 7844"

# RTR: pop CCR + PC from stack — test via BSR/RTR pair
# Setup flags: ORI #$1F,CCR (set all flags)
# BSR.W +4 (push PC); RTR pops CCR (from stack) + PC (from stack)
# This is complex — RTR needs a proper stack frame. Let me use a simpler pattern:
# Push known CCR value + return address onto stack, then RTR
# MOVE.L #<return_addr>,-(SP); MOVE.W #$001F,-(SP); RTR
# But we don't know the return address... skip RTR for now.

# STOP: can't easily test since it halts. The harness USES STOP #$2700 to end.
# We implicitly test STOP in every vector.

# ---- FUZZ VECTORS (auto-generated, seed=0xDEADBEEF) ----
# ALU chain: and.l d4,d3; sub.l d4,d3
TESTS[fuzz_alu_0]="C684 9684"
# Shift chain: asr.l #8,d3; asr.l #3,d3; rol.l #7,d3
TESTS[fuzz_shift_0]="E083 E683 EF9B"
# Bit ops: bchg #17,d4; bchg #25,d4; bclr #0,d4; bchg #31,d4
TESTS[fuzz_bitops_0]="0844 0011 0844 0019 0884 0000 0844 001F"
# Mul/Div: muls.w d5,d3; divs.w d5,d3
TESTS[fuzz_muldiv_0]="C7C5 87C5"
# Ext/Swap: tst.l d0; ext.l d0; not.l d0
TESTS[fuzz_extswap_0]="4A80 48C0 4680"
# Addx/Subx: ori #$10,ccr; subx.l d5,d2; negx.l d2
TESTS[fuzz_addxsubx_0]="003C 0010 9585 4082"
# Mem roundtrip: move.l d3,(60,a1); not.l d3; move.l (60,a1),d0; cmp.l d3,d0
TESTS[fuzz_memrt_0]="2343 003C 4683 2029 003C B083"
# Exg chain: exg d4,d1; exg d1,d5; exg d2,d3; tst.l d1
TESTS[fuzz_exg_0]="C941 C345 C543 4A81"
# Mixed ALU+Shift: or.l d1,d0; swap d0; sub.l d3,d0
TESTS[fuzz_mixed_0]="8081 4840 9083"
# Flag stress: ori #$0,ccr; tst.l d0
TESTS[fuzz_flags_0]="003C 0000 4A80"
# ALU chain: and.l d5,d5; add.l d4,d5
TESTS[fuzz_alu_1]="CA85 DA84"
# Shift chain: lsr.l #3,d1; asr.l #5,d1
TESTS[fuzz_shift_1]="E689 EA81"
# Bit ops: bset #5,d5; bchg #8,d5
TESTS[fuzz_bitops_1]="08C5 0005 0845 0008"
# Mul/Div: mulu.w d5,d1; divu.w d5,d1
TESTS[fuzz_muldiv_1]="C2C5 82C5"
# Ext/Swap: swap d2; neg.l d2; ext.w d2; tst.l d2
TESTS[fuzz_extswap_1]="4842 4482 4882 4A82"
# Addx/Subx: andi #$EF,ccr; subx.l d5,d2; negx.l d2
TESTS[fuzz_addxsubx_1]="023C 00EF 9585 4082"
# Mem roundtrip: move.l d3,(212,a1); not.l d3; move.l (212,a1),d0; cmp.l d3,d0
TESTS[fuzz_memrt_1]="2343 00D4 4683 2029 00D4 B083"
# Exg chain: exg d5,d2; exg d4,d3; tst.l d4
TESTS[fuzz_exg_1]="CB42 C943 4A84"
# Mixed ALU+Shift: lsl.l #1,d2; and.l d0,d2; lsl.l #2,d2
TESTS[fuzz_mixed_1]="E38A C480 E58A"
# Flag stress: ori #$11,ccr; addx.l d4,d0; tst.l d0
TESTS[fuzz_flags_1]="003C 0011 D184 4A80"
# ALU chain: or.l d1,d3; eor.l d1,d3
TESTS[fuzz_alu_2]="8681 B383"
# Shift chain: ror.l #6,d3; asr.l #1,d3; asl.l #8,d3
TESTS[fuzz_shift_2]="EC9B E283 E183"
# Bit ops: bset #7,d1; bchg #21,d1; bset #1,d1
TESTS[fuzz_bitops_2]="08C1 0007 0841 0015 08C1 0001"
# Mul/Div: muls.w d4,d2; divu.w d4,d2
TESTS[fuzz_muldiv_2]="C5C4 84C4"
# Ext/Swap: tst.l d0; ext.l d0; swap d0; not.l d0
TESTS[fuzz_extswap_2]="4A80 48C0 4840 4680"
# Addx/Subx: andi #$EF,ccr; addx.l d5,d0; negx.l d0
TESTS[fuzz_addxsubx_2]="023C 00EF D185 4080"
# Mem roundtrip: move.l d2,(60,a2); not.l d2; move.l (60,a2),d3; cmp.l d2,d3
TESTS[fuzz_memrt_2]="2542 003C 4682 262A 003C B682"
# Exg chain: exg d1,d3; exg d0,d2; tst.l d5
TESTS[fuzz_exg_2]="C343 C142 4A85"
# Mixed ALU+Shift: lsr.l #7,d3; swap d3; or.l d5,d3; neg.l d3; or.l d5,d3
TESTS[fuzz_mixed_2]="EE8B 4843 8685 4483 8685"
# Flag stress: ori #$f,ccr; addx.l d4,d1; tst.l d1
TESTS[fuzz_flags_2]="003C 000F D384 4A81"
# ALU chain: and.l d3,d1; sub.l d5,d1
TESTS[fuzz_alu_3]="C283 9285"
# Shift chain: asl.l #8,d5; ror.l #8,d5
TESTS[fuzz_shift_3]="E185 E09D"
# Bit ops: bset #31,d1; bset #0,d1; bclr #24,d1; bset #8,d1
TESTS[fuzz_bitops_3]="08C1 001F 08C1 0000 0881 0018 08C1 0008"
# Mul/Div: muls.w d4,d2; divu.w d4,d2
TESTS[fuzz_muldiv_3]="C5C4 84C4"
# Ext/Swap: ext.l d3; swap d3; tst.l d3
TESTS[fuzz_extswap_3]="48C3 4843 4A83"
# Addx/Subx: ori #$10,ccr; subx.l d4,d0; negx.l d0
TESTS[fuzz_addxsubx_3]="003C 0010 9184 4080"
# Mem roundtrip: move.l d2,(244,a1); not.l d2; move.l (244,a1),d3; cmp.l d2,d3
TESTS[fuzz_memrt_3]="2342 00F4 4682 2629 00F4 B682"
# Exg chain: exg d1,d3; exg d5,d4; tst.l d2
TESTS[fuzz_exg_3]="C343 CB44 4A82"
# Mixed ALU+Shift: or.l d4,d3; sub.l d3,d3; lsl.l #6,d3; swap d3; sub.l d3,d3; add.l d2,d3
TESTS[fuzz_mixed_3]="8684 9683 ED8B 4843 9683 D682"
# Flag stress: ori #$13,ccr; addx.l d4,d0; tst.l d0
TESTS[fuzz_flags_3]="003C 0013 D184 4A80"
# ALU chain: add.l d2,d2; sub.l d5,d2; and.l d5,d2
TESTS[fuzz_alu_4]="D482 9485 C485"
# Shift chain: rol.l #7,d2; asr.l #1,d2; asl.l #7,d2
TESTS[fuzz_shift_4]="EF9A E282 EF82"
# Bit ops: bclr #13,d3; bset #28,d3; bchg #10,d3
TESTS[fuzz_bitops_4]="0883 000D 08C3 001C 0843 000A"
# Mul/Div: muls.w d5,d2; divs.w d5,d2
TESTS[fuzz_muldiv_4]="C5C5 85C5"
# Ext/Swap: ext.w d5; tst.l d5; ext.l d5; tst.l d5
TESTS[fuzz_extswap_4]="4885 4A85 48C5 4A85"
# Addx/Subx: ori #$10,ccr; subx.l d4,d1
TESTS[fuzz_addxsubx_4]="003C 0010 9384"
# Mem roundtrip: move.l d0,(8,a0); not.l d0; move.l (8,a0),d1; cmp.l d0,d1
TESTS[fuzz_memrt_4]="2140 0008 4680 2228 0008 B280"
# Exg chain: exg d4,d0; tst.l d1
TESTS[fuzz_exg_4]="C940 4A81"
# Mixed ALU+Shift: swap d1; or.l d1,d1; neg.l d1; lsr.l #3,d1; neg.l d1
TESTS[fuzz_mixed_4]="4841 8281 4481 E689 4481"
# Flag stress: ori #$1a,ccr; addx.l d4,d2; tst.l d2
TESTS[fuzz_flags_4]="003C 001A D584 4A82"


declare -A SENTINEL_A6
declare -A INIT_REGS   # optional initial register state (D0-D7 A0-A7 [SR])
_ADD_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
_ADD_D1_ONE_TAIL="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[add_core_b_reg_zero_native]="A5A500FF $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_w_reg_overflow_native]="A5A57FFF $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_l_reg_carry_native]="FFFFFFFF $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_b_self_alias_native]="A5A50080 $_ADD_ZERO_TAIL 00002700"
INIT_REGS[add_core_w_self_alias_native]="A5A58000 $_ADD_ZERO_TAIL 00002700"
INIT_REGS[add_core_l_self_alias_native]="80000000 $_ADD_ZERO_TAIL 00002700"
INIT_REGS[add_core_b_imm_overflow_native]="A5A5007F $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_w_imm_carry_native]="A5A50001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_l_imm_large_native]="00000001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_l_imm_negative_native]="00000001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_b_reg_noflags_native]="A5A5007F $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_w_reg_noflags_native]="A5A57FFF $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_l_reg_noflags_native]="7FFFFFFF $_ADD_D1_ONE_TAIL 0000271F"
INIT_REGS[add_core_b_aind_source_special_native]="A5A5007F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_w_postinc_source_native]="A5A5FFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_l_predec_source_native]="7FFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_b_d16_source_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_w_index_source_special_native]="A5A57FFF 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_l_absw_source_native]="FFFFFFFF $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_b_absl_source_special_native]="A5A50001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_w_pc16_source_native]="A5A57FFF $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_l_pcindex_source_native]="FFFFFFFF FFFFFFEE 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_b_aind_dest_special_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_w_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_l_predec_dest_native]="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_b_d16_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_w_index_dest_special_native]="A5A50001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_l_absw_dest_native]="00000001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_b_absl_dest_special_native]="A5A50001 $_ADD_ZERO_TAIL 0000271F"
INIT_REGS[add_core_b_a7_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[add_core_b_a7_predec_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[add_core_b_addi_postinc_dest_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_b_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[add_core_b_postinc_dest_noflags_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _ADD_ZERO_TAIL _ADD_D1_ONE_TAIL
_AND_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[and_core_b_reg_zero_native]="A5A500FF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_w_reg_negative_native]="A5A5FFFF 00008000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_reg_positive_native]="FFFFFFFF 7FFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_self_alias_native]="A5A50080 $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_w_self_alias_native]="A5A58000 $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_l_self_alias_native]="80000000 $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_b_imm_zero_native]="A5A500FF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_w_imm_negative_native]="A5A5FFFF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_l_imm_pattern_native]="FFFFFFFF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_l_imm_negative_native]="FFFFFFFF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_b_reg_noflags_native]="A5A500FF 0000000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_w_reg_noflags_native]="A5A5FFFF 00000F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_reg_noflags_native]="FFFFFFFF 0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_aind_source_special_native]="A5A500F0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_w_postinc_source_native]="A5A5F0F0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_predec_source_native]="FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_d16_source_native]="A5A500FF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_w_index_source_special_native]="A5A5FFFF 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_absw_source_native]="F0F0F0F0 $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_b_absl_source_special_native]="A5A500F0 $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_w_pc16_source_native]="A5A5FFFF $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_l_pcindex_source_native]="FFFFFFFF FFFFFFEE 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_aind_dest_special_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_w_postinc_dest_native]="A5A50F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_predec_dest_native]="0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_d16_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_w_index_dest_special_native]="A5A58000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_l_absw_dest_native]="0F0F0F0F $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_b_absl_dest_special_native]="A5A5000F $_AND_ZERO_TAIL 0000271F"
INIT_REGS[and_core_b_a7_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[and_core_b_a7_predec_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[and_core_b_andi_postinc_dest_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[and_core_b_postinc_dest_noflags_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _AND_ZERO_TAIL
_EOR_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[eor_core_b_reg_zero_native]="A5A500FF 000000FF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_w_reg_negative_native]="A5A57FFF 0000FFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_l_reg_positive_native]="FFFFFFFF 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_b_self_alias_native]="A5A50080 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_w_self_alias_native]="A5A58000 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_l_self_alias_native]="80000000 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_b_imm_zero_native]="A5A500FF $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_w_imm_negative_native]="A5A57FFF $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_l_imm_pattern_native]="00000000 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_l_imm_negative_native]="00000000 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_b_reg_noflags_native]="A5A500F0 0000000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_w_reg_noflags_native]="A5A5F0F0 00000F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_l_reg_noflags_native]="F0F0F0F0 0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_b_imm_noflags_native]="A5A500F0 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_w_imm_noflags_native]="A5A5F0F0 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_l_imm_noflags_native]="F0F0F0F0 $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_b_aind_dest_special_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_w_postinc_dest_native]="A5A50F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_l_predec_dest_native]="0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_b_d16_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_w_index_dest_special_native]="A5A50F0F 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_l_absw_dest_native]="0F0F0F0F $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_b_absl_dest_special_native]="A5A5000F $_EOR_ZERO_TAIL 0000271F"
INIT_REGS[eor_core_b_a7_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[eor_core_b_a7_predec_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[eor_core_b_eori_postinc_dest_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_b_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[eor_core_b_postinc_dest_noflags_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _EOR_ZERO_TAIL
_OR_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[or_core_b_reg_zero_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_reg_negative_native]="A5A50000 00008000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_reg_positive_native]="70000000 0FFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_self_alias_native]="A5A50080 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_w_self_alias_native]="A5A58000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_l_self_alias_native]="80000000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_imm_zero_native]="A5A50000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_w_imm_negative_native]="A5A50000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_l_imm_pattern_native]="00000000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_l_imm_negative_native]="00000000 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_reg_noflags_native]="A5A500F0 0000000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_reg_noflags_native]="A5A5F0F0 00000F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_reg_noflags_native]="F0F0F0F0 0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_imm_noflags_native]="A5A500F0 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_w_imm_noflags_native]="A5A5F0F0 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_l_imm_noflags_native]="F0F0F0F0 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_aind_source_special_native]="A5A500F0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_postinc_source_native]="A5A5F0F0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_predec_source_native]="0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_d16_source_native]="A5A500F0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_index_source_special_native]="A5A500F0 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_absw_source_native]="F0F0F0F0 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_absl_source_special_native]="A5A5000F $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_w_pc16_source_native]="A5A5FF00 $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_l_pcindex_source_native]="7F000000 FFFFFFEE 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_aind_dest_special_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_postinc_dest_native]="A5A50F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_predec_dest_native]="0F0F0F0F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_d16_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_w_index_dest_special_native]="A5A50F0F 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_l_absw_dest_native]="0F0F0F0F $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_absl_dest_special_native]="A5A5000F $_OR_ZERO_TAIL 0000271F"
INIT_REGS[or_core_b_a7_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[or_core_b_a7_predec_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[or_core_b_ori_postinc_dest_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_postinc_dest_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[or_core_b_postinc_dest_noflags_native]="A5A5000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _OR_ZERO_TAIL
_SUB_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[sub_core_b_reg_zero_native]="A5A50001 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_reg_overflow_native]="A5A58000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_reg_borrow_native]="00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_self_alias_native]="A5A50080 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_w_self_alias_native]="A5A58000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_l_self_alias_native]="80000000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_imm_overflow_native]="A5A50080 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_w_imm_borrow_native]="A5A50000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_l_imm_large_native]="12345679 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_l_imm_negative_native]="00000000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_reg_noflags_native]="A5A50080 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_reg_noflags_native]="A5A58000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_reg_noflags_native]="80000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_imm_noflags_native]="A5A50080 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_w_imm_noflags_native]="A5A58000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_l_imm_noflags_native]="80000000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_aind_source_special_native]="A5A50080 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_postinc_source_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_predec_source_native]="80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_d16_source_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_index_source_special_native]="A5A58000 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_absw_source_native]="00000000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_absl_source_special_native]="A5A50000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_w_pc16_source_native]="A5A58000 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_l_pcindex_source_native]="00000000 FFFFFFEE 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_aind_dest_special_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_predec_dest_native]="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_d16_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_w_index_dest_special_native]="A5A50001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_l_absw_dest_native]="00000001 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_absl_dest_special_native]="A5A50001 $_SUB_ZERO_TAIL 0000271F"
INIT_REGS[sub_core_b_a7_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[sub_core_b_a7_predec_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[sub_core_b_subi_postinc_dest_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_postinc_dest_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[sub_core_b_postinc_dest_noflags_native]="A5A50001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _SUB_ZERO_TAIL
_ADDA_ZERO_D="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
_ADDA_ZERO_A_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[adda_core_w_dreg_positive_native]="00007FFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 10000000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_dreg_negative_native]="DEAD8000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 10000000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_dreg_wrap_native]="FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_areg_alias_native]="$_ADDA_ZERO_D 00008000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_areg_alias_native]="$_ADDA_ZERO_D 80000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_max_fields_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00008000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00020000 0000271F"
INIT_REGS[adda_core_w_imm_small_positive_native]="$_ADDA_ZERO_D 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_imm_small_negative_native]="$_ADDA_ZERO_D 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_imm_large_positive_native]="$_ADDA_ZERO_D 00010000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_imm_large_negative_native]="$_ADDA_ZERO_D 00010000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_imm_small_positive_native]="$_ADDA_ZERO_D 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_imm_small_negative_native]="$_ADDA_ZERO_D 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_imm_large_positive_native]="$_ADDA_ZERO_D 00000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_imm_large_negative_native]="$_ADDA_ZERO_D 00000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_const_dst_wrap]="$_ADDA_ZERO_D 00000000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_const_dst_wrap]="$_ADDA_ZERO_D 00000000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_aind_alias_native]="$_ADDA_ZERO_D 0000A000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_postinc_alias_native]="$_ADDA_ZERO_D 0000A000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_predec_alias_native]="$_ADDA_ZERO_D 0000A002 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_postinc_alias_native]="$_ADDA_ZERO_D 0000A000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_predec_alias_native]="$_ADDA_ZERO_D 0000A004 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_d16_source_native]="$_ADDA_ZERO_D 00001000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[adda_core_w_index_source_special_native]="00000000 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00010000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[adda_core_l_absw_source_native]="$_ADDA_ZERO_D 00000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_absl_source_special_native]="$_ADDA_ZERO_D 00000001 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_pc16_source_native]="$_ADDA_ZERO_D 00010000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_pcindex_source_native]="00000000 FFFFFFEE 00000000 00000000 00000000 00000000 00000000 00000000 FFFFFFFF $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_w_dreg_noflags_native]="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
INIT_REGS[adda_core_l_dreg_noflags_native]="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00001000 $_ADDA_ZERO_A_TAIL 0000271F"
unset _ADDA_ZERO_D _ADDA_ZERO_A_TAIL
_NEG_INIT_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[neg_b_zero_native]="A5A50000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_w_zero_native]="A5A50000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_b_one_native]="A5A50001 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_w_one_native]="A5A50001 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_b_min_overflow_native]="A5A50080 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_w_min_overflow_native]="A5A58000 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_b_minus_one_native]="A5A500FF $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_w_minus_one_native]="A5A5FFFF $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_b_min_nf_native]="A5A50080 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_w_min_nf_native]="A5A58000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_l_zero_native]="00000000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_l_one_native]="00000001 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_l_min_overflow_native]="80000000 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_l_minus_one_native]="FFFFFFFF $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_l_min_nf_native]="80000000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_b_aind_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[neg_w_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[neg_l_predec_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[neg_b_d16_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[neg_w_indexed_special_native]="A5A50000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[neg_l_absw_native]="00000000 $_NEG_INIT_ZERO_TAIL 00002700"
INIT_REGS[neg_b_absl_special_native]="A5A50000 $_NEG_INIT_ZERO_TAIL 0000271F"
INIT_REGS[neg_b_a7_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[neg_b_a7_predec_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 00002700"
unset _NEG_INIT_ZERO_TAIL
_NEGX_INIT_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
for _negx_width in b w; do
    INIT_REGS["negx_${_negx_width}_zero_x0_z1_native"]="A5A50000 $_NEGX_INIT_ZERO_TAIL 00002704"
    INIT_REGS["negx_${_negx_width}_zero_x0_z0_native"]="A5A50000 $_NEGX_INIT_ZERO_TAIL 00002700"
    INIT_REGS["negx_${_negx_width}_zero_x1_z1_native"]="A5A50000 $_NEGX_INIT_ZERO_TAIL 00002714"
done
INIT_REGS[negx_l_zero_x0_z1_native]="00000000 $_NEGX_INIT_ZERO_TAIL 00002704"
INIT_REGS[negx_l_zero_x0_z0_native]="00000000 $_NEGX_INIT_ZERO_TAIL 00002700"
INIT_REGS[negx_l_zero_x1_z1_native]="00000000 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_b_min_x0_overflow_native]="A5A50080 $_NEGX_INIT_ZERO_TAIL 00002704"
INIT_REGS[negx_w_min_x0_overflow_native]="A5A58000 $_NEGX_INIT_ZERO_TAIL 00002704"
INIT_REGS[negx_l_min_x0_overflow_native]="80000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 00002000 00002100 00002200 00002300 00002400 00002500 00002600 007EFF00 00002704"
INIT_REGS[negx_b_min_x1_native]="A5A50080 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_w_min_x1_native]="A5A58000 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_l_min_x1_native]="80000000 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_b_min_x1_nf_native]="A5A50080 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_w_min_x1_nf_native]="A5A58000 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_l_min_x1_nf_native]="80000000 $_NEGX_INIT_ZERO_TAIL 00002714"
INIT_REGS[negx_b_aind_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[negx_w_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[negx_l_predec_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[negx_b_d16_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[negx_w_indexed_special_native]="A5A50000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[negx_l_absw_native]="00000000 $_NEGX_INIT_ZERO_TAIL 00002704"
INIT_REGS[negx_b_absl_special_native]="A5A50000 $_NEGX_INIT_ZERO_TAIL 00002700"
INIT_REGS[negx_b_a7_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00002704"
INIT_REGS[negx_b_a7_predec_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 00002714"
unset _negx_width _NEGX_INIT_ZERO_TAIL
_TAS_INIT_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[tas_b_d0_zero_x0_native]="A5A50000 $_TAS_INIT_ZERO_TAIL 0000270F"
INIT_REGS[tas_b_d0_zero_x1_native]="A5A50000 $_TAS_INIT_ZERO_TAIL 0000271F"
INIT_REGS[tas_b_d0_positive_x1_native]="A5A5007F $_TAS_INIT_ZERO_TAIL 0000271F"
INIT_REGS[tas_b_d0_negative_x0_native]="A5A50080 $_TAS_INIT_ZERO_TAIL 00002707"
INIT_REGS[tas_b_aind_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[tas_b_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[tas_b_predec_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A001 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002707"
INIT_REGS[tas_b_d16_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[tas_b_indexed_special_native]="A5A50000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000270F"
INIT_REGS[tas_b_absw_native]="A5A50000 $_TAS_INIT_ZERO_TAIL 0000271F"
INIT_REGS[tas_b_absl_special_native]="A5A50000 $_TAS_INIT_ZERO_TAIL 0000271F"
INIT_REGS[tas_b_a7_postinc_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[tas_b_a7_predec_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 00002707"
unset _TAS_INIT_ZERO_TAIL

_SCC_DREG_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[scc_core_tf_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 0000271F"
INIT_REGS[scc_core_hi_ls_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 00002710"
INIT_REGS[scc_core_cc_cs_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 00002714"
INIT_REGS[scc_core_ne_eq_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 00002718"
INIT_REGS[scc_core_vc_vs_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 00002711"
INIT_REGS[scc_core_pl_mi_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 00002712"
INIT_REGS[scc_core_ge_lt_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 0000271A"
INIT_REGS[scc_core_gt_le_dreg_native]="A5A50000 B6B600FF $_SCC_DREG_TAIL 0000271A"
unset _SCC_DREG_TAIL
INIT_REGS[scc_core_aind_hi_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002710"
INIT_REGS[scc_core_postinc_t_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[scc_core_predec_f_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A001 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[scc_core_d16_eq_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[scc_core_index_vs_special_native]="A5A50000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002712"
INIT_REGS[scc_core_absw_mi_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002718"
INIT_REGS[scc_core_absl_gt_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271A"
INIT_REGS[scc_core_a7_postinc_t_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[scc_core_a7_predec_f_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"

_BCC_INIT_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A100 0000A200 00000000 00000000 00000000 00000000 007EFF00"
for _bcc_name in bcc_core_hi_taken_b_native bcc_core_ls_not_taken_b_native bcc_core_cc_taken_b_native bcc_core_cs_not_taken_b_native bcc_core_ne_taken_b_native bcc_core_eq_not_taken_b_native bcc_core_vc_taken_b_native bcc_core_vs_not_taken_b_native bcc_core_pl_taken_b_native bcc_core_mi_not_taken_b_native bcc_core_ge_taken_b_native bcc_core_lt_not_taken_b_native bcc_core_gt_taken_b_native bcc_core_le_not_taken_b_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 00002710"; done
for _bcc_name in bcc_core_hi_not_taken_b_native bcc_core_ls_taken_b_native bcc_core_cc_not_taken_b_native bcc_core_cs_taken_b_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 00002711"; done
for _bcc_name in bcc_core_ne_not_taken_b_native bcc_core_eq_taken_b_native bcc_core_gt_not_taken_b_native bcc_core_le_taken_b_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 00002714"; done
for _bcc_name in bcc_core_vc_not_taken_b_native bcc_core_vs_taken_b_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 00002712"; done
for _bcc_name in bcc_core_pl_not_taken_b_native bcc_core_mi_taken_b_native bcc_core_ge_not_taken_b_native bcc_core_lt_taken_b_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 00002718"; done
for _bcc_name in bcc_core_bra_b_forward_native bcc_core_bra_w_forward_native bcc_core_bra_l_forward_native; do INIT_REGS["$_bcc_name"]="00000000 $_BCC_INIT_TAIL 0000271F"; done
for _bcc_name in bcc_core_bne_b_backward_native bcc_core_bne_w_backward_native bcc_core_bne_l_backward_native; do INIT_REGS["$_bcc_name"]="00000002 $_BCC_INIT_TAIL 00002710"; done
unset _bcc_name _BCC_INIT_TAIL

_CLR_INIT_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000"
for _clr_name in clr_core_b_dreg_native clr_core_w_dreg_native clr_core_l_dreg_native clr_core_b_aind_special_native clr_core_w_postinc_native clr_core_l_predec_native clr_core_b_d16_native clr_core_l_absw_native clr_core_b_absl_special_native clr_core_b_a7_postinc_native clr_core_b_a7_predec_native; do INIT_REGS["$_clr_name"]="A5A5FFFF $_CLR_INIT_TAIL 0000271F"; done
INIT_REGS[clr_core_w_index_special_native]="A5A5FFFF 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[clr_core_b_postinc_successor_bne_native]="A5A5FFFF 11111111 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[clr_core_w_dreg_noflags_native]="A5A5FFFF $_CLR_INIT_TAIL 00002700"
INIT_REGS[clr_core_l_postinc_noflags_native]="A5A5FFFF $_CLR_INIT_TAIL 00002700"
unset _clr_name _CLR_INIT_TAIL

_EXG_INIT_FULL="11223344 AABBCCDD 22222222 33333333 44444444 55555555 66666666 77777777 0000A000 0000B000 0000C000 0000D000 0000E000 0000F500 0000A600 0000F700"
for _exg_name in exg_core_dn_dn_native exg_core_an_an_native exg_core_dn_an_native exg_core_dn_dn_self_native exg_core_an_an_self_native exg_core_dn_dn_max_native exg_core_an_an_max_native exg_core_dn_an_max_native exg_core_dn_dn_roundtrip_native exg_core_an_an_roundtrip_native exg_core_dn_an_roundtrip_native; do INIT_REGS["$_exg_name"]="$_EXG_INIT_FULL 0000271F"; done
INIT_REGS[exg_core_dn_an_noflags_native]="$_EXG_INIT_FULL 00002700"
unset _exg_name _EXG_INIT_FULL

_EXT_AREGS="0000A000 0000B000 0000C000 0000D000 0000E000 0000F000 0000A600 0000F000"
_EXT_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 $_EXT_AREGS"
INIT_REGS[ext_core_w_negative_native]="A5A50080 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_w_zero_native]="A5A50000 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_w_positive_native]="A5A5007F $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_w_max_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 77770080 $_EXT_AREGS 0000271F"
INIT_REGS[ext_core_l_negative_native]="A5A58000 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_l_zero_native]="A5A50000 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_l_positive_native]="A5A57FFF $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_l_max_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 77778000 $_EXT_AREGS 0000271F"
INIT_REGS[extb_core_l_negative_native]="A5A50080 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[extb_core_l_zero_native]="A5A50000 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[extb_core_l_positive_native]="A5A5007F $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[extb_core_l_max_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 77770080 $_EXT_AREGS 0000271F"
INIT_REGS[ext_core_wl_chain_negative_native]="A5A50080 $_EXT_ZERO_TAIL 0000271F"
INIT_REGS[ext_core_w_noflags_native]="A5A50080 $_EXT_ZERO_TAIL 00002700"
INIT_REGS[ext_core_l_noflags_native]="A5A58000 $_EXT_ZERO_TAIL 00002700"
INIT_REGS[extb_core_l_noflags_native]="A5A50080 $_EXT_ZERO_TAIL 00002700"
unset _EXT_AREGS _EXT_ZERO_TAIL

_DBCC_INIT_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A100 0000A200 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[dbcc_core_dbt_true_native]="A5A50001 $_DBCC_INIT_TAIL 0000271F"
INIT_REGS[dbcc_core_dbf_terminal_native]="A5A50000 $_DBCC_INIT_TAIL 0000271F"
INIT_REGS[dbcc_core_dbf_branch_native]="A5A50001 $_DBCC_INIT_TAIL 0000271F"
INIT_REGS[dbcc_core_dbf_wrap_native]="A5A5FFFF $_DBCC_INIT_TAIL 0000271F"
INIT_REGS[dbcc_core_hi_true_native]="A5A50001 $_DBCC_INIT_TAIL 00002710"
INIT_REGS[dbcc_core_ls_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 00002710"
INIT_REGS[dbcc_core_cc_true_native]="A5A50001 $_DBCC_INIT_TAIL 00002714"
INIT_REGS[dbcc_core_cs_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 00002714"
INIT_REGS[dbcc_core_ne_true_native]="A5A50001 $_DBCC_INIT_TAIL 00002718"
INIT_REGS[dbcc_core_eq_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 00002718"
INIT_REGS[dbcc_core_vc_true_native]="A5A50001 $_DBCC_INIT_TAIL 00002711"
INIT_REGS[dbcc_core_vs_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 00002711"
INIT_REGS[dbcc_core_pl_true_native]="A5A50001 $_DBCC_INIT_TAIL 00002712"
INIT_REGS[dbcc_core_mi_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 00002712"
INIT_REGS[dbcc_core_ge_true_native]="A5A50001 $_DBCC_INIT_TAIL 0000271A"
INIT_REGS[dbcc_core_lt_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 0000271A"
INIT_REGS[dbcc_core_gt_true_native]="A5A50001 $_DBCC_INIT_TAIL 0000271A"
INIT_REGS[dbcc_core_le_false_branch_native]="A5A50001 $_DBCC_INIT_TAIL 0000271A"
unset _DBCC_INIT_TAIL

_BITOP_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[bitop_core_btst_dyn_l_count63_native]="80000000 0000003F $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_btst_imm_l_count63_native]="00000000 00000000 $_BITOP_ZERO_TAIL 0000271B"
INIT_REGS[bitop_core_bchg_dyn_l_alias_native]="A5A5001F 00000000 $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_bchg_imm_l_bit31_native]="25A5001F 00000000 $_BITOP_ZERO_TAIL 0000271B"
INIT_REGS[bitop_core_bclr_dyn_l_count32_native]="A5A50001 00000020 $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_bclr_imm_l_bit31_noflags_native]="00000000 00000000 $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_bset_dyn_l_count63_native]="25A5001F 0000003F $_BITOP_ZERO_TAIL 0000271B"
INIT_REGS[bitop_core_bset_imm_l_bit0_native]="A5A50001 00000000 $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_bchg_dyn_l_distinct_native]="A5A50001 00000020 $_BITOP_ZERO_TAIL 0000271F"
INIT_REGS[bitop_core_bset_dyn_l_alias_native]="00000005 00000000 $_BITOP_ZERO_TAIL 0000271B"
unset _BITOP_ZERO_TAIL

INIT_REGS[bitop_core_bchg_imm_aind_zero_special_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bchg_imm_aind_one_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_bclr_dyn_postinc_zero_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bclr_dyn_predec_one_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A001 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_bset_imm_d16_zero_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bset_dyn_index_one_special_native]="A5A50000 00000002 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_bchg_dyn_absw_zero_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bclr_imm_absl_one_special_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_bset_dyn_a7_postinc_zero_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271B"
INIT_REGS[bitop_core_bchg_dyn_a7_predec_one_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 0000271F"
INIT_REGS[bitop_core_btst_dyn_aind_set_special_native]="00000007 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_btst_imm_d16_zero_native]="00000000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bchg_imm_aind_noflags_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_bset_imm_pc_d16_zero_native]="A5A50000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_bclr_dyn_pc_index_one_native]="A5A50000 FFFFFFEE 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_btst_imm_pc_d16_set_native]="00000000 00000000 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[bitop_core_btst_dyn_pc_index_zero_native]="00000007 FFFFFFEE 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_btst_imm_destination_zero_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271B"
INIT_REGS[bitop_core_btst_dyn_destination_set_native]="00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"

_CMP_REG_TAIL="22222222 33333333 44444444 55555555 66666666 77777777"
_CMP_A_TAIL="00002200 00002300 00002400 00002500 00002600 007EFF00 0000271F"
INIT_REGS[cmp_core_b_reg_borrow_native]="A5A50000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_w_reg_overflow_native]="A5A58000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_reg_alias_equal_native]="80000000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_b_imm_const_overflow_native]="00000000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_w_imm_runtime_overflow_native]="A5A58000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_imm_const_overflow_native]="00000000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_reg_distinct_borrow_native]="00000000 FFFFFFFF $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_b_aind_special_native]="A5A5007F 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_w_postinc_native]="A5A58000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_predec_native]="00000000 00000001 $_CMP_REG_TAIL 0000A004 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_b_d16_native]="A5A50000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_w_index_special_native]="A5A57FFF 00000002 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_absw_native]="00000000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_b_absl_special_native]="A5A5007F 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_w_pc_d16_native]="A5A58000 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_l_pc_index_native]="00000000 FFFFFFEE $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmp_core_b_postinc_noflags_native]="A5A5007F 00000001 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_b_distinct_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_w_distinct_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_l_distinct_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_b_same_a0_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_b_same_a7_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 00002200 00002300 00002400 00002500 00002600 0000A000 0000271F"
INIT_REGS[cmpm_core_w_special_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpm_core_l_noflags_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_w_imm_negative_native]="A5A50000 11111111 $_CMP_REG_TAIL 00000000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_w_postinc_alias_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_w_d16_negative_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 00007FFF $_CMP_A_TAIL"
INIT_REGS[cmpa_core_l_areg_alias_native]="A5A50000 11111111 $_CMP_REG_TAIL 80000000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_l_aind_special_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 00000000 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_w_pc_index_native]="A5A50000 FFFFFFEE $_CMP_REG_TAIL 00000000 0000A100 $_CMP_A_TAIL"
INIT_REGS[cmpa_core_l_postinc_noflags_native]="A5A50000 11111111 $_CMP_REG_TAIL 0000A000 0000A100 $_CMP_A_TAIL"
unset _CMP_REG_TAIL _CMP_A_TAIL

_MOVE_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[move_core_b_reg_negative_native]="A5A50000 00000080 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_b_reg_zero_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_w_reg_negative_native]="A5A50000 00008001 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_w_reg_zero_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_l_reg_negative_native]="A5A50000 80000001 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_l_reg_zero_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_b_self_alias_native]="A5A50080 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_w_self_alias_native]="A5A58001 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_b_imm_negative_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_w_imm_negative_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[move_core_l_imm_zero_native]="A5A50000 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[mov_l_rr_self_native]="DEADBEEF 00000000 $_MOVE_ZERO_TAIL 00002717"
INIT_REGS[mov_l_rr_const_movea_native]="00000000 00000000 $_MOVE_ZERO_TAIL 0000271F"
INIT_REGS[move_core_b_aind_to_dn_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_w_postinc_to_dn_native]="A5A5BEEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_predec_to_dn_native]="A5A5BEEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 0000A004 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_d16_to_dn_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_w_index_to_dn_special_native]="A5A50000 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_absw_to_dn_native]="A5A5BEEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_absl_to_dn_special_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_w_pc16_to_dn_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_pcindex_to_dn_native]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_dn_to_aind_special_native]="A5A50080 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_w_dn_to_postinc_native]="A5A58001 11110000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_dn_to_predec_native]="DEADBEEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A004 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_dn_to_d16_native]="A5A5007F 11110000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_w_dn_to_index_special_native]="A5A58001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_dn_to_absw_native]="DEADBEEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_dn_to_absl_special_native]="A5A50080 11110000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_areg_postinc_alias_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_l_memmem_postinc_alias_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002717"
INIT_REGS[move_core_b_a7_postinc_dst_native]="A5A50080 11110000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00002717"
INIT_REGS[move_core_b_a7_postinc_src_native]="A5A500FF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00002717"
unset _MOVE_ZERO_TAIL

_MOVEA_ZERO_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[movea_core_w_dreg_native]="12348001 00000000 $_MOVEA_ZERO_TAIL 0000271F"
INIT_REGS[movea_core_w_imm_native]="00000000 00000000 $_MOVEA_ZERO_TAIL 0000271F"
INIT_REGS[movea_core_l_dreg_native]="DEADBEEF 00000000 $_MOVEA_ZERO_TAIL 0000271F"
INIT_REGS[movea_core_w_aind_special_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[movea_core_w_postinc_alias_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[movea_core_w_predec_alias_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A002 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[movea_core_l_postinc_alias_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[movea_core_l_a7_postinc_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 0000271F"
INIT_REGS[movea_core_w_index_special_native]="00000000 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00002000 0000A000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[movea_core_w_pc16_native]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
unset _MOVEA_ZERO_TAIL

_MOVE16_DREGS="00000000 00000000 00000000 00000000 44440000 00000000 00000000 00000000"
_MOVE16_A2_TAIL="00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[move16_core_postinc_to_absl_native]="$_MOVE16_DREGS 0000A003 00000000 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_absl_to_postinc_native]="$_MOVE16_DREGS 00000000 0000B007 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_aind_to_absl_native]="$_MOVE16_DREGS 0000A003 00000000 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_absl_to_aind_native]="$_MOVE16_DREGS 00000000 0000B007 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_postpost_distinct_native]="$_MOVE16_DREGS 0000A003 0000B007 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_postpost_same_native]="$_MOVE16_DREGS 0000A003 00000000 $_MOVE16_A2_TAIL 0000271F"
INIT_REGS[move16_core_postpost_special_native]="$_MOVE16_DREGS 0000A003 0000B007 $_MOVE16_A2_TAIL 0000271F"
unset _MOVE16_DREGS _MOVE16_A2_TAIL

# Exact-anchor replay skips each setup prefix, so restore the audited operands
# explicitly rather than collapsing every pre-existing CHK.W case to 0 <= 0.
INIT_REGS[chk_w_in_range]="00000008 00000014 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[chk_w_zero]="00000000 00000064 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[chk_w_equal]="00000032 00000032 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[chk_w_negative_trap_n]="FFFFFFFF 00000014 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[chk_w_upper_trap_n_clear]="00000015 00000014 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271D"
INIT_REGS[chk_l_negative_trap_n]="FFFFFFFF 00000014 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[chk_l_upper_trap_n_clear]="00010000 0000FFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271D"
INIT_REGS[chk_l_in_range_preserve_ccr]="00010000 00020000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271D"
INIT_REGS[divu_w_zero_frame]="12345678 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_w_zero_frame]="87654321 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_w_overflow_preserve_z]="00010000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_w_imm_overflow_preserve_z]="00010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
_SHIFT_COUNT32_INIT_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[asl_b_reg_count32_boundary]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_w_reg_count32_boundary]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_count32_boundary]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_zero_count32_v_clear]="00000000 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_zero_count32_const_v_clear]="DEADBEEF 00000001 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_b_reg_zero_count63_v_clear]="A5A50000 0000003F $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_w_reg_zero_count33_v_clear]="A5A50000 00000021 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_b_reg_count32_boundary]="A5A5007F 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_w_reg_count32_boundary]="A5A57FFF 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_l_reg_count32_boundary]="7FFFFFFF 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_b_reg_count32_boundary]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_w_reg_count32_boundary]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_l_reg_count32_boundary]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_b_reg_count32_boundary]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_w_reg_count32_boundary]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_count32_boundary]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_count33_boundary]="80000001 00000021 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_const_count32]="DEADBEEF 00000001 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_b_reg_count32_nf]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_w_reg_count32_nf]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_count32_nf]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_b_reg_count32_nf]="A5A5007F 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_w_reg_count32_nf]="A5A57FFF 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_l_reg_count32_nf]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_b_reg_count32_nf]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_w_reg_count32_nf]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_l_reg_count32_nf]="00000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_b_reg_count32_nf]="A5A50081 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_w_reg_count32_nf]="A5A58001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_count32_nf]="80000001 00000020 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_b_reg_same_count_data]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_w_reg_same_count_data]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_same_count_data]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_b_reg_same_count_data]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_w_reg_same_count_data]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_l_reg_same_count_data]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_b_reg_same_count_data]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_w_reg_same_count_data]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_l_reg_same_count_data]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_b_reg_same_count_data]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_w_reg_same_count_data]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_same_count_data]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_b_reg_same_count_data_nf]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_w_reg_same_count_data_nf]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asl_l_reg_same_count_data_nf]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_b_reg_same_count_data_nf]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_w_reg_same_count_data_nf]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[asr_l_reg_same_count_data_nf]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_b_reg_same_count_data_nf]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_w_reg_same_count_data_nf]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsl_l_reg_same_count_data_nf]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_b_reg_same_count_data_nf]="A5A500A1 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_w_reg_same_count_data_nf]="A5A58021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[lsr_l_reg_same_count_data_nf]="80000021 00000000 $_SHIFT_COUNT32_INIT_TAIL"
declare -A _SHIFT_BOUNDARY_INIT_DATA=(
    [b]=A5A50081 [w]=A5A58001 [l]=80000001
)
for _shift_op in asl asr lsl lsr; do
    for _shift_width in b w l; do
        for _shift_count in 31 33 63; do
            printf -v _shift_count_init '%08X' "$_shift_count"
            _shift_name="${_shift_op}_${_shift_width}_reg_count${_shift_count}_boundary"
            _shift_init="${_SHIFT_BOUNDARY_INIT_DATA[$_shift_width]} ${_shift_count_init} $_SHIFT_COUNT32_INIT_TAIL"
            INIT_REGS["$_shift_name"]="$_shift_init"
            INIT_REGS["${_shift_name}_nf"]="$_shift_init"
        done
    done
done
unset _shift_op _shift_width _shift_count _shift_count_init _shift_name _shift_init
unset _SHIFT_BOUNDARY_INIT_DATA
declare -A _ROTATE_REGISTER_INIT_DATA=(
    [b]=A5A50081 [w]=A5A58001 [l]=80000001
)
declare -A _ROTATE_ALIAS_INIT_DATA=(
    [b]=A5A500A1 [w]=A5A58021 [l]=80000021
)
INIT_REGS[rol_l_reg_const_count64]="80000001 00000040 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[rol_l_reg_const_count64_nf]="80000001 00000040 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[ror_l_reg_const_count64]="80000001 00000040 $_SHIFT_COUNT32_INIT_TAIL"
INIT_REGS[ror_l_reg_const_count64_nf]="80000001 00000040 $_SHIFT_COUNT32_INIT_TAIL"
for _rotate_op in rol ror; do
    for _rotate_width in b w l; do
        case "$_rotate_width" in
            b) _rotate_immediate_data=A5A50081 ;;
            w) _rotate_immediate_data=A5A58001 ;;
            l) _rotate_immediate_data=80000001 ;;
        esac
        _rotate_immediate_name="${_rotate_op}_${_rotate_width}_imm_count8"
        _rotate_immediate_init="${_rotate_immediate_data} 00000000 $_SHIFT_COUNT32_INIT_TAIL"
        INIT_REGS["$_rotate_immediate_name"]="$_rotate_immediate_init"
        INIT_REGS["${_rotate_immediate_name}_nf"]="$_rotate_immediate_init"
    done
done
_ROTATE_MEMORY_INIT="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[rolw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[rolw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[rorw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[rorw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[aslw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[aslw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[asrw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[asrw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[lslw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[lslw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[lsrw_mem_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[lsrw_mem_native_nf]="$_ROTATE_MEMORY_INIT"
INIT_REGS[roxlw_mem_x_native]="$_ROTATE_MEMORY_INIT"
INIT_REGS[roxrw_mem_x_native]="$_ROTATE_MEMORY_INIT"
unset _rotate_op _rotate_width _rotate_immediate_data _rotate_immediate_name _rotate_immediate_init _ROTATE_MEMORY_INIT
for _rotate_op in rol ror; do
    for _rotate_width in b w l; do
        for _rotate_count in 0 31 32 33 63; do
            printf -v _rotate_count_init '%08X' "$_rotate_count"
            _rotate_name="${_rotate_op}_${_rotate_width}_reg_count${_rotate_count}_boundary"
            _rotate_init="${_ROTATE_REGISTER_INIT_DATA[$_rotate_width]} ${_rotate_count_init} $_SHIFT_COUNT32_INIT_TAIL"
            INIT_REGS["$_rotate_name"]="$_rotate_init"
            INIT_REGS["${_rotate_name}_nf"]="$_rotate_init"
        done
        _rotate_alias_name="${_rotate_op}_${_rotate_width}_reg_same_count_data"
        _rotate_alias_init="${_ROTATE_ALIAS_INIT_DATA[$_rotate_width]} 00000000 $_SHIFT_COUNT32_INIT_TAIL"
        INIT_REGS["$_rotate_alias_name"]="$_rotate_alias_init"
        INIT_REGS["${_rotate_alias_name}_nf"]="$_rotate_alias_init"
    done
done
unset _rotate_op _rotate_width _rotate_count _rotate_count_init _rotate_name _rotate_init
unset _rotate_alias_name _rotate_alias_init _ROTATE_REGISTER_INIT_DATA _ROTATE_ALIAS_INIT_DATA
unset _SHIFT_COUNT32_INIT_TAIL
INIT_REGS[divu_l_zero_frame]="13579BDF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_l_zero_frame]="89ABCDEF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divu_l32_zero_distinct]="13579BDF 00000000 2468ACE0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_l32_zero_distinct]="89ABCDEF 00000000 76543210 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divu_l32_success_nf]="00000064 00000007 A5A55A5A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l32_success_nf]="FFFFFF9C 00000007 A5A55A5A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divu_l32_same_dq_dr_nf]="00000064 00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l32_same_dq_dr_nf]="FFFFFF9C 00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divu_l32_src_dr_alias_nf]="00000064 00000000 00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l32_src_dr_alias_nf]="FFFFFF9C 00000000 00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divu_l64_zero_frame]="00000000 00000000 13579BDF 2468ACE0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_l64_zero_frame]="00000000 00000000 89ABCDEF FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divu_l64_same_dq_dr]="00000001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_l64_same_dq_dr]="FFFFFFFF 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divu_l64_same_dq_dr_nf]="00000001 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divs_l64_same_dq_dr_nf]="FFFFFFFF 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[divu_l64_overflow]="00000000 00000001 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divu_l64_overflow_nf]="00000000 00000001 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l64_overflow]="80000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l64_overflow_nf]="80000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l32_overflow]="80000000 FFFFFFFF 12345678 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[divs_l32_overflow_nf]="80000000 FFFFFFFF 12345678 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002715"
INIT_REGS[trapv_taken_frame]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271F"
INIT_REGS[trapv_not_taken_preserve]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 0000271D"
# Exact-opcode BCD replays bypass each setup prefix. Restore the operands, X/Z
# state, address registers, and (for predecrement forms) the pre-access EA.
INIT_REGS[bcd_abcd_zero_sticky_set]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_abcd_zero_sticky_clear]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_abcd_nonzero_clears_sticky]="00000001 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_abcd_carry_zero]="00000099 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_abcd_same_reg_with_x]="A5A50099 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[bcd_sbcd_zero_sticky_set]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_sbcd_zero_sticky_clear]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_sbcd_borrow]="00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_sbcd_same_reg_with_x]="A5A50000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[bcd_nbcd_zero_sticky_set]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_nbcd_zero_sticky_clear]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_nbcd_nonzero]="00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_nbcd_with_x]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[bcd_abcd_decimal_09_plus_01]="00000009 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_abcd_invalid_nibble_exact]="0000000A 0000000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002710"
INIT_REGS[bcd_abcd_extend_chain]="00000099 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_sbcd_decimal_10_minus_01]="00000010 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_sbcd_invalid_nibble_exact]="00000000 0000000A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002710"
INIT_REGS[bcd_nbcd_decimal_10]="00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[bcd_nbcd_invalid_nibble_exact]="0000000A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002710"
INIT_REGS[bcd_abcd_predec_src_a7]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002041 00000000 00000000 00000000 00000000 00000000 00000000 00002082 00002704"
INIT_REGS[bcd_abcd_predec_dst_a7]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002081 00000000 00000000 00000000 00000000 00000000 00000000 00002042 00002704"
INIT_REGS[bcd_abcd_predec_a7_alias]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002084 00002704"
INIT_REGS[bcd_sbcd_predec_src_a7]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002041 00000000 00000000 00000000 00000000 00000000 00000000 00002082 00002704"
INIT_REGS[bcd_sbcd_predec_dst_a7]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002081 00000000 00000000 00000000 00000000 00000000 00000000 00002042 00002704"
INIT_REGS[bcd_sbcd_predec_a7_alias]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002084 00002704"
INIT_REGS[bcd_nbcd_predec_a7]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00002042 00002704"
INIT_REGS[bcd_native_abcd_zero_sticky]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002704"
INIT_REGS[bcd_native_abcd_invalid_extend]="0000000A 0000000F 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[bcd_native_sbcd_invalid_borrow]="00000000 0000000A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[bcd_native_nbcd_invalid_borrow]="0000000A 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002714"
INIT_REGS[mulls32_negative_fit_v_native]="00000002 FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_source_preserve_v_native]="00000002 FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_source_low_alias_native]="FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_same_result_alias_native]="00000002 FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu32_low_sign_full_flags_native]="80000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu32_overflow_low_zero_flags_native]="00010000 00010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mulls32_negative_overflow_low_zero_native]="00000002 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mulls32_positive_overflow_low_sign_native]="00000002 40000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mulls64_negative_flags_native]="000003E8 FFFFFF9C 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_zero_flags_native]="00001234 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_source_high_alias_native]="00000002 FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_all_alias_native]="FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu32_immediate_nf_native]="00000000 00000007 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[mullu64_memory_nf_native]="FFFFFFFF 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000A000 00000000 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
# MOVEM exact-anchor replay state. Setup prefixes still make the trace pass
# self-contained; these inputs recreate the architectural state at each family
# opcode so B2_NATIVE_ASSERT_PC proves the audited MOVEM itself enters natively.
_MOVEM_ZERO_D="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
_MOVEM_ZERO_A_TAIL="00000000 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[movem_l_postinc_base_alias_native]="$_MOVEM_ZERO_D 00003000 $_MOVEM_ZERO_A_TAIL 00002701"
INIT_REGS[movem_w_postinc_base_alias_native]="$_MOVEM_ZERO_D 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_l_predec_base_alias_native]="11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_w_predec_base_alias_native]="FFFF8001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_l_aind_load_base_alias_native]="$_MOVEM_ZERO_D 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_l_aind_store_base_alias_native]="11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00003000 22222222 00000000 00000000 00000000 00000000 00000000 007EFF00 00002700"
INIT_REGS[movem_zero_mask_native]="$_MOVEM_ZERO_D 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_l_control_modes_native]="11111111 22222222 00000000 00000000 00000000 00000000 00000000 00000000 00003000 $_MOVEM_ZERO_A_TAIL 00002700"
INIT_REGS[movem_l_pc_modes_native]="00000000 00000000 00000000 00000000 00002000 00000000 00000000 00000000 00003008 $_MOVEM_ZERO_A_TAIL 00002700"
unset _MOVEM_ZERO_D _MOVEM_ZERO_A_TAIL
MOVEM_ALL_LIVE_INIT="01010101 02020202 03030303 04040404 05050505 06060606 07070707 08080808 11111111 12121212 13131313 14141414 15151515 00003400 17171717 007EFF00 00002700"
INIT_REGS[movem_l_all_live_roundtrip_native]="$MOVEM_ALL_LIVE_INIT"
INIT_REGS[movem_l_all_live_special_native]="$MOVEM_ALL_LIVE_INIT"
unset MOVEM_ALL_LIVE_INIT
# Fuzz vector initial register states
INIT_REGS[io_byte_write_roundtrip]="00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 50001000 0A014100 00000000 00000000 00000000 00000000 00000000 007EFF00"
INIT_REGS[fuzz_alu_0]="8878FDF6 80000000 00000000 637A51D3 7FFFFFFF 00000000 000000FF FFFFFFFF 0038D748 007BBF88 003C4A38 0023044C 003974BC 00072334 00000000 007EFF00"
INIT_REGS[fuzz_shift_0]="7FFFFFFF FFFFFFFF 0000FFFF 000000FF FFFFFFFF 80000000 0000FFFF 6F01C50E 00124FD8 005EB90C 0032C4F4 006E747C 005771AC 002B43C0 00000000 007EFF00"
INIT_REGS[fuzz_bitops_0]="FFFFFFFF F567E951 3D5E6FD4 000000FF 10F5BF4D 7FFFFFFF 11D9AF43 75616BFD 001AAB38 00330250 0075C460 005CAF44 00439394 000B9E84 00000000 007EFF00"
INIT_REGS[fuzz_muldiv_0]="000000FF 00000000 FFFFFFFF 80000000 0000008E 0000760C CC333AE3 5CB9710E 0044EBD0 005ABBFC 00695CC8 007CE2A4 006C5B90 00733658 00000000 007EFF00"
INIT_REGS[fuzz_extswap_0]="7FFFFFFF A0635EFF 000000FF 80000000 00000000 00000000 7FFFFFFF 000000C5 006FADBC 006CCE54 00631828 00753CB8 000B9958 00570EEC 00000000 007EFF00"
INIT_REGS[fuzz_addxsubx_0]="7FFFFFFF 7FFFFFFF 00000000 000000F3 00000000 00000000 0000FFFF 80000000 0020F168 00580528 001E44E8 002F4F34 002C2B74 002D03EC 00000000 007EFF00"
INIT_REGS[fuzz_memrt_0]="7FFFFFFF BD92BE4B 00000000 FFFFFFFF A287EB05 55E7D610 000000FF 0000FFFF 00414E60 0051A0B8 007394F8 00694E60 0034DD04 0035BE6C 00000000 007EFF00"
INIT_REGS[fuzz_exg_0]="7FFFFFFF 00000000 000000FF 475A6474 0000008F FFFFFFFF AA6BA628 032BD4ED 002651D4 003F6728 003EFB14 0007632C 0014D140 005B2EBC 00000000 007EFF00"
INIT_REGS[fuzz_mixed_0]="00000000 0000FFFF 00000004 00000027 80000000 000000B8 DE82A945 0000FFFF 00341FB8 0002FB2C 001CBAC4 0056F5D0 003C7BDC 003F7804 00000000 007EFF00"
INIT_REGS[fuzz_flags_0]="80000000 80000000 000000C0 F311B6E1 0000FFFF 7FFFFFFF C91E5274 FFFFFFFF 0029D134 0063A530 006C413C 001FD270 0012EA80 0070F5E0 00000000 007EFF00"
INIT_REGS[fuzz_alu_1]="E8EE138F FFFFFFFF 80000000 0000FFFF 0000FFFF 80000000 E3BC7C50 59D6AAA6 00154C7C 0004F11C 002CAFE4 005FE0A8 000C3530 006C2ED8 00000000 007EFF00"
INIT_REGS[fuzz_shift_1]="00000000 00000000 FFFFFFFF 5448D078 0000FFFF FFFFFFFF FFFFFFFF B3497EB3 00590C00 0015C96C 00316E30 00378A68 003B0BF4 0026E3A0 00000000 007EFF00"
INIT_REGS[fuzz_bitops_1]="FFFFFFFF 00000000 00000000 0000007E 0000007D 4AB3775A FB60C0C3 0000FFFF 0009F9BC 003737C0 0044E830 0024A9C0 00339F64 00233F90 00000000 007EFF00"
INIT_REGS[fuzz_muldiv_1]="AEECBF29 80000000 80000000 FFFFFFFF 1BE0D930 0000B5C7 7FFFFFFF 00000000 003F05F0 0057A43C 00459DBC 000BB2C8 007ADE84 003AA810 00000000 007EFF00"
INIT_REGS[fuzz_extswap_1]="3EFDD522 00000036 80000000 6AF18701 80000000 FFFFFFFF 000000FF 0000FFFF 003AFDF8 00507248 0049E580 005FC27C 0015E3F0 00301E1C 00000000 007EFF00"
INIT_REGS[fuzz_addxsubx_1]="7FFFFFFF 80000000 00000062 0000004B 7FFFFFFF 87040427 7FFFFFFF A35154CE 00366F60 001A16F8 00724F4C 003DF7AC 004B7B40 0010FA88 00000000 007EFF00"
INIT_REGS[fuzz_memrt_1]="C245E710 3B4DA9EF 241620CC 7FFFFFFF FFFFFFFF 00000019 9DD3E198 00000000 001FD5F8 00142300 0079C99C 001DADC4 00585FB0 007A0C68 00000000 007EFF00"
INIT_REGS[fuzz_exg_1]="00000000 0000FFFF 7FFFFFFF 00000000 0000FFFF 0000FFFF 00000000 000000BC 0031A1B8 003EF580 00459FE4 0006BD90 002F6B80 0009D460 00000000 007EFF00"
INIT_REGS[fuzz_mixed_1]="00000000 80000000 7FFFFFFF 00000000 0000FFFF 00000000 000000FF 80000000 0078F5DC 001F065C 0010F264 0032D7D0 005F0B0C 003E697C 00000000 007EFF00"
INIT_REGS[fuzz_flags_1]="C04533B9 00000000 4689409F 00000005 00000000 0B795496 CEF18F0E FACF15E9 00124C74 00566848 0062A114 002740D0 005BC32C 002C2150 00000000 007EFF00"
INIT_REGS[fuzz_alu_2]="2BB84DD1 7FFFFFFF 0000FFFF B88D9738 00000000 FFFFFFFF 00000041 80000000 00361470 001D1ACC 007E2F9C 003AE218 0040B090 00585EB0 00000000 007EFF00"
INIT_REGS[fuzz_shift_2]="0000FFFF BE83F4AB 00000000 80000000 00000000 80000000 80000000 00000000 0077A1E4 00247BD8 004BED8C 00286964 002BADC4 007D41D8 00000000 007EFF00"
INIT_REGS[fuzz_bitops_2]="80000000 FFFFFFFF FFFFFFFF 00000023 80000000 7FFFFFFF 0000FFFF 00000084 005B7F3C 0005EE58 00781E7C 0024174C 000AA384 007B0B00 00000000 007EFF00"
INIT_REGS[fuzz_muldiv_2]="0000FFFF 000000D4 595124DA 7FFFFFFF 0000D55A 0000007C 2E24CEC1 4C0F0F27 00007C30 003F3944 00351CB0 003656C0 003F1824 005E60B0 00000000 007EFF00"
INIT_REGS[fuzz_extswap_2]="80000000 000000FF 4FC1F43B F26435A8 0000FFFF 7FFFFFFF 00000000 000000FF 0014FBA8 005800A0 0008C620 00080578 006D2B98 007422E8 00000000 007EFF00"
INIT_REGS[fuzz_addxsubx_2]="02C481F3 6A4AE5AD 80000000 95EAD6BA 7FFFFFFF 0000FFFF 677BE43B 9A6E70E5 000479F0 006C80F8 00104B8C 0028EC7C 006CE61C 0061BA50 00000000 007EFF00"
INIT_REGS[fuzz_memrt_2]="7FFFFFFF 000000FF FFFFFFFF 000000BC 7FFFFFFF 00000000 A08A2385 AD0C4765 0020B96C 00555408 00196114 004B94E4 006E5368 006ACC94 00000000 007EFF00"
INIT_REGS[fuzz_exg_2]="00000000 00000000 80000000 07465B1C 00000000 0000FFFF 00000085 DAA4134D 002AF0EC 00639414 0024E28C 0076C624 00540F70 0025AF44 00000000 007EFF00"
INIT_REGS[fuzz_mixed_2]="00000000 000000FF FFFFFFFF 0000FFFF 7FFFFFFF 03465513 221C64EA 80000000 007B34B4 0039DAA4 004F6F20 00114818 005A2644 00797148 00000000 007EFF00"
INIT_REGS[fuzz_flags_2]="0000FFFF 00000000 C459EA3A 80000000 00000000 1136C00B A6B7D7DE 00000000 004935D0 007DC188 00458580 002328E4 003E2864 003309CC 00000000 007EFF00"
INIT_REGS[fuzz_alu_3]="00000067 000000B7 7FFFFFFF 9B0B8017 0000FFFF 80000000 7FFFFFFF D03FF5DA 0044C65C 0072C5E0 0048C79C 006E0518 0008DCA0 0070FEDC 00000000 007EFF00"
INIT_REGS[fuzz_shift_3]="0BDBFE50 FFFFFFFF 00000000 7FFFFFFF 47D43365 E08347E3 7FFFFFFF 927EE333 00689DB8 000FAA94 0067413C 000B56DC 0016EE04 0040835C 00000000 007EFF00"
INIT_REGS[fuzz_bitops_3]="88596DE9 FFFFFFFF 7FFFFFFF FFFFFFFF 7FFFFFFF F86E8FA7 BA114E62 7FFFFFFF 006B6D30 000C73C4 003BE184 0002C488 004BAF8C 000E54E0 00000000 007EFF00"
INIT_REGS[fuzz_muldiv_3]="80000000 000000FF 00000000 7FFFFFFF 00005110 7AB04BDC 3ECFA952 BC405280 00276380 003D79B4 002DF3C0 006257D4 004A3988 00261688 00000000 007EFF00"
INIT_REGS[fuzz_extswap_3]="0000FFFF 00000036 FFFFFFFF 7FFFFFFF 00000000 0000FFFF 000000FF 00000055 004335E0 0002A388 007287C8 00584D40 00339710 00520748 00000000 007EFF00"
INIT_REGS[fuzz_addxsubx_3]="FFFFFFFF FFFFFFFF 5AB0C8C7 0000FFFF FFFFFFFF 0000007B 00000000 FFFFFFFF 00043CDC 000A0C4C 00050074 00132CCC 00135EA4 00761FA4 00000000 007EFF00"
INIT_REGS[fuzz_memrt_3]="000000FF 092D6826 00000000 1B613295 FFFFFFFF 000000FF 39374372 00000000 00216324 007097F8 006063B8 007D5844 00112DB4 000BD0E8 00000000 007EFF00"
INIT_REGS[fuzz_exg_3]="897A1A19 80000000 80000000 7FFFFFFF 00000000 7FFFFFFF 58FD46B7 80000000 0017F2C0 00627BF8 005773EC 0005FFBC 001F4DAC 005CF8E8 00000000 007EFF00"
INIT_REGS[fuzz_mixed_3]="FFFFFFFF 00000000 000000FF 00000000 7FFFFFFF 0000FFFF 000000D5 7FFFFFFF 00031B6C 007706C4 000EB344 0011D03C 0004937C 0064B398 00000000 007EFF00"
INIT_REGS[fuzz_flags_3]="93FDE8D8 7FFFFFFF 7FFFFFFF 000000FF FFFFFFFF 00000000 0000FFFF E3976C1E 005F2C8C 001AA328 00402EB0 0079B354 003C55A4 004E5DC4 00000000 007EFF00"
INIT_REGS[fuzz_alu_4]="E814971D 00000022 FFFFFFFF 00000000 7FFFFFFF 00000001 0B8E2A96 D15F0551 004CE140 005C15AC 002152BC 00078ADC 00138CE0 001222EC 00000000 007EFF00"
INIT_REGS[fuzz_shift_4]="80000000 00000000 FFFFFFFF 000000E9 DCFDF7CF 00000000 CDD2AB32 0000FFFF 00439B04 002F7E14 006D7A70 0061AE70 0077845C 00673AB8 00000000 007EFF00"
INIT_REGS[fuzz_bitops_4]="80000000 4C01E224 00000000 00000000 000000FF 1ABCB699 00000000 000000FF 006DEDC8 00458F14 005E8554 00404918 00393DDC 0030DC8C 00000000 007EFF00"
INIT_REGS[fuzz_muldiv_4]="000000FF 000000FF 7FFFFFFF 000000B0 FFFFFFFF 0000B35A 00000000 E8863BAD 000BB0E8 003FDE68 0056BB90 003151B8 001B5728 0070AC64 00000000 007EFF00"
INIT_REGS[fuzz_extswap_4]="80000000 6361AA64 000000FF 0000FFFF 12047320 FFFFFFFF 80000000 7FFFFFFF 0044A034 0065CB9C 004A336C 0079B13C 0068E7C0 00074BD0 00000000 007EFF00"
INIT_REGS[fuzz_addxsubx_4]="23D01E2E 00000000 F7F440AC 7FFFFFFF 00000000 0000FFFF 000000FF CE808892 00214B28 004B1844 00144DC0 000F502C 002972A8 002DF22C 00000000 007EFF00"
INIT_REGS[fuzz_memrt_4]="000000FF 6B78D8FC 0000FFFF 0000FFFF 80000000 FA7FE2E8 000000FF FFFFFFFF 006F9C80 00347EAC 00527498 00467C38 003C6564 0014C494 00000000 007EFF00"
INIT_REGS[fuzz_exg_4]="000000FF 80000000 000000FF 68651AA6 80000000 000000FF FFFFFFFF 7FFFFFFF 0028E76C 001B17E4 003806E0 004FF650 005A19BC 00313940 00000000 007EFF00"
INIT_REGS[fuzz_mixed_4]="80000000 0000FFFF 80000000 9BA96951 7FFFFFFF 80000000 FFFFFFFF 7FFFFFFF 0005ADF8 0043FF50 0048CF98 00464810 0025684C 00195E8C 00000000 007EFF00"
INIT_REGS[fuzz_flags_4]="FFFFFFFF 00000000 000000FF 0000002F 00000000 35FDF202 FFFFFFFF 00000000 0025B20C 003BEC14 00482078 00628CFC 005D71F0 0057BB88 00000000 007EFF00"
SENTINEL_A6[nop]="a601005a"
SENTINEL_A6[nop_triplet]="a60100c2"
SENTINEL_A6[roxl_x_propagation]="a60100c3"
SENTINEL_A6[roxr_x_propagation]="a60100c4"
SENTINEL_A6[roxl_count_2]="a60100c5"
SENTINEL_A6[asl_overflow]="a60100c6"
SENTINEL_A6[lsr_count_32]="a60100c7"
SENTINEL_A6[asr_count_0]="a60100c8"
SENTINEL_A6[ror_word]="a60100c9"
SENTINEL_A6[rol_word]="a60100ca"
SENTINEL_A6[btst_reg_high_bit]="a60100cb"
SENTINEL_A6[btst_b_d16_highbit]="a6b7d160"
SENTINEL_A6[muls_neg_neg]="a60100cc"
SENTINEL_A6[muls_zero]="a60100cd"
SENTINEL_A6[divs_neg_neg]="a60100ce"
SENTINEL_A6[divs_overflow]="a60100cf"
SENTINEL_A6[abcd_basic]="a60100d0"
SENTINEL_A6[sbcd_basic]="a60100d1"
SENTINEL_A6[negx_with_x]="a60100d2"
SENTINEL_A6[negx_zero]="a60100d3"
_add_sentinel_id=1
for _add_name in "${ADD_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_add_name"] 'a6ad%04x' "$_add_sentinel_id"
    ((_add_sentinel_id+=1))
done
unset _add_name _add_sentinel_id
_and_sentinel_id=1
for _and_name in "${AND_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_and_name"] 'a6a4%04x' "$_and_sentinel_id"
    ((_and_sentinel_id+=1))
done
unset _and_name _and_sentinel_id
_eor_sentinel_id=1
for _eor_name in "${EOR_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_eor_name"] 'a6e4%04x' "$_eor_sentinel_id"
    ((_eor_sentinel_id+=1))
done
unset _eor_name _eor_sentinel_id
_or_sentinel_id=1
for _or_name in "${OR_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_or_name"] 'a6e0%04x' "$_or_sentinel_id"
    ((_or_sentinel_id+=1))
done
unset _or_name _or_sentinel_id
_sub_sentinel_id=1
for _sub_name in "${SUB_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_sub_name"] 'a6e5%04x' "$_sub_sentinel_id"
    ((_sub_sentinel_id+=1))
done
unset _sub_name _sub_sentinel_id
_adda_sentinel_id=1
for _adda_name in "${ADDA_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_adda_name"] 'a6da%04x' "$_adda_sentinel_id"
    ((_adda_sentinel_id+=1))
done
unset _adda_name _adda_sentinel_id
_bcc_sentinel_id=1
for _bcc_name in "${BCC_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_bcc_name"] 'a6bc%04x' "$_bcc_sentinel_id"
    ((_bcc_sentinel_id+=1))
done
unset _bcc_name _bcc_sentinel_id
_clr_sentinel_id=1
for _clr_name in "${CLR_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_clr_name"] 'a6c1%04x' "$_clr_sentinel_id"
    ((_clr_sentinel_id+=1))
done
unset _clr_name _clr_sentinel_id
_exg_sentinel_id=1
for _exg_name in "${EXG_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_exg_name"] 'a6e8%04x' "$_exg_sentinel_id"
    ((_exg_sentinel_id+=1))
done
unset _exg_name _exg_sentinel_id
_ext_sentinel_id=1
for _ext_name in "${EXT_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_ext_name"] 'a6e7%04x' "$_ext_sentinel_id"
    ((_ext_sentinel_id+=1))
done
unset _ext_name _ext_sentinel_id
_neg_sentinel_id=1
for _neg_name in "${NEG_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_neg_name"] 'a60f%04x' "$_neg_sentinel_id"
    ((_neg_sentinel_id+=1))
done
unset _neg_name _neg_sentinel_id
_negx_sentinel_id=1
for _negx_name in "${NEGX_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_negx_name"] 'a606%04x' "$_negx_sentinel_id"
    ((_negx_sentinel_id+=1))
done
unset _negx_name _negx_sentinel_id
_tas_sentinel_id=1
for _tas_name in "${TAS_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_tas_name"] 'a607%04x' "$_tas_sentinel_id"
    ((_tas_sentinel_id+=1))
done
unset _tas_name _tas_sentinel_id
_move_sentinel_id=1
for _move_name in "${MOVE_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_move_name"] 'a608%04x' "$_move_sentinel_id"
    ((_move_sentinel_id+=1))
done
unset _move_name _move_sentinel_id
_movea_sentinel_id=1
for _movea_name in "${MOVEA_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_movea_name"] 'a609%04x' "$_movea_sentinel_id"
    ((_movea_sentinel_id+=1))
done
unset _movea_name _movea_sentinel_id
_move16_sentinel_id=1
for _move16_name in "${MOVE16_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_move16_name"] 'a60a%04x' "$_move16_sentinel_id"
    ((_move16_sentinel_id+=1))
done
unset _move16_name _move16_sentinel_id
_scc_sentinel_id=1
for _scc_name in "${SCC_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_scc_name"] 'a60b%04x' "$_scc_sentinel_id"
    ((_scc_sentinel_id+=1))
done
unset _scc_name _scc_sentinel_id
_dbcc_sentinel_id=1
for _dbcc_name in "${DBCC_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_dbcc_name"] 'a60c%04x' "$_dbcc_sentinel_id"
    ((_dbcc_sentinel_id+=1))
done
unset _dbcc_name _dbcc_sentinel_id
_bitop_sentinel_id=1
for _bitop_name in "${BITOP_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_bitop_name"] 'a60d%04x' "$_bitop_sentinel_id"
    ((_bitop_sentinel_id+=1))
done
unset _bitop_name _bitop_sentinel_id
_cmp_sentinel_id=1
for _cmp_name in "${CMP_NATIVE_MATRIX_NAMES[@]}"; do
    printf -v SENTINEL_A6["$_cmp_name"] 'a60e%04x' "$_cmp_sentinel_id"
    ((_cmp_sentinel_id+=1))
done
unset _cmp_name _cmp_sentinel_id
SENTINEL_A6[addx_basic]="a60100d4"
SENTINEL_A6[subx_basic]="a60100d5"
SENTINEL_A6[ext_word]="a60100d6"
SENTINEL_A6[ext_long]="a60100d7"
SENTINEL_A6[move_to_mem_and_back]="a60100d8"
SENTINEL_A6[movem_predec_postinc]="a60100d9"
SENTINEL_A6[movem_no_writeback]="a6010201"
SENTINEL_A6[movem_predec_mixed_order]="a60100e8"
SENTINEL_A6[movem_l_postinc_base_alias_native]="a6050001"
SENTINEL_A6[movem_w_postinc_base_alias_native]="a6050002"
SENTINEL_A6[movem_l_predec_base_alias_native]="a6050003"
SENTINEL_A6[movem_w_predec_base_alias_native]="a6050004"
SENTINEL_A6[movem_l_aind_load_base_alias_native]="a6050005"
SENTINEL_A6[movem_l_aind_store_base_alias_native]="a6050006"
SENTINEL_A6[movem_l_all_live_roundtrip_native]="a6050007"
SENTINEL_A6[movem_l_all_live_special_native]="a6050008"
SENTINEL_A6[movem_zero_mask_native]="a6050009"
SENTINEL_A6[movem_l_control_modes_native]="a605000a"
SENTINEL_A6[movem_l_pc_modes_native]="a605000b"
SENTINEL_A6[addx_chain]="a60100da"
SENTINEL_A6[flag_chain_xzn]="a60100db"
SENTINEL_A6[shift_chain]="a60100dc"
SENTINEL_A6[roxl_reg_count_32]="a60100ec"
SENTINEL_A6[roxl_reg_count_33]="a60100ed"
SENTINEL_A6[roxr_reg_count_33]="a60100ea"
SENTINEL_A6[roxr_reg_count_32]="a60100eb"
SENTINEL_A6[roxr_reg_count_0]="a60100ee"
SENTINEL_A6[roxr_reg_count_0_copies_x]="a60100f3"
SENTINEL_A6[roxl_b_reg_count_63_copies_x]="a60100f4"
SENTINEL_A6[roxr_b_reg_count_63_copies_x]="a60100f5"
SENTINEL_A6[roxl_w_reg_count_51_copies_x]="a60100f6"
SENTINEL_A6[roxr_w_reg_count_51_copies_x]="a60100f7"
SENTINEL_A6[roxl_l_reg_count_33_copies_x]="a60100f8"
SENTINEL_A6[roxr_l_reg_count_33_copies_x]="a60100f9"
SENTINEL_A6[roxl_l_reg_count_0_copies_x]="a60100fa"
SENTINEL_A6[roxl_l_reg_count_33_pressure]="a60100fb"
SENTINEL_A6[roxr_l_reg_count_33_pressure]="a60100fc"
SENTINEL_A6[asr_l_reg_count0_pressure_preserves_x]="a6d6014b"
SENTINEL_A6[addx_b_zero_sticky_z_set]="a6030221"
SENTINEL_A6[addx_w_zero_sticky_z_set]="a6030222"
SENTINEL_A6[addx_b_zero_without_x_sticky_z_set]="a6030223"
SENTINEL_A6[addx_w_zero_without_x_sticky_z_set]="a6030224"
SENTINEL_A6[addx_l_zero_without_x_sticky_z_set]="a6030227"
SENTINEL_A6[roxl_l_zero_count_copies_cleared_x]="a6030228"
SENTINEL_A6[subx_b_zero_sticky_z_set]="a6030225"
SENTINEL_A6[subx_w_zero_sticky_z_set]="a6030226"
SENTINEL_A6[addx_l_zero_sticky_z_set]="a6030301"
SENTINEL_A6[subx_l_zero_sticky_z_set]="a6030302"
SENTINEL_A6[addx_b_zero_sticky_z_clear]="a6030303"
SENTINEL_A6[addx_w_zero_sticky_z_clear]="a6030304"
SENTINEL_A6[addx_l_zero_sticky_z_clear]="a6030305"
SENTINEL_A6[subx_b_zero_sticky_z_clear]="a6030306"
SENTINEL_A6[subx_w_zero_sticky_z_clear]="a6030307"
SENTINEL_A6[subx_l_zero_sticky_z_clear]="a6030308"
SENTINEL_A6[addx_b_overflow_with_x]="a6030309"
SENTINEL_A6[addx_w_overflow_with_x]="a603030a"
SENTINEL_A6[addx_l_overflow_with_x]="a603030b"
SENTINEL_A6[subx_b_overflow_with_x]="a603030c"
SENTINEL_A6[subx_w_overflow_with_x]="a603030d"
SENTINEL_A6[subx_l_overflow_with_x]="a603030e"
SENTINEL_A6[subx_b_without_x]="a603030f"
SENTINEL_A6[subx_w_without_x]="a6030310"
SENTINEL_A6[subx_l_without_x]="a6030311"
SENTINEL_A6[ccr_ori_exact_bits]="a6030312"
SENTINEL_A6[ccr_andi_exact_mask]="a6030313"
SENTINEL_A6[ccr_eori_exact_toggle]="a6030314"
SENTINEL_A6[ccr_ori_after_borrow_flags]="a6030315"
SENTINEL_A6[ccr_andi_after_borrow_flags]="a6030316"
SENTINEL_A6[ccr_eori_after_borrow_flags]="a6030317"
SENTINEL_A6[bcd_abcd_zero_sticky_set]="a6030401"
SENTINEL_A6[bcd_abcd_zero_sticky_clear]="a6030402"
SENTINEL_A6[bcd_abcd_nonzero_clears_sticky]="a6030403"
SENTINEL_A6[bcd_abcd_carry_zero]="a6030404"
SENTINEL_A6[bcd_abcd_same_reg_with_x]="a6030405"
SENTINEL_A6[bcd_sbcd_zero_sticky_set]="a6030406"
SENTINEL_A6[bcd_sbcd_zero_sticky_clear]="a6030407"
SENTINEL_A6[bcd_sbcd_borrow]="a6030408"
SENTINEL_A6[bcd_sbcd_same_reg_with_x]="a6030409"
SENTINEL_A6[bcd_nbcd_zero_sticky_set]="a603040a"
SENTINEL_A6[bcd_nbcd_zero_sticky_clear]="a603040b"
SENTINEL_A6[bcd_nbcd_nonzero]="a603040c"
SENTINEL_A6[bcd_nbcd_with_x]="a603040d"
SENTINEL_A6[bcd_abcd_decimal_09_plus_01]="a6030415"
SENTINEL_A6[bcd_abcd_invalid_nibble_exact]="a6030416"
SENTINEL_A6[bcd_abcd_extend_chain]="a6030417"
SENTINEL_A6[bcd_sbcd_decimal_10_minus_01]="a6030418"
SENTINEL_A6[bcd_sbcd_invalid_nibble_exact]="a6030419"
SENTINEL_A6[bcd_nbcd_decimal_10]="a603041a"
SENTINEL_A6[bcd_nbcd_invalid_nibble_exact]="a603041b"
SENTINEL_A6[bcd_native_abcd_zero_sticky]="a603041c"
SENTINEL_A6[bcd_native_abcd_invalid_extend]="a603041d"
SENTINEL_A6[bcd_native_sbcd_invalid_borrow]="a603041e"
SENTINEL_A6[bcd_native_nbcd_invalid_borrow]="a603041f"
SENTINEL_A6[bcd_abcd_predec_src_a7]="a603040e"
SENTINEL_A6[bcd_abcd_predec_dst_a7]="a603040f"
SENTINEL_A6[bcd_abcd_predec_a7_alias]="a6030410"
SENTINEL_A6[bcd_sbcd_predec_src_a7]="a6030411"
SENTINEL_A6[bcd_sbcd_predec_dst_a7]="a6030412"
SENTINEL_A6[bcd_sbcd_predec_a7_alias]="a6030413"
SENTINEL_A6[bcd_nbcd_predec_a7]="a6030414"
SENTINEL_A6[addx_b_distinct_reg_consumes_x]="a6030211"
SENTINEL_A6[addx_w_distinct_reg_consumes_x]="a6030212"
SENTINEL_A6[addx_l_distinct_reg_consumes_x]="a6030213"
SENTINEL_A6[subx_b_distinct_reg_consumes_x]="a6030214"
SENTINEL_A6[subx_w_distinct_reg_consumes_x]="a6030215"
SENTINEL_A6[subx_l_distinct_reg_consumes_x]="a6030216"
SENTINEL_A6[addx_b_same_reg_consumes_x]="a6030201"
SENTINEL_A6[addx_w_same_reg_consumes_x]="a6030202"
SENTINEL_A6[addx_l_same_reg_consumes_x]="a6030203"
SENTINEL_A6[subx_b_same_reg_consumes_x]="a6030204"
SENTINEL_A6[subx_w_same_reg_consumes_x]="a6030205"
SENTINEL_A6[subx_l_same_reg_consumes_x]="a6030206"
SENTINEL_A6[asl_b_reg_count_0_preserves_x]="a6030101"
SENTINEL_A6[asl_w_reg_count_0_preserves_x]="a6030102"
SENTINEL_A6[asl_l_reg_count_0_preserves_x]="a6030103"
SENTINEL_A6[asr_b_reg_count_0_preserves_x]="a6030104"
SENTINEL_A6[asr_w_reg_count_0_preserves_x]="a6030105"
SENTINEL_A6[asr_l_reg_count_0_preserves_x]="a6030106"
SENTINEL_A6[lsl_b_reg_count_0_preserves_x]="a6030107"
SENTINEL_A6[lsl_w_reg_count_0_preserves_x]="a6030108"
SENTINEL_A6[lsl_l_reg_count_0_preserves_x]="a6030109"
SENTINEL_A6[lsr_b_reg_count_0_preserves_x]="a603010a"
SENTINEL_A6[lsr_w_reg_count_0_preserves_x]="a603010b"
SENTINEL_A6[lsr_l_reg_count_0_preserves_x]="a603010c"
SENTINEL_A6[roxl_reg_count_63]="a60100ef"
SENTINEL_A6[roxr_reg_count_63]="a60100f0"
SENTINEL_A6[roxr_roxl_chain_x]="a60100f1"
SENTINEL_A6[roxl_lsr_chain_x]="a60100f2"
SENTINEL_A6[mulu_large]="a60100dd"
SENTINEL_A6[divu_remainder]="a60100de"
SENTINEL_A6[abcd_with_carry]="a60100df"
SENTINEL_A6[nbcd_basic]="a60100e0"
SENTINEL_A6[bsr_rts]="a60100e1"
SENTINEL_A6[link_unlk]="a60100e2"
SENTINEL_A6[indexed_addr_mode]="a60100e3"
SENTINEL_A6[indexed_full_neg_base]="a6010200"
SENTINEL_A6[io_byte_write_roundtrip]="a60102ff"
SENTINEL_A6[strict_zero_ram_native]="a6010300"
SENTINEL_A6[host_code_reuse_coherence]="a6010303"
SENTINEL_A6[dbra_ccr_preserve_z_clear]="a6010301"
SENTINEL_A6[dbra_ccr_preserve_z_set]="a6010302"
SENTINEL_A6[byte_postinc]="a60100e4"
SENTINEL_A6[cmpm_equal]="a60100e5"
SENTINEL_A6[move_sr_roundtrip]="a60100e6"
SENTINEL_A6[dbra_loop_100]="a6010100"
SENTINEL_A6[move]="a6010001"
SENTINEL_A6[moveq_signext]="a601007a"
SENTINEL_A6[alu]="a6010002"
SENTINEL_A6[alu_overflow]="a6010031"
SENTINEL_A6[addi_subi_long]="a6010043"
SENTINEL_A6[addi_subi_long_wrap]="a60100a2"
SENTINEL_A6[addi_subi_word]="a6010044"
SENTINEL_A6[addi_subi_word_wrap]="a6010073"
SENTINEL_A6[addi_subi_byte]="a6010056"
SENTINEL_A6[addi_subi_byte_wrap]="a601006f"
SENTINEL_A6[shift]="a6010003"
SENTINEL_A6[bitops]="a6010004"
SENTINEL_A6[bitops_chg]="a6010032"
SENTINEL_A6[bitops_highbit]="a601006d"
SENTINEL_A6[bitops_chg_highbit]="a6010077"
SENTINEL_A6[branch]="a6010005"
SENTINEL_A6[branch_chain]="a6010057"
SENTINEL_A6[compare]="a6010006"
SENTINEL_A6[compare_negative]="a6010033"
SENTINEL_A6[cmpi_sizes]="a6010045"
SENTINEL_A6[cmpi_sizes_zero]="a60100a4"
SENTINEL_A6[cmpi_byte_negative]="a6010071"
SENTINEL_A6[cmpi_word_negative]="a6010072"
SENTINEL_A6[cmpi_long_negative]="a6010078"
SENTINEL_A6[cmpi_beq_taken]="a601005b"
SENTINEL_A6[muldiv]="a6010007"
SENTINEL_A6[movem]="a6010008"
SENTINEL_A6[misc]="a6010009"
SENTINEL_A6[clr_sizes]="a601007b"
SENTINEL_A6[clr_byte_preserve_upper]="a60100a8"
SENTINEL_A6[clr_word_preserve_upper]="a60100a9"
SENTINEL_A6[neg_sizes]="a601007c"
SENTINEL_A6[neg_zero_sizes]="a60100a6"
SENTINEL_A6[swap_roundtrip]="a601007d"
SENTINEL_A6[flags]="a601000a"
SENTINEL_A6[flags_eori_ccr]="a601006e"
SENTINEL_A6[exg]="a601000b"
SENTINEL_A6[exg_roundtrip]="a6010034"
SENTINEL_A6[imm_logic]="a601000c"
SENTINEL_A6[imm_logic_alt]="a6010035"
SENTINEL_A6[imm_logic_byte_highbit]="a60100a3"
SENTINEL_A6[imm_logic_word]="a6010068"
SENTINEL_A6[imm_logic_long]="a601006a"
SENTINEL_A6[imm_logic_long_alt]="a6010075"
SENTINEL_A6[tst_sizes]="a601006b"
SENTINEL_A6[tst_zero]="a6010076"
SENTINEL_A6[tst_positive]="a60100a7"
SENTINEL_A6[bra_taken]="a601000d"
SENTINEL_A6[bra_w_taken]="a601003e"
SENTINEL_A6[bne_not_taken]="a601000e"
SENTINEL_A6[bne_taken]="a601000f"
SENTINEL_A6[bne_w_not_taken]="a601003f"
SENTINEL_A6[bne_w_taken]="a6010040"
SENTINEL_A6[beq_taken]="a6010010"
SENTINEL_A6[beq_not_taken]="a6010011"
SENTINEL_A6[beq_w_taken]="a6010041"
SENTINEL_A6[beq_w_not_taken]="a6010042"
SENTINEL_A6[bpl_taken]="a6010012"
SENTINEL_A6[bpl_not_taken]="a6010029"
SENTINEL_A6[bpl_w_taken]="a6010046"
SENTINEL_A6[bpl_w_not_taken]="a601005c"
SENTINEL_A6[bmi_taken]="a601002a"
SENTINEL_A6[bmi_not_taken]="a6010013"
SENTINEL_A6[bmi_w_taken]="a6010047"
SENTINEL_A6[bmi_w_not_taken]="a601005d"
SENTINEL_A6[bvc_taken]="a6010014"
SENTINEL_A6[bvc_not_taken_overflow]="a601002b"
SENTINEL_A6[bvc_w_taken]="a6010048"
SENTINEL_A6[bvc_w_not_taken_overflow]="a601005e"
SENTINEL_A6[bvs_taken_overflow]="a601002c"
SENTINEL_A6[bvs_not_taken]="a6010015"
SENTINEL_A6[bvs_w_taken_overflow]="a6010049"
SENTINEL_A6[bvs_w_not_taken]="a601005f"
SENTINEL_A6[bge_taken]="a6010016"
SENTINEL_A6[bge_not_taken]="a6010025"
SENTINEL_A6[bge_w_taken]="a601004a"
SENTINEL_A6[bge_w_not_taken]="a6010060"
SENTINEL_A6[blt_taken]="a6010026"
SENTINEL_A6[blt_not_taken]="a6010017"
SENTINEL_A6[blt_w_taken]="a601004b"
SENTINEL_A6[blt_w_not_taken]="a6010061"
SENTINEL_A6[bgt_taken]="a6010018"
SENTINEL_A6[bgt_not_taken]="a6010027"
SENTINEL_A6[bgt_w_taken]="a601004c"
SENTINEL_A6[bgt_w_not_taken]="a6010062"
SENTINEL_A6[ble_taken]="a6010028"
SENTINEL_A6[ble_not_taken]="a6010019"
SENTINEL_A6[ble_w_taken]="a601004d"
SENTINEL_A6[ble_w_not_taken]="a6010063"
SENTINEL_A6[bcc_taken]="a601001a"
SENTINEL_A6[bcc_not_taken]="a601001b"
SENTINEL_A6[bcc_w_taken]="a601004e"
SENTINEL_A6[bcc_w_not_taken]="a6010064"
SENTINEL_A6[bcs_taken]="a601001c"
SENTINEL_A6[bcs_not_taken]="a601001d"
SENTINEL_A6[bcs_w_taken]="a601004f"
SENTINEL_A6[bcs_w_not_taken]="a6010065"
SENTINEL_A6[bhi_taken]="a6010022"
SENTINEL_A6[bhi_not_taken]="a6010023"
SENTINEL_A6[bhi_w_taken]="a6010050"
SENTINEL_A6[bhi_w_not_taken]="a6010066"
SENTINEL_A6[bls_taken]="a6010024"
SENTINEL_A6[bls_not_taken]="a601002d"
SENTINEL_A6[bls_w_taken]="a6010051"
SENTINEL_A6[bls_w_not_taken]="a6010067"
SENTINEL_A6[scc_basic]="a601001e"
SENTINEL_A6[scc_eq_ne]="a601002e"
SENTINEL_A6[scc_carry]="a601002f"
SENTINEL_A6[scc_hi_ls]="a601003a"
SENTINEL_A6[scc_hi_ls_z]="a601003b"
SENTINEL_A6[scc_vc_vs]="a6010036"
SENTINEL_A6[scc_pl_mi]="a6010037"
SENTINEL_A6[scc_ge_lt]="a6010038"
SENTINEL_A6[scc_gt_le]="a6010039"
SENTINEL_A6[scc_ccr_preserve_blt]="a601007e"
SENTINEL_A6[scc_ccr_preserve_bcs]="a601007f"
SENTINEL_A6[scc_ccr_preserve_bne_not_taken]="a6010080"
SENTINEL_A6[scc_ccr_preserve_beq_taken]="a6010081"
SENTINEL_A6[quick_ops]="a601001f"
SENTINEL_A6[quick_ops_long_neg_roundtrip]="a60100a5"
SENTINEL_A6[quick_ops_word]="a6010058"
SENTINEL_A6[quick_ops_word_wrap]="a6010074"
SENTINEL_A6[quick_ops_long_wrap]="a6010079"
SENTINEL_A6[quick_ops_byte]="a6010069"
SENTINEL_A6[quick_ops_byte_wrap]="a6010070"
SENTINEL_A6[quick_ops_addr]="a601006c"
SENTINEL_A6[dbra]="a6010020"
SENTINEL_A6[dbra_not_taken]="a6010021"
SENTINEL_A6[dbra_start_minus1_branch]="a60100e7"
SENTINEL_A6[dbra_start_8000_branch]="a60100e9"
SENTINEL_A6[dbt_true_not_taken]="a6010059"
SENTINEL_A6[dbra_three_iter]="a6010030"
SENTINEL_A6[dbcc_loop_c_set]="a6010082"
SENTINEL_A6[dbcs_not_taken_c_set]="a6010083"
SENTINEL_A6[dbpl_loop_n_set]="a6010084"
SENTINEL_A6[dbmi_not_taken_n_set]="a6010085"
SENTINEL_A6[dbhi_not_taken_hi_set]="a6010086"
SENTINEL_A6[dbls_not_taken_ls_set]="a6010087"
SENTINEL_A6[dbge_not_taken_n_eq_v]="a6010088"
SENTINEL_A6[dblt_not_taken_n_ne_v]="a6010089"
SENTINEL_A6[dbgt_not_taken_gt_set]="a601008a"
SENTINEL_A6[dble_not_taken_le_set]="a601008b"
SENTINEL_A6[dbhi_false_dec_terminal_ls_set]="a601008c"
SENTINEL_A6[dbls_false_dec_terminal_hi_set]="a601008d"
SENTINEL_A6[dbge_false_dec_terminal_n_ne_v]="a601008e"
SENTINEL_A6[dblt_false_dec_terminal_n_eq_v]="a601008f"
SENTINEL_A6[dbgt_false_dec_terminal_z_set]="a6010090"
SENTINEL_A6[dble_false_dec_terminal_gt_set]="a6010091"
SENTINEL_A6[dbcc_ccr_preserve_beq_taken]="a6010092"
SENTINEL_A6[dbcc_ccr_preserve_bne_taken]="a6010093"
SENTINEL_A6[dbcc_ccr_preserve_bcs_taken]="a6010094"
SENTINEL_A6[dbcc_ccr_preserve_bvc_taken]="a6010095"
SENTINEL_A6[dbcc_ccr_preserve_bvs_taken]="a6010096"
SENTINEL_A6[dbcc_ccr_preserve_bhi_taken]="a6010097"
SENTINEL_A6[dbcc_ccr_preserve_bls_taken]="a6010098"
SENTINEL_A6[dbcc_ccr_preserve_bge_taken]="a6010099"
SENTINEL_A6[dbcc_ccr_preserve_blt_taken]="a601009a"
SENTINEL_A6[dbcc_ccr_preserve_bgt_taken]="a601009b"
SENTINEL_A6[dbcc_ccr_preserve_ble_taken]="a601009c"
SENTINEL_A6[dbvc_loop_v_set]="a6010052"
SENTINEL_A6[dbvs_loop_v_clear]="a6010053"
SENTINEL_A6[dbvc_not_taken_v_clear]="a6010054"
SENTINEL_A6[dbvs_not_taken_v_set]="a6010055"
SENTINEL_A6[dbne_loop_z_set]="a601003c"
SENTINEL_A6[dbeq_loop_z_clear]="a601003d"
SENTINEL_A6[dbeq_x_clobber]="a601dbcc"
SENTINEL_A6[moveq_edges]="a60100aa"
SENTINEL_A6[alu_negative_roundtrip]="a60100ab"
SENTINEL_A6[imm_logic_word_highbit]="a60100ac"
SENTINEL_A6[branch_chain_z_clear]="a60100ad"
SENTINEL_A6[branch_chain_carry_set]="a60100ae"
SENTINEL_A6[branch_chain_overflow_set]="a60100af"
SENTINEL_A6[scc_ccr_preserve_bvs_taken]="a60100b0"
SENTINEL_A6[dbra_four_iter]="a60100b1"
SENTINEL_A6[scc_ccr_preserve_bvc_taken]="a60100b2"
SENTINEL_A6[scc_ccr_preserve_bhi_taken]="a60100b3"
SENTINEL_A6[scc_ccr_preserve_bls_taken]="a60100b4"
SENTINEL_A6[dbra_five_iter]="a60100b5"
SENTINEL_A6[branch_chain_eq_then_ne]="a60100b6"
SENTINEL_A6[branch_chain_carry_clear]="a60100b7"
SENTINEL_A6[imm_logic_long_highbit]="a60100b8"
SENTINEL_A6[dbra_six_iter]="a60100b9"
SENTINEL_A6[lsl_l_count0]="a6010125"
SENTINEL_A6[asr_l_8_neg]="a6010126"
SENTINEL_A6[rol_l_16]="a6010127"
SENTINEL_A6[lsl_b_7]="a6010128"
SENTINEL_A6[asr_b_1_sign]="a6010129"
SENTINEL_A6[divs_word_hardfail]="a601014b"
SENTINEL_A6[divu_word_hardfail]="a601014c"
SENTINEL_A6[mull_32_hardfail]="a601014d"
SENTINEL_A6[divl_32_hardfail]="a601014e"
SENTINEL_A6[aslw_mem_hardfail]="a601014f"
SENTINEL_A6[lsrw_mem_hardfail]="a6010150"
SENTINEL_A6[rolw_mem_hardfail]="a6010151"
SENTINEL_A6[ori_sr_hardfail]="a6010152"
SENTINEL_A6[andi_sr_hardfail]="a6010153"
SENTINEL_A6[eori_sr_hardfail]="a6010154"
SENTINEL_A6[move_from_sr_hardfail]="a6010155"
SENTINEL_A6[move_to_sr_hardfail]="a6010156"
SENTINEL_A6[divs_neg_by_neg_edge]="a60001c0"
SENTINEL_A6[divs_by_minus_one_edge]="a60001c1"
SENTINEL_A6[divs_zero_dividend_edge]="a60001c2"
SENTINEL_A6[divs_overflow_edge]="a60001c3"
SENTINEL_A6[divu_exact_edge]="a60001c4"
SENTINEL_A6[divu_with_remainder_edge]="a60001c5"
SENTINEL_A6[divu_overflow_edge]="a60001c6"
SENTINEL_A6[mull_unsigned_32]="a60001c7"
SENTINEL_A6[mull_signed_32]="a60001c8"
SENTINEL_A6[divl_unsigned_32]="a60001c9"
SENTINEL_A6[divl_signed_32]="a60001ca"
SENTINEL_A6[asrw_mem_edge]="a60001cb"
SENTINEL_A6[roxlw_mem_edge]="a60001cc"
SENTINEL_A6[roxrw_mem_edge]="a60001cd"
SENTINEL_A6[abcd_99_plus_01_edge]="a60001ce"
SENTINEL_A6[sbcd_with_x_edge]="a60001cf"
SENTINEL_A6[nbcd_99_edge]="a60001d0"
SENTINEL_A6[bfextu_reg_edge]="a60001d1"
SENTINEL_A6[bfexts_reg_edge]="a60001d2"
SENTINEL_A6[bfffo_reg_edge]="a60001d3"
SENTINEL_A6[bfset_reg_edge]="a60001d4"
SENTINEL_A6[bfclr_reg_edge]="a60001d5"
SENTINEL_A6[bfchg_reg_edge]="a60001d6"
SENTINEL_A6[bftst_reg_edge]="a60001d7"
SENTINEL_A6[bfins_reg_edge]="a60001d8"
SENTINEL_A6[bitfield_mem_an_family]="a65b0001"
SENTINEL_A6[bitfield_d16_an]="a65b0002"
SENTINEL_A6[bitfield_indexed_an]="a65b0003"
SENTINEL_A6[bitfield_absw]="a65b0004"
SENTINEL_A6[bitfield_absl]="a65b0005"
SENTINEL_A6[bitfield_pc_d16]="a65b0006"
SENTINEL_A6[bitfield_pc_indexed]="a65b0007"
SENTINEL_A6[pack_dn_edge]="a60001d9"
SENTINEL_A6[pack_predec_a7_alias]="a6ca3001"
SENTINEL_A6[unpk_dn_edge]="a60001da"
SENTINEL_A6[unpk_predec_a7_alias]="a6ca3002"
SENTINEL_A6[chk2_w_equal_preserve_ccr]="a6c22001"
SENTINEL_A6[chk2_b_areg_fullwidth_d16]="a6c22002"
SENTINEL_A6[chk2_l_wrapped_absl]="a6c22003"
SENTINEL_A6[chk2_w_trap_vector6]="a6c22004"
SENTINEL_A6[chk2_w_indexed_inrange]="a6c22005"
SENTINEL_A6[chk2_l_fullindexed_inrange]="a6c22006"
SENTINEL_A6[chk2_w_pcrel_inrange]="a6c22007"
SENTINEL_A6[movep_l_roundtrip]="a60001db"
SENTINEL_A6[sr_ops_combo]="a60001dc"
SENTINEL_A6[moves_write_read]="a60001dd"
SENTINEL_A6[moves_predec_store_alias]="a65d0001"
SENTINEL_A6[moves_predec_read_alias]="a65d0002"
SENTINEL_A6[moves_l_indexed_store]="a65d0003"
SENTINEL_A6[moves_b_postinc_areg_alias]="a6c5e001"
SENTINEL_A6[moves_privilege_vector8]="a6c5e002"
SENTINEL_A6[fullsr_orsr_privilege_vector8]="a65c0080"
SENTINEL_A6[fullsr_andsr_privilege_vector8]="a65c0081"
SENTINEL_A6[fullsr_eorsr_privilege_vector8]="a65c0082"
SENTINEL_A6[fullsr_mv2sr_privilege_vector8]="a65c0083"
SENTINEL_A6[fullsr_mvsr_privilege_vector8]="a65c0084"
SENTINEL_A6[system_usp_roundtrip]="a65c0001"
SENTINEL_A6[reset_privilege_vector8]="a65c0002"
SENTINEL_A6[usp_privilege_vector8]="a65c0003"
SENTINEL_A6[stop_clear_s_vector8]="a65c0004"
SENTINEL_A6[stop_privilege_vector8]="a65c0005"
SENTINEL_A6[movec_privilege_vector8]="a65c0006"
SENTINEL_A6[rte_privilege_vector8]="a65c0007"
SENTINEL_A6[cache_privilege_vector8]="a65c0008"
SENTINEL_A6[cache_supervisor_successors]="a65c0009"
SENTINEL_A6[fdbcc_false_decrement_branch]="a6fd8001"
SENTINEL_A6[ftrapcc_true_vector7]="a6f7a001"
SENTINEL_A6[ftrapcc_false_operand_lengths]="a6f7a002"
SENTINEL_A6[fpp_semantic_successor]="a6f20001"
SENTINEL_A6[fscc_false_byte]="a6f24001"
SENTINEL_A6[fbcc_false_operand_lengths]="a6f28001"
SENTINEL_A6[cas_b_success]="a65c1001"
SENTINEL_A6[cas_b_fail]="a65c1002"
SENTINEL_A6[cas_b_predec]="a65c1003"
SENTINEL_A6[cas_w_postinc]="a65c1004"
SENTINEL_A6[cas_l_d16]="a65c1005"
SENTINEL_A6[cas2_w_success]="a6ca2001"
SENTINEL_A6[cas2_w_fail_first]="a6ca2002"
SENTINEL_A6[cas2_w_fail_second]="a6ca2003"
SENTINEL_A6[cas2_l_success]="a6ca2004"
SENTINEL_A6[cas2_l_fail_second]="a6ca2005"
SENTINEL_A6[cas2_l_alias_compare]="a6ca2006"
SENTINEL_A6[move_b_flags]="a601012a"
SENTINEL_A6[move_w_zero]="a601012b"
SENTINEL_A6[cmpi_l_abs_short_eq]="a6010136"
SENTINEL_A6[cmpi_l_abs_short_ne]="a6010137"
SENTINEL_A6[cmpi_bne_w_not_taken]="a6010138"
SENTINEL_A6[cmpi_bne_w_taken]="a6010139"
SENTINEL_A6[cmpi_b_abs_short_blt]="a601013a"
SENTINEL_A6[movem_save_modify_restore]="a601013b"
SENTINEL_A6[movec_cacr_roundtrip]="a6010147"
SENTINEL_A6[cache_init_sequence]="a6010148"
SENTINEL_A6[move_l_neg_disp_a5]="a6010149"
SENTINEL_A6[sr_barrier_cache_init]="a601014a"
SENTINEL_A6[bsr_l_long]="a601013c"
SENTINEL_A6[tst_bne_after_bsr_rts]="a6010140"
SENTINEL_A6[tst_bne_after_jsr_an]="a6010141"
SENTINEL_A6[save_clear_slot_restore_tst]="a6010146"
SENTINEL_A6[jmp_d8_pc_dn_w]="a601013d"
SENTINEL_A6[pea_movem_stack]="a601013e"
SENTINEL_A6[subq_sp_movea_write]="a601013f"
SENTINEL_A6[add_l_an_dn]="a601012c"
SENTINEL_A6[sub_w_dn_an]="a601012d"
SENTINEL_A6[cmp_b]="a601012e"
SENTINEL_A6[cmp_w]="a601012f"
SENTINEL_A6[ori_w_mem]="a6010130"
SENTINEL_A6[andi_b_mem]="a6010131"
SENTINEL_A6[link_neg16]="a6010132"
SENTINEL_A6[mulu_max]="a6010133"
SENTINEL_A6[divs_neg_rem]="a6010134"
SENTINEL_A6[negx_64bit]="a6010135"
SENTINEL_A6[not_sizes]="a60100ba"
SENTINEL_A6[asl_w_vflag]="a601010a"
SENTINEL_A6[asl_b_overflow]="a601010b"
SENTINEL_A6[lsr_w_regcount]="a601010c"
SENTINEL_A6[asr_w_preserve]="a601010d"
SENTINEL_A6[movem_w_signext]="a601010e"
SENTINEL_A6[cmpm_l_equal]="a601010f"
SENTINEL_A6[cmpm_b_unequal]="a6010110"
SENTINEL_A6[all_regs_alive]="a601011a"
SENTINEL_A6[scaled_index_word]="a601011b"
SENTINEL_A6[byte_indexed_load]="a601011c"
SENTINEL_A6[indexed_store_load]="a601011d"
SENTINEL_A6[addq_subq_sizes]="a601011e"
SENTINEL_A6[x_flag_chain]="a601011f"
SENTINEL_A6[sub_w_subx_chain]="a6010120"
SENTINEL_A6[dbeq_loop_50]="a6010123"
SENTINEL_A6[dbmi_loop_neg]="a6010124"
SENTINEL_A6[exg_dn_an]="a6010121"
SENTINEL_A6[push_pop_a0]="a6010122"
SENTINEL_A6[addx_64bit]="a6010111"
SENTINEL_A6[subx_64bit]="a6010112"
SENTINEL_A6[muls_boundary]="a6010113"
SENTINEL_A6[divu_max_quotient]="a6010114"
SENTINEL_A6[move_b_preserve_flags]="a6010115"
SENTINEL_A6[mov_l_rr_self_native]="a6010551"
SENTINEL_A6[mov_l_rr_const_movea_native]="a6010552"
SENTINEL_A6[byte_logic_chain]="a6010116"
SENTINEL_A6[bchg_imm_high]="a6010117"
SENTINEL_A6[neg_w_partial]="a6010118"
SENTINEL_A6[clr_b_tst]="a6010119"
SENTINEL_A6[not_word_preserve_upper]="a60100bb"
SENTINEL_A6[not_byte_preserve_upper]="a60100bc"
SENTINEL_A6[scc_ccr_preserve_bpl_taken]="a60100bd"
SENTINEL_A6[scc_ccr_preserve_bmi_taken]="a60100be"
SENTINEL_A6[scc_ccr_preserve_bge_taken]="a60100bf"
SENTINEL_A6[scc_ccr_preserve_bgt_taken]="a60100c0"
SENTINEL_A6[scc_ccr_preserve_ble_taken]="a60100c1"
SENTINEL_A6[dbne_loop_cmpi]="a6010101"
SENTINEL_A6[bsr_in_dbra_loop]="a6010102"
SENTINEL_A6[table_lookup]="a6010103"
SENTINEL_A6[dbra_loop_1000]="a6010104"
SENTINEL_A6[swap_pack]="a6010105"
SENTINEL_A6[lea_scaled_index]="a6010106"
SENTINEL_A6[multi_branch]="a6010107"
SENTINEL_A6[andi_l_dn]="a6010108"
SENTINEL_A6[eor_self]="a6010109"
SENTINEL_A6[adda_w_cov]="a60001e0"
SENTINEL_A6[adda_l_cov]="a60001e1"
SENTINEL_A6[adda_w_neg_cov]="a60001e2"
SENTINEL_A6[eori_ccr_cov]="a60001e3"
SENTINEL_A6[rtr_cov]="a60001e4"
SENTINEL_A6[mvr2usp_cov]="a60001e5"
SENTINEL_A6[move_b_d16_an_cov]="a60001e6"
SENTINEL_A6[move_w_d16_an_cov]="a60001e7"
SENTINEL_A6[move_l_d16_an_cov]="a60001e8"
SENTINEL_A6[move_l_idx_absw_native]="a621f0f0"
SENTINEL_A6[move_b_idx_cov]="a60001e9"
SENTINEL_A6[move_l_idx_scale_cov]="a60001ea"
SENTINEL_A6[move_l_pc_rel_cov]="a60001eb"
SENTINEL_A6[move_l_abs_w_cov]="a60001ec"
SENTINEL_A6[move_l_abs_l_cov]="a60001ed"
SENTINEL_A6[predec_postinc_cov]="a60001ee"
SENTINEL_A6[imm_to_mem_b_cov]="a60001ef"
SENTINEL_A6[imm_to_mem_w_cov]="a60001f0"
SENTINEL_A6[imm_to_mem_l_cov]="a60001f1"
SENTINEL_A6[add_b_overflow_cov]="a60001f2"
SENTINEL_A6[sub_w_borrow_cov]="a60001f3"
SENTINEL_A6[cmp_l_equal_cov]="a60001f4"
SENTINEL_A6[and_l_zero_cov]="a60001f5"
SENTINEL_A6[or_l_allones_cov]="a60001f6"
SENTINEL_A6[eor_self_cov]="a60001f7"
SENTINEL_A6[neg_b_overflow_cov]="a60001f8"
SENTINEL_A6[not_b_cov]="a60001f9"
SENTINEL_A6[odd_addr_cov]="a60001fa"
SENTINEL_A6[a7_byte_postinc_cov]="a60001fb"
# Additional opcode coverage sentinels
SENTINEL_A6[chk_w_in_range]="a6f03200"
SENTINEL_A6[chk_w_zero]="a6f03300"
SENTINEL_A6[chk_w_equal]="a6f03400"
SENTINEL_A6[chk_w_negative_trap_n]="a6c6e001"
SENTINEL_A6[chk_w_upper_trap_n_clear]="a6c6e002"
SENTINEL_A6[chk_l_negative_trap_n]="a6c6e003"
SENTINEL_A6[chk_l_upper_trap_n_clear]="a6c6e004"
SENTINEL_A6[chk_l_in_range_preserve_ccr]="a6c6e005"
SENTINEL_A6[divu_w_zero_frame]="a6d50001"
SENTINEL_A6[divs_w_zero_frame]="a6d50002"
SENTINEL_A6[divs_w_overflow_preserve_z]="a6d50017"
SENTINEL_A6[divs_w_imm_overflow_preserve_z]="a6d5001c"
SENTINEL_A6[asl_b_reg_count32_boundary]="a6d60001"
SENTINEL_A6[asl_w_reg_count32_boundary]="a6d60002"
SENTINEL_A6[asl_l_reg_count32_boundary]="a6d60003"
SENTINEL_A6[asl_l_reg_zero_count32_v_clear]="a6d60148"
SENTINEL_A6[asl_l_reg_zero_count32_const_v_clear]="a6d6014c"
SENTINEL_A6[lsr_l_reg_const_count32]="a6d6014d"
SENTINEL_A6[asl_b_reg_zero_count63_v_clear]="a6d60149"
SENTINEL_A6[asl_w_reg_zero_count33_v_clear]="a6d6014a"
SENTINEL_A6[asr_b_reg_count32_boundary]="a6d60004"
SENTINEL_A6[asr_w_reg_count32_boundary]="a6d60005"
SENTINEL_A6[asr_l_reg_count32_boundary]="a6d60006"
SENTINEL_A6[lsl_b_reg_count32_boundary]="a6d60007"
SENTINEL_A6[lsl_w_reg_count32_boundary]="a6d60008"
SENTINEL_A6[lsl_l_reg_count32_boundary]="a6d60009"
SENTINEL_A6[lsr_b_reg_count32_boundary]="a6d6000a"
SENTINEL_A6[lsr_w_reg_count32_boundary]="a6d6000b"
SENTINEL_A6[lsr_l_reg_count32_boundary]="a6d6000c"
SENTINEL_A6[lsr_l_reg_count33_boundary]="a6d6000d"
SENTINEL_A6[asl_b_reg_count32_nf]="a6d6000e"
SENTINEL_A6[asl_w_reg_count32_nf]="a6d6000f"
SENTINEL_A6[asl_l_reg_count32_nf]="a6d60010"
SENTINEL_A6[asr_b_reg_count32_nf]="a6d60011"
SENTINEL_A6[asr_w_reg_count32_nf]="a6d60012"
SENTINEL_A6[asr_l_reg_count32_nf]="a6d60013"
SENTINEL_A6[lsl_b_reg_count32_nf]="a6d60014"
SENTINEL_A6[lsl_w_reg_count32_nf]="a6d60015"
SENTINEL_A6[lsl_l_reg_count32_nf]="a6d60016"
SENTINEL_A6[lsr_b_reg_count32_nf]="a6d60017"
SENTINEL_A6[lsr_w_reg_count32_nf]="a6d60018"
SENTINEL_A6[lsr_l_reg_count32_nf]="a6d60019"
SENTINEL_A6[asl_b_reg_same_count_data]="a6d6001a"
SENTINEL_A6[asl_w_reg_same_count_data]="a6d6001b"
SENTINEL_A6[asl_l_reg_same_count_data]="a6d6001c"
SENTINEL_A6[asr_b_reg_same_count_data]="a6d6001d"
SENTINEL_A6[asr_w_reg_same_count_data]="a6d6001e"
SENTINEL_A6[asr_l_reg_same_count_data]="a6d6001f"
SENTINEL_A6[lsl_b_reg_same_count_data]="a6d60020"
SENTINEL_A6[lsl_w_reg_same_count_data]="a6d60021"
SENTINEL_A6[lsl_l_reg_same_count_data]="a6d60022"
SENTINEL_A6[lsr_b_reg_same_count_data]="a6d60023"
SENTINEL_A6[lsr_w_reg_same_count_data]="a6d60024"
SENTINEL_A6[lsr_l_reg_same_count_data]="a6d60025"
SENTINEL_A6[asl_b_reg_same_count_data_nf]="a6d60026"
SENTINEL_A6[asl_w_reg_same_count_data_nf]="a6d60027"
SENTINEL_A6[asl_l_reg_same_count_data_nf]="a6d60028"
SENTINEL_A6[asr_b_reg_same_count_data_nf]="a6d60029"
SENTINEL_A6[asr_w_reg_same_count_data_nf]="a6d6002a"
SENTINEL_A6[asr_l_reg_same_count_data_nf]="a6d6002b"
SENTINEL_A6[lsl_b_reg_same_count_data_nf]="a6d6002c"
SENTINEL_A6[lsl_w_reg_same_count_data_nf]="a6d6002d"
SENTINEL_A6[lsl_l_reg_same_count_data_nf]="a6d6002e"
SENTINEL_A6[lsr_b_reg_same_count_data_nf]="a6d6002f"
SENTINEL_A6[lsr_w_reg_same_count_data_nf]="a6d60030"
SENTINEL_A6[lsr_l_reg_same_count_data_nf]="a6d60031"
_shift_sentinel_index=256
for _shift_name in "${SHIFT_BOUNDARY_MATRIX_NAMES[@]}"; do
    printf -v _shift_sentinel 'a6d6%04x' "$_shift_sentinel_index"
    SENTINEL_A6["$_shift_name"]="$_shift_sentinel"
    ((_shift_sentinel_index += 1))
done
unset _shift_name _shift_sentinel _shift_sentinel_index
_rotate_sentinel_index=512
for _rotate_name in "${ROTATE_REGISTER_MATRIX_NAMES[@]}"; do
    printf -v _rotate_sentinel 'a6d6%04x' "$_rotate_sentinel_index"
    SENTINEL_A6["$_rotate_name"]="$_rotate_sentinel"
    ((_rotate_sentinel_index += 1))
done
unset _rotate_name _rotate_sentinel _rotate_sentinel_index
SENTINEL_A6[rol_l_reg_const_count64]="a6d60260"
SENTINEL_A6[rol_l_reg_const_count64_nf]="a6d60261"
SENTINEL_A6[ror_l_reg_const_count64]="a6d60262"
SENTINEL_A6[ror_l_reg_const_count64_nf]="a6d60263"
SENTINEL_A6[rol_b_imm_count8]="a6d60264"
SENTINEL_A6[rol_b_imm_count8_nf]="a6d60265"
SENTINEL_A6[rol_w_imm_count8]="a6d60266"
SENTINEL_A6[rol_w_imm_count8_nf]="a6d60267"
SENTINEL_A6[rol_l_imm_count8]="a6d60268"
SENTINEL_A6[rol_l_imm_count8_nf]="a6d60269"
SENTINEL_A6[ror_b_imm_count8]="a6d6026a"
SENTINEL_A6[ror_b_imm_count8_nf]="a6d6026b"
SENTINEL_A6[ror_w_imm_count8]="a6d6026c"
SENTINEL_A6[ror_w_imm_count8_nf]="a6d6026d"
SENTINEL_A6[ror_l_imm_count8]="a6d6026e"
SENTINEL_A6[ror_l_imm_count8_nf]="a6d6026f"
SENTINEL_A6[rolw_mem_native]="a6d60270"
SENTINEL_A6[rolw_mem_native_nf]="a6d60271"
SENTINEL_A6[rorw_mem_native]="a6d60272"
SENTINEL_A6[rorw_mem_native_nf]="a6d60273"
SENTINEL_A6[aslw_mem_native]="a6d60274"
SENTINEL_A6[aslw_mem_native_nf]="a6d60275"
SENTINEL_A6[asrw_mem_native]="a6d60276"
SENTINEL_A6[asrw_mem_native_nf]="a6d60277"
SENTINEL_A6[lslw_mem_native]="a6d60278"
SENTINEL_A6[lslw_mem_native_nf]="a6d60279"
SENTINEL_A6[lsrw_mem_native]="a6d6027a"
SENTINEL_A6[lsrw_mem_native_nf]="a6d6027b"
SENTINEL_A6[roxlw_mem_x_native]="a6d6027c"
SENTINEL_A6[roxrw_mem_x_native]="a6d6027d"
SENTINEL_A6[divu_l_zero_frame]="a6d50003"
SENTINEL_A6[divs_l_zero_frame]="a6d50004"
SENTINEL_A6[divu_l32_zero_distinct]="a6d5000f"
SENTINEL_A6[divs_l32_zero_distinct]="a6d50010"
SENTINEL_A6[divu_l32_success_nf]="a6d50011"
SENTINEL_A6[divs_l32_success_nf]="a6d50012"
SENTINEL_A6[divu_l32_same_dq_dr_nf]="a6d50018"
SENTINEL_A6[divs_l32_same_dq_dr_nf]="a6d50019"
SENTINEL_A6[divu_l32_src_dr_alias_nf]="a6d5001a"
SENTINEL_A6[divs_l32_src_dr_alias_nf]="a6d5001b"
SENTINEL_A6[divu_l64_zero_frame]="a6d50007"
SENTINEL_A6[divs_l64_zero_frame]="a6d50008"
SENTINEL_A6[divu_l64_same_dq_dr]="a6d50009"
SENTINEL_A6[divs_l64_same_dq_dr]="a6d5000a"
SENTINEL_A6[divu_l64_same_dq_dr_nf]="a6d5000b"
SENTINEL_A6[divs_l64_same_dq_dr_nf]="a6d5000c"
SENTINEL_A6[divu_l64_overflow]="a6d50013"
SENTINEL_A6[divu_l64_overflow_nf]="a6d50014"
SENTINEL_A6[divs_l64_overflow]="a6d50015"
SENTINEL_A6[divs_l64_overflow_nf]="a6d50016"
SENTINEL_A6[divs_l32_overflow]="a6d5000d"
SENTINEL_A6[divs_l32_overflow_nf]="a6d5000e"
SENTINEL_A6[trapv_taken_frame]="a6d50005"
SENTINEL_A6[trapv_not_taken_preserve]="a6d50006"
SENTINEL_A6[sbcd_borrow_chain]="a6f03500"
SENTINEL_A6[sbcd_zero_zero]="a6f03600"
SENTINEL_A6[nbcd_zero_no_x]="a6f03700"
SENTINEL_A6[nbcd_with_x]="a6f03800"
SENTINEL_A6[bfins_low8]="a6f03900"
SENTINEL_A6[bfins_mid8]="a6f03a00"
SENTINEL_A6[movec_vbr_roundtrip]="a6f03b00"
SENTINEL_A6[movec_sfc_roundtrip]="a6f03c00"
SENTINEL_A6[movec_dfc_roundtrip]="a6f03d00"
SENTINEL_A6[mull_u64]="a6f03e00"
SENTINEL_A6[mull_s32_neg]="a6f03f00"
SENTINEL_A6[divl_u32_rem]="a6f04000"
SENTINEL_A6[divl_s32_neg]="a6f04100"
SENTINEL_A6[divl_u32_max]="a6f04200"
SENTINEL_A6[divl_s32_neg_divisor]="a6f04300"
SENTINEL_A6[mull_s64_neg]="a6f04400"
SENTINEL_A6[mulls32_negative_fit_v_native]="a6040001"
SENTINEL_A6[mullu64_source_preserve_v_native]="a6040002"
SENTINEL_A6[mullu64_source_low_alias_native]="a6040003"
SENTINEL_A6[mullu64_same_result_alias_native]="a6040004"
SENTINEL_A6[mullu32_low_sign_full_flags_native]="a6040005"
SENTINEL_A6[mullu32_overflow_low_zero_flags_native]="a6040006"
SENTINEL_A6[mulls32_negative_overflow_low_zero_native]="a6040007"
SENTINEL_A6[mulls32_positive_overflow_low_sign_native]="a6040008"
SENTINEL_A6[mulls64_negative_flags_native]="a6040009"
SENTINEL_A6[mullu64_zero_flags_native]="a604000a"
SENTINEL_A6[mullu64_source_high_alias_native]="a604000b"
SENTINEL_A6[mullu64_all_alias_native]="a604000c"
SENTINEL_A6[mullu32_immediate_nf_native]="a604000d"
SENTINEL_A6[mullu64_memory_nf_native]="a604000e"
SENTINEL_A6[divl_same_dq_dr]="a6f04500"
SENTINEL_A6[divl_u64]="a6f04600"
SENTINEL_A6[divl_s64]="a6f04700"
SENTINEL_A6[bfins_dreg_imm]="a6f04800"
SENTINEL_A6[bfins_dreg_narrow]="a6f04900"
SENTINEL_A6[bfins_dreg_wrap]="a6f04a00"
SENTINEL_A6[bfins_dreg_dyn]="a6f04b00"
SENTINEL_A6[bfins_dreg_dyn_width32]="a6f04c00"
SENTINEL_A6[bfins_mem_span32]="a6f04d00"
SENTINEL_A6[bfins_mem_dyn_negative]="a6f04e00"
SENTINEL_A6[bfins_dreg_boot_alias]="a6f04f00"
SENTINEL_A6[bfins_mem_dyn_neg_width32]="a6f05000"
SENTINEL_A6[bfins_mem_dyn_pos_width32]="a6f05100"
SENTINEL_A6[oracle_zf_moveq_z1_take]="a6020001"
SENTINEL_A6[oracle_zf_moveq_z0_notake]="a6020002"
SENTINEL_A6[oracle_zf_moveq_z0_take]="a6020003"
SENTINEL_A6[oracle_zf_moveq_z1_notake]="a6020004"
SENTINEL_A6[oracle_zf_tst_z1_take]="a6020005"
SENTINEL_A6[oracle_zf_tst_z0_notake]="a6020006"
SENTINEL_A6[oracle_zf_move_z1_take]="a6020007"
SENTINEL_A6[oracle_zf_move_z0_notake]="a6020008"
SENTINEL_A6[oracle_zf_and_z1_take]="a6020009"
SENTINEL_A6[oracle_zf_and_z0_notake]="a602000a"
SENTINEL_A6[oracle_zf_sub_z1_take]="a602000b"
SENTINEL_A6[oracle_zf_sub_z0_notake]="a602000c"
SENTINEL_A6[oracle_zf_bne_z1_take]="a602000d"
SENTINEL_A6[oracle_zf_bne_z0_notake]="a602000e"
SENTINEL_A6[oracle_zf_mem_take]="a602000f"
SENTINEL_A6[oracle_zf_mem_notake]="a6020010"
SENTINEL_A6[oracle_zf_dbf_preserve_take]="a6020011"
# Fuzz vector sentinels
SENTINEL_A6[fuzz_alu_0]="a6f00000"
SENTINEL_A6[fuzz_shift_0]="a6f00100"
SENTINEL_A6[fuzz_bitops_0]="a6f00200"
SENTINEL_A6[fuzz_muldiv_0]="a6f00300"
SENTINEL_A6[fuzz_extswap_0]="a6f00400"
SENTINEL_A6[fuzz_addxsubx_0]="a6f00500"
SENTINEL_A6[fuzz_memrt_0]="a6f00600"
SENTINEL_A6[fuzz_exg_0]="a6f00700"
SENTINEL_A6[fuzz_mixed_0]="a6f00800"
SENTINEL_A6[fuzz_flags_0]="a6f00900"
SENTINEL_A6[fuzz_alu_1]="a6f00a00"
SENTINEL_A6[fuzz_shift_1]="a6f00b00"
SENTINEL_A6[fuzz_bitops_1]="a6f00c00"
SENTINEL_A6[fuzz_muldiv_1]="a6f00d00"
SENTINEL_A6[fuzz_extswap_1]="a6f00e00"
SENTINEL_A6[fuzz_addxsubx_1]="a6f00f00"
SENTINEL_A6[fuzz_memrt_1]="a6f01000"
SENTINEL_A6[fuzz_exg_1]="a6f01100"
SENTINEL_A6[fuzz_mixed_1]="a6f01200"
SENTINEL_A6[fuzz_flags_1]="a6f01300"
SENTINEL_A6[fuzz_alu_2]="a6f01400"
SENTINEL_A6[fuzz_shift_2]="a6f01500"
SENTINEL_A6[fuzz_bitops_2]="a6f01600"
SENTINEL_A6[fuzz_muldiv_2]="a6f01700"
SENTINEL_A6[fuzz_extswap_2]="a6f01800"
SENTINEL_A6[fuzz_addxsubx_2]="a6f01900"
SENTINEL_A6[fuzz_memrt_2]="a6f01a00"
SENTINEL_A6[fuzz_exg_2]="a6f01b00"
SENTINEL_A6[fuzz_mixed_2]="a6f01c00"
SENTINEL_A6[fuzz_flags_2]="a6f01d00"
SENTINEL_A6[fuzz_alu_3]="a6f01e00"
SENTINEL_A6[fuzz_shift_3]="a6f01f00"
SENTINEL_A6[fuzz_bitops_3]="a6f02000"
SENTINEL_A6[fuzz_muldiv_3]="a6f02100"
SENTINEL_A6[fuzz_extswap_3]="a6f02200"
SENTINEL_A6[fuzz_addxsubx_3]="a6f02300"
SENTINEL_A6[fuzz_memrt_3]="a6f02400"
SENTINEL_A6[fuzz_exg_3]="a6f02500"
SENTINEL_A6[fuzz_mixed_3]="a6f02600"
SENTINEL_A6[fuzz_flags_3]="a6f02700"
SENTINEL_A6[fuzz_alu_4]="a6f02800"
SENTINEL_A6[fuzz_shift_4]="a6f02900"
SENTINEL_A6[fuzz_bitops_4]="a6f02a00"
SENTINEL_A6[fuzz_muldiv_4]="a6f02b00"
SENTINEL_A6[fuzz_extswap_4]="a6f02c00"
SENTINEL_A6[fuzz_addxsubx_4]="a6f02d00"
SENTINEL_A6[fuzz_memrt_4]="a6f02e00"
SENTINEL_A6[fuzz_exg_4]="a6f02f00"
SENTINEL_A6[fuzz_mixed_4]="a6f03000"
SENTINEL_A6[fuzz_flags_4]="a6f03100"
SENTINEL_A6[cache_disabled_selfmod_replay]="a6c0e001"
SENTINEL_A6[movea_l_sp_postinc_cov]="a6c0e002"
SENTINEL_A6[movea_l_postinc_alias]="a62058a0"
SENTINEL_A6[branch_flush_bgt_zero]="a6c0e003"

# Risk-focused subset used for strict mismatch-first autoresearch.
# Only these vectors count toward risky_total progression.
declare -A RISKY_TESTS=(
    [rol_l_reg_const_count64]=1
    [rol_l_reg_const_count64_nf]=1
    [ror_l_reg_const_count64]=1
    [ror_l_reg_const_count64_nf]=1
    [rol_b_imm_count8]=1
    [rol_b_imm_count8_nf]=1
    [rol_w_imm_count8]=1
    [rol_w_imm_count8_nf]=1
    [rol_l_imm_count8]=1
    [rol_l_imm_count8_nf]=1
    [ror_b_imm_count8]=1
    [ror_b_imm_count8_nf]=1
    [ror_w_imm_count8]=1
    [ror_w_imm_count8_nf]=1
    [ror_l_imm_count8]=1
    [ror_l_imm_count8_nf]=1
    [rolw_mem_native]=1
    [rolw_mem_native_nf]=1
    [rorw_mem_native]=1
    [rorw_mem_native_nf]=1
    [aslw_mem_native]=1
    [aslw_mem_native_nf]=1
    [asrw_mem_native]=1
    [asrw_mem_native_nf]=1
    [lslw_mem_native]=1
    [lslw_mem_native_nf]=1
    [lsrw_mem_native]=1
    [lsrw_mem_native_nf]=1
    [roxlw_mem_x_native]=1
    [roxrw_mem_x_native]=1
    [asl_l_reg_zero_count32_const_v_clear]=1
    [lsr_l_reg_const_count32]=1
    [asr_l_reg_count0_pressure_preserves_x]=1
    [asl_b_reg_count32_boundary]=1
    [asl_w_reg_count32_boundary]=1
    [asl_l_reg_count32_boundary]=1
    [asl_l_reg_zero_count32_v_clear]=1
    [asl_b_reg_zero_count63_v_clear]=1
    [asl_w_reg_zero_count33_v_clear]=1
    [asr_b_reg_count32_boundary]=1
    [asr_w_reg_count32_boundary]=1
    [asr_l_reg_count32_boundary]=1
    [lsl_b_reg_count32_boundary]=1
    [lsl_w_reg_count32_boundary]=1
    [lsl_l_reg_count32_boundary]=1
    [lsr_b_reg_count32_boundary]=1
    [lsr_w_reg_count32_boundary]=1
    [lsr_l_reg_count32_boundary]=1
    [lsr_l_reg_count33_boundary]=1
    [asl_b_reg_count32_nf]=1
    [asl_w_reg_count32_nf]=1
    [asl_l_reg_count32_nf]=1
    [asr_b_reg_count32_nf]=1
    [asr_w_reg_count32_nf]=1
    [asr_l_reg_count32_nf]=1
    [lsl_b_reg_count32_nf]=1
    [lsl_w_reg_count32_nf]=1
    [lsl_l_reg_count32_nf]=1
    [lsr_b_reg_count32_nf]=1
    [lsr_w_reg_count32_nf]=1
    [lsr_l_reg_count32_nf]=1
    [asl_b_reg_same_count_data]=1
    [asl_w_reg_same_count_data]=1
    [asl_l_reg_same_count_data]=1
    [asr_b_reg_same_count_data]=1
    [asr_w_reg_same_count_data]=1
    [asr_l_reg_same_count_data]=1
    [lsl_b_reg_same_count_data]=1
    [lsl_w_reg_same_count_data]=1
    [lsl_l_reg_same_count_data]=1
    [lsr_b_reg_same_count_data]=1
    [lsr_w_reg_same_count_data]=1
    [lsr_l_reg_same_count_data]=1
    [asl_b_reg_same_count_data_nf]=1
    [asl_w_reg_same_count_data_nf]=1
    [asl_l_reg_same_count_data_nf]=1
    [asr_b_reg_same_count_data_nf]=1
    [asr_w_reg_same_count_data_nf]=1
    [asr_l_reg_same_count_data_nf]=1
    [lsl_b_reg_same_count_data_nf]=1
    [lsl_w_reg_same_count_data_nf]=1
    [lsl_l_reg_same_count_data_nf]=1
    [lsr_b_reg_same_count_data_nf]=1
    [lsr_w_reg_same_count_data_nf]=1
    [lsr_l_reg_same_count_data_nf]=1
    [divs_w_imm_overflow_preserve_z]=1
    [divu_l32_same_dq_dr_nf]=1
    [divs_l32_same_dq_dr_nf]=1
    [divu_l32_src_dr_alias_nf]=1
    [divs_l32_src_dr_alias_nf]=1
    [divs_w_overflow_preserve_z]=1
    [cas_b_success]=1
    [cas_b_fail]=1
    [cas_b_predec]=1
    [cas_w_postinc]=1
    [cas_l_d16]=1
    [host_code_reuse_coherence]=1
    [cache_disabled_selfmod_replay]=1
    [movea_l_sp_postinc_cov]=1
    [movea_l_postinc_alias]=1
    [branch_flush_bgt_zero]=1
    [roxl_x_propagation]=1
    [roxr_x_propagation]=1
    [roxl_count_2]=1
    [asl_overflow]=1
    [lsr_count_32]=1
    [asr_count_0]=1
    [ror_word]=1
    [rol_word]=1
    [shift_chain]=1
    [roxl_reg_count_32]=1
    [roxl_reg_count_33]=1
    [roxr_reg_count_33]=1
    [roxr_reg_count_32]=1
    [roxr_reg_count_0]=1
    [roxl_b_reg_count_63_copies_x]=1
    [roxr_b_reg_count_63_copies_x]=1
    [roxl_w_reg_count_51_copies_x]=1
    [roxr_w_reg_count_51_copies_x]=1
    [roxl_l_reg_count_33_copies_x]=1
    [roxr_l_reg_count_33_copies_x]=1
    [roxl_l_reg_count_0_copies_x]=1
    [roxr_reg_count_0_copies_x]=1
    [roxl_l_reg_count_33_pressure]=1
    [roxr_l_reg_count_33_pressure]=1
    [ccr_ori_exact_bits]=1
    [ccr_andi_exact_mask]=1
    [ccr_eori_exact_toggle]=1
    [ccr_ori_after_borrow_flags]=1
    [ccr_andi_after_borrow_flags]=1
    [ccr_eori_after_borrow_flags]=1
    [addx_b_zero_sticky_z_clear]=1
    [addx_w_zero_sticky_z_clear]=1
    [addx_l_zero_sticky_z_clear]=1
    [subx_b_zero_sticky_z_clear]=1
    [subx_w_zero_sticky_z_clear]=1
    [subx_l_zero_sticky_z_clear]=1
    [addx_b_overflow_with_x]=1
    [addx_w_overflow_with_x]=1
    [addx_l_overflow_with_x]=1
    [subx_b_overflow_with_x]=1
    [subx_w_overflow_with_x]=1
    [subx_l_overflow_with_x]=1
    [subx_b_without_x]=1
    [subx_w_without_x]=1
    [subx_l_without_x]=1
    [addx_b_zero_sticky_z_set]=1
    [addx_w_zero_sticky_z_set]=1
    [addx_l_zero_sticky_z_set]=1
    [addx_b_zero_without_x_sticky_z_set]=1
    [addx_w_zero_without_x_sticky_z_set]=1
    [addx_l_zero_without_x_sticky_z_set]=1
    [roxl_l_zero_count_copies_cleared_x]=1
    [subx_b_zero_sticky_z_set]=1
    [subx_w_zero_sticky_z_set]=1
    [subx_l_zero_sticky_z_set]=1
    [addx_b_distinct_reg_consumes_x]=1
    [addx_w_distinct_reg_consumes_x]=1
    [addx_l_distinct_reg_consumes_x]=1
    [subx_b_distinct_reg_consumes_x]=1
    [subx_w_distinct_reg_consumes_x]=1
    [subx_l_distinct_reg_consumes_x]=1
    [addx_b_same_reg_consumes_x]=1
    [addx_w_same_reg_consumes_x]=1
    [addx_l_same_reg_consumes_x]=1
    [subx_b_same_reg_consumes_x]=1
    [subx_w_same_reg_consumes_x]=1
    [subx_l_same_reg_consumes_x]=1
    [asl_b_reg_count_0_preserves_x]=1
    [asl_w_reg_count_0_preserves_x]=1
    [asl_l_reg_count_0_preserves_x]=1
    [asr_b_reg_count_0_preserves_x]=1
    [asr_w_reg_count_0_preserves_x]=1
    [asr_l_reg_count_0_preserves_x]=1
    [lsl_b_reg_count_0_preserves_x]=1
    [lsl_w_reg_count_0_preserves_x]=1
    [lsl_l_reg_count_0_preserves_x]=1
    [lsr_b_reg_count_0_preserves_x]=1
    [lsr_w_reg_count_0_preserves_x]=1
    [lsr_l_reg_count_0_preserves_x]=1
    [roxl_reg_count_63]=1
    [roxr_reg_count_63]=1
    [roxr_roxl_chain_x]=1
    [roxl_lsr_chain_x]=1
    [movem_predec_postinc]=1
    [movem_no_writeback]=1
    [movem_predec_mixed_order]=1
    [movem]=1
    [indexed_full_neg_base]=1
    [io_byte_write_roundtrip]=1
    [strict_zero_ram_native]=1
    [dbra_ccr_preserve_z_clear]=1
    [dbra_ccr_preserve_z_set]=1
    [dbra]=1
    [dbra_not_taken]=1
    [dbra_start_minus1_branch]=1
    [dbra_start_8000_branch]=1
    [dbt_true_not_taken]=1
    [dbra_three_iter]=1
    [dbra_four_iter]=1
    [dbra_five_iter]=1
    [dbra_six_iter]=1
    [dbcc_loop_c_set]=1
    [dbcs_not_taken_c_set]=1
    [dbpl_loop_n_set]=1
    [dbmi_not_taken_n_set]=1
    [dbhi_not_taken_hi_set]=1
    [dbls_not_taken_ls_set]=1
    [dbge_not_taken_n_eq_v]=1
    [dblt_not_taken_n_ne_v]=1
    [dbgt_not_taken_gt_set]=1
    [dble_not_taken_le_set]=1
    [dbhi_false_dec_terminal_ls_set]=1
    [dbls_false_dec_terminal_hi_set]=1
    [dbge_false_dec_terminal_n_ne_v]=1
    [dblt_false_dec_terminal_n_eq_v]=1
    [dbgt_false_dec_terminal_z_set]=1
    [dble_false_dec_terminal_gt_set]=1
    [dbcc_ccr_preserve_beq_taken]=1
    [dbcc_ccr_preserve_bne_taken]=1
    [dbcc_ccr_preserve_bcs_taken]=1
    [dbcc_ccr_preserve_bvc_taken]=1
    [dbcc_ccr_preserve_bvs_taken]=1
    [dbcc_ccr_preserve_bhi_taken]=1
    [dbcc_ccr_preserve_bls_taken]=1
    [dbcc_ccr_preserve_bge_taken]=1
    [dbcc_ccr_preserve_blt_taken]=1
    [dbcc_ccr_preserve_bgt_taken]=1
    [dbcc_ccr_preserve_ble_taken]=1
    [dbvc_loop_v_set]=1
    [dbvs_loop_v_clear]=1
    [dbvc_not_taken_v_clear]=1
    [dbvs_not_taken_v_set]=1
    [dbne_loop_z_set]=1
    [dbeq_loop_z_clear]=1
    [btst_reg_high_bit]=1
    [btst_b_d16_highbit]=1
    [move_to_mem_and_back]=1
    [bitops_highbit]=1
    [bitops_chg_highbit]=1
    [flags]=1
    [flags_eori_ccr]=1
    [scc_vc_vs]=1
    [move_sr_roundtrip]=1
    [muls_neg_neg]=1
    [muls_zero]=1
    [divs_neg_neg]=1
    [divs_overflow]=1
    [mulu_large]=1
    [divu_remainder]=1
    [divu_w_zero_frame]=1
    [divs_w_zero_frame]=1
    [divu_l_zero_frame]=1
    [divs_l_zero_frame]=1
    [divu_l32_zero_distinct]=1
    [divs_l32_zero_distinct]=1
    [divu_l32_success_nf]=1
    [divs_l32_success_nf]=1
    [divu_l64_zero_frame]=1
    [divs_l64_zero_frame]=1
    [divu_l64_same_dq_dr]=1
    [divs_l64_same_dq_dr]=1
    [divu_l64_same_dq_dr_nf]=1
    [divs_l64_same_dq_dr_nf]=1
    [divu_l64_overflow]=1
    [divu_l64_overflow_nf]=1
    [divs_l64_overflow]=1
    [divs_l64_overflow_nf]=1
    [divs_l32_overflow]=1
    [divs_l32_overflow_nf]=1
    [trapv_taken_frame]=1
    [trapv_not_taken_preserve]=1
    [muldiv]=1
    [abcd_basic]=1
    [sbcd_basic]=1
    [abcd_with_carry]=1
    [nbcd_basic]=1
    [negx_with_x]=1
    [negx_zero]=1
    [addx_basic]=1
    [subx_basic]=1
    [addx_chain]=1
    [flag_chain_xzn]=1
    [dbne_loop_cmpi]=1
    [bsr_in_dbra_loop]=1
    [table_lookup]=1
    [dbra_loop_1000]=1
    [swap_pack]=1
    [lea_scaled_index]=1
    [multi_branch]=1
    [andi_l_dn]=1
    [eor_self]=1
    [asl_w_vflag]=1
    [asl_b_overflow]=1
    [lsr_w_regcount]=1
    [asr_w_preserve]=1
    [movem_w_signext]=1
    [cmpm_l_equal]=1
    [cmpm_b_unequal]=1
    [addx_64bit]=1
    [subx_64bit]=1
    [muls_boundary]=1
    [divu_max_quotient]=1
    [move_b_preserve_flags]=1
    [byte_logic_chain]=1
    [bchg_imm_high]=1
    [neg_w_partial]=1
    [clr_b_tst]=1
    [all_regs_alive]=1
    [scaled_index_word]=1
    [byte_indexed_load]=1
    [indexed_store_load]=1
    [addq_subq_sizes]=1
    [x_flag_chain]=1
    [sub_w_subx_chain]=1
    [exg_dn_an]=1
    [push_pop_a0]=1
    [dbeq_loop_50]=1
    [dbmi_loop_neg]=1
    [lsl_l_count0]=1
    [asr_l_8_neg]=1
    [rol_l_16]=1
    [lsl_b_7]=1
    [asr_b_1_sign]=1
    [move_b_flags]=1
    [move_w_zero]=1
    [add_l_an_dn]=1
    [sub_w_dn_an]=1
    [cmp_b]=1
    [cmp_w]=1
    [ori_w_mem]=1
    [andi_b_mem]=1
    [link_neg16]=1
    [mulu_max]=1
    [divs_neg_rem]=1
    [negx_64bit]=1
    [cmpi_l_abs_short_eq]=1
    [cmpi_l_abs_short_ne]=1
    [cmpi_bne_w_not_taken]=1
    [cmpi_bne_w_taken]=1
    [cmpi_b_abs_short_blt]=1
    [movem_save_modify_restore]=1
    [bsr_l_long]=1
    [jmp_d8_pc_dn_w]=1
    [pea_movem_stack]=1
    [subq_sp_movea_write]=1
    [tst_bne_after_bsr_rts]=1
    [tst_bne_after_jsr_an]=1
    [save_clear_slot_restore_tst]=1
    [movec_cacr_roundtrip]=1
    [cache_init_sequence]=1
    [move_l_neg_disp_a5]=1
    [sr_barrier_cache_init]=1
    [divs_word_hardfail]=1
    [divu_word_hardfail]=1
    [mull_32_hardfail]=1
    [divl_32_hardfail]=1
    [aslw_mem_hardfail]=1
    [lsrw_mem_hardfail]=1
    [rolw_mem_hardfail]=1
    [ori_sr_hardfail]=1
    [andi_sr_hardfail]=1
    [eori_sr_hardfail]=1
    [move_from_sr_hardfail]=1
    [move_to_sr_hardfail]=1
    [divs_neg_by_neg_edge]=1
    [divs_by_minus_one_edge]=1
    [divs_zero_dividend_edge]=1
    [divs_overflow_edge]=1
    [divu_exact_edge]=1
    [divu_with_remainder_edge]=1
    [divu_overflow_edge]=1
    [mull_unsigned_32]=1
    [mull_signed_32]=1
    [divl_unsigned_32]=1
    [divl_signed_32]=1
    [asrw_mem_edge]=1
    [roxlw_mem_edge]=1
    [roxrw_mem_edge]=1
    [abcd_99_plus_01_edge]=1
    [sbcd_with_x_edge]=1
    [nbcd_99_edge]=1
    [bfextu_reg_edge]=1
    [bfexts_reg_edge]=1
    [bfffo_reg_edge]=1
    [bfset_reg_edge]=1
    [bfclr_reg_edge]=1
    [bfchg_reg_edge]=1
    [bftst_reg_edge]=1
    [bfins_reg_edge]=1
    [bitfield_mem_an_family]=1
    [bitfield_d16_an]=1
    [bitfield_indexed_an]=1
    [bitfield_absw]=1
    [bitfield_absl]=1
    [bitfield_pc_d16]=1
    [bitfield_pc_indexed]=1
    [pack_dn_edge]=1
    [pack_predec_a7_alias]=1
    [unpk_dn_edge]=1
    [unpk_predec_a7_alias]=1
    [chk2_w_equal_preserve_ccr]=1
    [chk2_b_areg_fullwidth_d16]=1
    [chk2_l_wrapped_absl]=1
    [chk2_w_trap_vector6]=1
    [chk2_w_indexed_inrange]=1
    [chk2_l_fullindexed_inrange]=1
    [chk2_w_pcrel_inrange]=1
    [movep_l_roundtrip]=1
    [sr_ops_combo]=1
    [moves_write_read]=1
    [moves_predec_store_alias]=1
    [moves_predec_read_alias]=1
    [moves_l_indexed_store]=1
    [moves_b_postinc_areg_alias]=1
    [moves_privilege_vector8]=1
    [fullsr_orsr_privilege_vector8]=1
    [fullsr_andsr_privilege_vector8]=1
    [fullsr_eorsr_privilege_vector8]=1
    [fullsr_mv2sr_privilege_vector8]=1
    [fullsr_mvsr_privilege_vector8]=1
    [system_usp_roundtrip]=1
    [reset_privilege_vector8]=1
    [usp_privilege_vector8]=1
    [stop_clear_s_vector8]=1
    [stop_privilege_vector8]=1
    [movec_privilege_vector8]=1
    [rte_privilege_vector8]=1
    [cache_privilege_vector8]=1
    [cache_supervisor_successors]=1
    [fdbcc_false_decrement_branch]=1
    [ftrapcc_true_vector7]=1
    [ftrapcc_false_operand_lengths]=1
    [fpp_semantic_successor]=1
    [fscc_false_byte]=1
    [fbcc_false_operand_lengths]=1
    [cas2_w_success]=1
    [cas2_w_fail_first]=1
    [cas2_w_fail_second]=1
    [cas2_l_success]=1
    [cas2_l_fail_second]=1
    [cas2_l_alias_compare]=1
    [adda_w_cov]=1
    [adda_l_cov]=1
    [adda_w_neg_cov]=1
    [eori_ccr_cov]=1
    [rtr_cov]=1
    [mvr2usp_cov]=1
    [move_b_d16_an_cov]=1
    [move_w_d16_an_cov]=1
    [move_l_d16_an_cov]=1
    [move_l_idx_absw_native]=1
    [move_b_idx_cov]=1
    [move_l_idx_scale_cov]=1
    [move_l_pc_rel_cov]=1
    [move_l_abs_w_cov]=1
    [move_l_abs_l_cov]=1
    [predec_postinc_cov]=1
    [imm_to_mem_b_cov]=1
    [imm_to_mem_w_cov]=1
    [imm_to_mem_l_cov]=1
    [add_b_overflow_cov]=1
    [sub_w_borrow_cov]=1
    [cmp_l_equal_cov]=1
    [and_l_zero_cov]=1
    [or_l_allones_cov]=1
    [eor_self_cov]=1
    [neg_b_overflow_cov]=1
    [not_b_cov]=1
    [odd_addr_cov]=1
    [a7_byte_postinc_cov]=1
    [dbra_loop_100]=1

    [fuzz_alu_0]=1
    [fuzz_shift_0]=1
    [fuzz_bitops_0]=1
    [fuzz_muldiv_0]=1
    [fuzz_extswap_0]=1
    [fuzz_addxsubx_0]=1
    [fuzz_memrt_0]=1
    [fuzz_exg_0]=1
    [fuzz_mixed_0]=1
    [fuzz_flags_0]=1
    [fuzz_alu_1]=1
    [fuzz_shift_1]=1
    [fuzz_bitops_1]=1
    [fuzz_muldiv_1]=1
    [fuzz_extswap_1]=1
    [fuzz_addxsubx_1]=1
    [fuzz_memrt_1]=1
    [fuzz_exg_1]=1
    [fuzz_mixed_1]=1
    [fuzz_flags_1]=1
    [fuzz_alu_2]=1
    [fuzz_shift_2]=1
    [fuzz_bitops_2]=1
    [fuzz_muldiv_2]=1
    [fuzz_extswap_2]=1
    [fuzz_addxsubx_2]=1
    [fuzz_memrt_2]=1
    [fuzz_exg_2]=1
    [fuzz_mixed_2]=1
    [fuzz_flags_2]=1
    [fuzz_alu_3]=1
    [fuzz_shift_3]=1
    [fuzz_bitops_3]=1
    [fuzz_muldiv_3]=1
    [fuzz_extswap_3]=1
    [fuzz_addxsubx_3]=1
    [fuzz_memrt_3]=1
    [fuzz_exg_3]=1
    [fuzz_mixed_3]=1
    [fuzz_flags_3]=1
    [fuzz_alu_4]=1
    [fuzz_shift_4]=1
    [fuzz_bitops_4]=1
    [fuzz_muldiv_4]=1
    [fuzz_extswap_4]=1
    [fuzz_addxsubx_4]=1
    [fuzz_memrt_4]=1
    [fuzz_exg_4]=1
    [fuzz_mixed_4]=1
    [fuzz_flags_4]=1

    [chk_w_in_range]=1
    [chk_w_zero]=1
    [chk_w_equal]=1
    [chk_w_negative_trap_n]=1
    [chk_w_upper_trap_n_clear]=1
    [chk_l_negative_trap_n]=1
    [chk_l_upper_trap_n_clear]=1
    [chk_l_in_range_preserve_ccr]=1
    [sbcd_borrow_chain]=1
    [sbcd_zero_zero]=1
    [nbcd_zero_no_x]=1
    [nbcd_with_x]=1
    [bfins_low8]=1
    [bfins_mid8]=1
    [movec_vbr_roundtrip]=1
    [movec_sfc_roundtrip]=1
    [movec_dfc_roundtrip]=1
    [mull_u64]=1
    [mull_s32_neg]=1
    [divl_u32_rem]=1
    [divl_s32_neg]=1
    [divl_u32_max]=1
    [divl_s32_neg_divisor]=1
    [mull_s64_neg]=1
    [mulls32_negative_fit_v_native]=1
    [mullu64_source_preserve_v_native]=1
    [mullu64_source_low_alias_native]=1
    [mullu64_same_result_alias_native]=1
    [mullu32_low_sign_full_flags_native]=1
    [mullu32_overflow_low_zero_flags_native]=1
    [mulls32_negative_overflow_low_zero_native]=1
    [mulls32_positive_overflow_low_sign_native]=1
    [mulls64_negative_flags_native]=1
    [mullu64_zero_flags_native]=1
    [mullu64_source_high_alias_native]=1
    [mullu64_all_alias_native]=1
    [mullu32_immediate_nf_native]=1
    [mullu64_memory_nf_native]=1
    [movem_l_postinc_base_alias_native]=1
    [movem_w_postinc_base_alias_native]=1
    [movem_l_predec_base_alias_native]=1
    [movem_w_predec_base_alias_native]=1
    [movem_l_aind_load_base_alias_native]=1
    [movem_l_aind_store_base_alias_native]=1
    [movem_l_all_live_roundtrip_native]=1
    [movem_l_all_live_special_native]=1
    [movem_zero_mask_native]=1
    [movem_l_control_modes_native]=1
    [movem_l_pc_modes_native]=1
    [divl_same_dq_dr]=1
    [divl_u64]=1
    [divl_s64]=1
    [bfins_dreg_imm]=1
    [bfins_dreg_narrow]=1
    [bfins_dreg_wrap]=1
    [bfins_dreg_dyn]=1
    [bfins_dreg_dyn_width32]=1
    [bfins_mem_span32]=1
    [bfins_mem_dyn_negative]=1
    [bfins_dreg_boot_alias]=1
    [bfins_mem_dyn_neg_width32]=1
    [bfins_mem_dyn_pos_width32]=1
    [dbeq_x_clobber]=1
    [oracle_zf_moveq_z1_take]=1
    [oracle_zf_moveq_z0_notake]=1
    [oracle_zf_moveq_z0_take]=1
    [oracle_zf_moveq_z1_notake]=1
    [oracle_zf_tst_z1_take]=1
    [oracle_zf_tst_z0_notake]=1
    [oracle_zf_move_z1_take]=1
    [oracle_zf_move_z0_notake]=1
    [oracle_zf_and_z1_take]=1
    [oracle_zf_and_z0_notake]=1
    [oracle_zf_sub_z1_take]=1
    [oracle_zf_sub_z0_notake]=1
    [oracle_zf_bne_z1_take]=1
    [oracle_zf_bne_z0_notake]=1
    [oracle_zf_mem_take]=1
    [oracle_zf_mem_notake]=1
    [oracle_zf_dbf_preserve_take]=1
    [bcd_abcd_zero_sticky_set]=1
    [bcd_abcd_zero_sticky_clear]=1
    [bcd_abcd_nonzero_clears_sticky]=1
    [bcd_abcd_carry_zero]=1
    [bcd_abcd_same_reg_with_x]=1
    [bcd_sbcd_zero_sticky_set]=1
    [bcd_sbcd_zero_sticky_clear]=1
    [bcd_sbcd_borrow]=1
    [bcd_sbcd_same_reg_with_x]=1
    [bcd_nbcd_zero_sticky_set]=1
    [bcd_nbcd_zero_sticky_clear]=1
    [bcd_nbcd_nonzero]=1
    [bcd_nbcd_with_x]=1
    [bcd_abcd_decimal_09_plus_01]=1
    [bcd_abcd_invalid_nibble_exact]=1
    [bcd_abcd_extend_chain]=1
    [bcd_sbcd_decimal_10_minus_01]=1
    [bcd_sbcd_invalid_nibble_exact]=1
    [bcd_nbcd_decimal_10]=1
    [bcd_nbcd_invalid_nibble_exact]=1
    [bcd_native_abcd_zero_sticky]=1
    [bcd_native_abcd_invalid_extend]=1
    [bcd_native_sbcd_invalid_borrow]=1
    [bcd_native_nbcd_invalid_borrow]=1
    [bcd_abcd_predec_src_a7]=1
    [bcd_abcd_predec_dst_a7]=1
    [bcd_abcd_predec_a7_alias]=1
    [bcd_sbcd_predec_src_a7]=1
    [bcd_sbcd_predec_dst_a7]=1
    [bcd_sbcd_predec_a7_alias]=1
    [bcd_nbcd_predec_a7]=1
)
for _shift_name in "${SHIFT_BOUNDARY_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_shift_name"]=1
done
unset _shift_name
for _rotate_name in "${ROTATE_REGISTER_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_rotate_name"]=1
done
unset _rotate_name
for _add_name in "${ADD_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_add_name"]=1
done
unset _add_name
for _and_name in "${AND_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_and_name"]=1
done
unset _and_name
for _eor_name in "${EOR_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_eor_name"]=1
done
unset _eor_name
for _or_name in "${OR_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_or_name"]=1
done
unset _or_name
for _sub_name in "${SUB_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_sub_name"]=1
done
unset _sub_name
for _adda_name in "${ADDA_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_adda_name"]=1
done
unset _adda_name
for _neg_name in "${NEG_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_neg_name"]=1
done
unset _neg_name
for _negx_name in "${NEGX_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_negx_name"]=1
done
unset _negx_name
for _tas_name in "${TAS_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_tas_name"]=1
done
unset _tas_name
for _move_name in "${MOVE_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_move_name"]=1
done
unset _move_name
for _movea_name in "${MOVEA_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_movea_name"]=1
done
unset _movea_name
for _move16_name in "${MOVE16_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_move16_name"]=1
done
unset _move16_name
for _scc_name in "${SCC_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_scc_name"]=1
done
unset _scc_name
for _bcc_name in "${BCC_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_bcc_name"]=1
done
unset _bcc_name
for _clr_name in "${CLR_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_clr_name"]=1
done
unset _clr_name
for _exg_name in "${EXG_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_exg_name"]=1
done
unset _exg_name
for _ext_name in "${EXT_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_ext_name"]=1
done
unset _ext_name
for _dbcc_name in "${DBCC_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_dbcc_name"]=1
done
unset _dbcc_name
for _bitop_name in "${BITOP_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_bitop_name"]=1
done
unset _bitop_name
for _cmp_name in "${CMP_NATIVE_MATRIX_NAMES[@]}"; do
    RISKY_TESTS["$_cmp_name"]=1
done
unset _cmp_name

# Preflight harness invariants: deterministic mapping and sentinel hygiene.
declare -A _seen_test_names=()
declare -A _seen_sentinels=()
for name in "${TEST_ORDER[@]}"; do
    if [ -n "${_seen_test_names[$name]+x}" ]; then
        emit_failure_metrics 1 "duplicate test name in TEST_ORDER: $name" 1
    fi
    _seen_test_names[$name]=1

    if [ -z "${TESTS[$name]+x}" ]; then
        emit_failure_metrics 1 "missing TESTS entry for test: $name" 1
    fi
    if [ -z "${SENTINEL_A6[$name]+x}" ]; then
        emit_failure_metrics 1 "missing SENTINEL_A6 entry for test: $name" 1
    fi

    hex_words="${TESTS[$name]}"
    if ! [[ "$hex_words" =~ ^[0-9A-Fa-f]{4}([[:space:]]+[0-9A-Fa-f]{4})*$ ]]; then
        emit_failure_metrics 1 "invalid TESTS encoding for $name: expected 4-hex words" 1
    fi
    if [[ "$hex_words" =~ (^|[[:space:]])2[Cc]7[Cc]($|[[:space:]]) ]]; then
        emit_failure_metrics 1 "TESTS for $name must not include MOVEA immediate opcode 2C7C (reserved for harness sentinel append)" 1
    fi

    sentinel="${SENTINEL_A6[$name]}"
    if ! [[ "$sentinel" =~ ^[0-9a-fA-F]{8}$ ]]; then
        emit_failure_metrics 1 "invalid sentinel format for $name: $sentinel" 1
    fi
    if [ -n "${_seen_sentinels[$sentinel]+x}" ]; then
        emit_failure_metrics 1 "duplicate sentinel value detected: $sentinel" 1
    fi
    _seen_sentinels[$sentinel]=1
done

for name in "${!TESTS[@]}"; do
    if [ -z "${_seen_test_names[$name]+x}" ]; then
        emit_failure_metrics 1 "TESTS entry not present in TEST_ORDER: $name" 1
    fi
done

for name in "${!SENTINEL_A6[@]}"; do
    if [ -z "${_seen_test_names[$name]+x}" ]; then
        emit_failure_metrics 1 "SENTINEL_A6 entry not present in TEST_ORDER: $name" 1
    fi
done

for name in "${!RISKY_TESTS[@]}"; do
    if [ -z "${_seen_test_names[$name]+x}" ]; then
        emit_failure_metrics 1 "RISKY_TESTS entry not present in TEST_ORDER: $name" 1
    fi
done

# Active mismatch-first campaign vectors.
# Add at most one new line to jit-test/active-risky-tests.txt per iteration.
ACTIVE_RISKY_FILE="$SCRIPT_DIR/active-risky-tests.txt"
if [ ! -f "$ACTIVE_RISKY_FILE" ]; then
    emit_failure_metrics 1 "missing active risky vector list: $ACTIVE_RISKY_FILE" 1
fi

mapfile -t ACTIVE_TEST_ORDER < <(grep -E '^[[:space:]]*[^#[:space:]][a-z0-9_]*[[:space:]]*$' "$ACTIVE_RISKY_FILE" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
if [ "${#ACTIVE_TEST_ORDER[@]}" -eq 0 ]; then
    emit_failure_metrics 1 "no active risky vectors listed in $ACTIVE_RISKY_FILE" 1
fi

# Optional exact-name or shell-glob subsets for focused debug loops. Explicit
# selection may run staged risky vectors before active-list promotion. Default
# runs remain the complete active campaign inventory.
if [ -n "${B2_TEST_NAMES:-}" ]; then
    declare -A _wanted_tests=()
    while IFS= read -r _name; do
        [ -n "$_name" ] && _wanted_tests["$_name"]=1
    done < <(printf '%s\n' "$B2_TEST_NAMES" | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed '/^$/d')
    for _name in "${!_wanted_tests[@]}"; do
        if [ -z "${_seen_test_names[$_name]+x}" ] || [ -z "${RISKY_TESTS[$_name]+x}" ]; then
            emit_failure_metrics 1 "B2_TEST_NAMES contains unknown or non-risky vector: $_name" 1
        fi
    done

    declare -a _filtered_active=()
    for name in "${TEST_ORDER[@]}"; do
        if [ -n "${_wanted_tests[$name]+x}" ] && [ -n "${RISKY_TESTS[$name]+x}" ]; then
            _filtered_active+=("$name")
        fi
    done
    ACTIVE_TEST_ORDER=("${_filtered_active[@]}")
    if [ "${#ACTIVE_TEST_ORDER[@]}" -eq 0 ]; then
        emit_failure_metrics 1 "B2_TEST_NAMES selected no known risky vectors" 1
    fi
elif [ -n "$TEST_PATTERNS" ]; then
    declare -a _patterns=()
    while IFS= read -r _pattern; do
        [ -n "$_pattern" ] && _patterns+=("$_pattern")
    done < <(printf '%s\n' "$TEST_PATTERNS" | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed '/^$/d')
    [ "${#_patterns[@]}" -gt 0 ] || emit_failure_metrics 1 "B2_TEST_PATTERN contains no patterns" 1
    declare -A _pattern_matches=()
    declare -a _filtered_active=()
    for name in "${TEST_ORDER[@]}"; do
        [ -n "${RISKY_TESTS[$name]+x}" ] || continue
        _selected=0
        for _pattern in "${_patterns[@]}"; do
            if [[ "$name" == $_pattern ]]; then
                _pattern_matches["$_pattern"]=$(( ${_pattern_matches[$_pattern]:-0} + 1 ))
                _selected=1
            fi
        done
        [ "$_selected" -eq 0 ] || _filtered_active+=("$name")
    done
    _pattern_index=0
    for _pattern in "${_patterns[@]}"; do
        if [ "${_pattern_matches[$_pattern]:-0}" -eq 0 ]; then
            emit_failure_metrics 1 "B2_TEST_PATTERN component matched no risky vectors: $_pattern" 1
        fi
        echo "METRIC selected_pattern_${_pattern_index}_matches=${_pattern_matches[$_pattern]}"
        _pattern_index=$((_pattern_index + 1))
    done
    echo "METRIC selected_pattern_count=${#_patterns[@]}"
    ACTIVE_TEST_ORDER=("${_filtered_active[@]}")
    if [ "${#ACTIVE_TEST_ORDER[@]}" -eq 0 ]; then
        emit_failure_metrics 1 "B2_TEST_PATTERN selected no known risky vectors" 1
    fi
fi

# Validate active list: known test names, risky-only, and no duplicates.
declare -A _seen_active=()
for name in "${ACTIVE_TEST_ORDER[@]}"; do
    if [ -n "${_seen_active[$name]+x}" ]; then
        emit_failure_metrics 1 "duplicate active risky vector: $name" 1
    fi
    _seen_active[$name]=1

    if [ -z "${_seen_test_names[$name]+x}" ]; then
        emit_failure_metrics 1 "active risky vector not present in TEST_ORDER: $name" 1
    fi
    if [ -z "${RISKY_TESTS[$name]+x}" ]; then
        emit_failure_metrics 1 "active vector is not tagged risky: $name" 1
    fi
done

# ---- Run active risky test cases and score -----------------------------------
PASS=0
FAIL=0
INFRA_FAIL=0
EQUIV_FAIL=0
INFRA_TIMEOUT=0
INFRA_EMU_EXIT=0
INFRA_NO_REGDUMP=0
INFRA_MULTI_REGDUMP=0
INFRA_SENTINEL=0
INFRA_OTHER=0
TOTAL=${#ACTIVE_TEST_ORDER[@]}
RISKY_TOTAL=0
RISKY_PASS=0
RISKY_FAIL_EQUIV=0
RISKY_INFRA_FAIL=0

for name in "${ACTIVE_TEST_ORDER[@]}"; do
    hex="${TESTS[$name]}"
    sentinel_a6="${SENTINEL_A6[$name]}"
    ifile="$RUN_DIR/${name}-interp.txt"
    jfile="$RUN_DIR/${name}-jit.txt"

    is_risky=0
    if [ -n "${RISKY_TESTS[$name]+x}" ]; then
        is_risky=1
        RISKY_TOTAL=$((RISKY_TOTAL+1))
    fi

    interp_ok=1
    jit_ok=1
    init="${INIT_REGS[$name]:-}"
    run_test "$name" "$hex" "false" "$sentinel_a6" "$ifile" "$init" || interp_ok=0
    run_test "$name" "$hex" "true"  "$sentinel_a6" "$jfile" "$init" || jit_ok=0

    if [ "$interp_ok" -eq 1 ] && [ "$jit_ok" -eq 1 ]; then
        if diff -q "$ifile" "$jfile" >/dev/null 2>&1; then
            echo "METRIC opcode_${name}=1"
            PASS=$((PASS+1))
            if [ "$is_risky" -eq 1 ]; then
                RISKY_PASS=$((RISKY_PASS+1))
            fi
        else
            echo "METRIC opcode_${name}=0"
            echo "  DIFF for $name:" >&2
            diff "$ifile" "$jfile" >&2 || true
            FAIL=$((FAIL+1))
            EQUIV_FAIL=$((EQUIV_FAIL+1))
            if [ "$is_risky" -eq 1 ]; then
                RISKY_FAIL_EQUIV=$((RISKY_FAIL_EQUIV+1))
            fi
        fi
    else
        echo "METRIC opcode_${name}=-1"  # harness infrastructure issue
        FAIL=$((FAIL+1))
        INFRA_FAIL=$((INFRA_FAIL+1))
        if [ "$is_risky" -eq 1 ]; then
            RISKY_INFRA_FAIL=$((RISKY_INFRA_FAIL+1))
        fi

        interp_reason=$(cat "${ifile}.reason" 2>/dev/null || echo "unknown")
        jit_reason=$(cat "${jfile}.reason" 2>/dev/null || echo "unknown")
        if [[ "$interp_reason,$jit_reason" == *"timeout"* ]]; then
            INFRA_TIMEOUT=$((INFRA_TIMEOUT+1))
        elif [[ "$interp_reason,$jit_reason" == *"emu_exit_"* ]]; then
            INFRA_EMU_EXIT=$((INFRA_EMU_EXIT+1))
        elif [[ "$interp_reason,$jit_reason" == *"no_regdump"* ]]; then
            INFRA_NO_REGDUMP=$((INFRA_NO_REGDUMP+1))
        elif [[ "$interp_reason,$jit_reason" == *"multi_regdump"* ]]; then
            INFRA_MULTI_REGDUMP=$((INFRA_MULTI_REGDUMP+1))
        elif [[ "$interp_reason,$jit_reason" == *"sentinel_mismatch"* ]]; then
            INFRA_SENTINEL=$((INFRA_SENTINEL+1))
        else
            INFRA_OTHER=$((INFRA_OTHER+1))
        fi
        echo "INFRA $name: interp_reason=$interp_reason jit_reason=$jit_reason" >&2
    fi
done

# Score: fraction of passing tests (0-100)
if [ "$TOTAL" -gt 0 ]; then
    SCORE=$(( PASS * 100 / TOTAL ))
else
    SCORE=0
fi

RISKY_FAIL=$((RISKY_TOTAL - RISKY_PASS))

echo "METRIC pass=$PASS"
echo "METRIC fail=$FAIL"
echo "METRIC total=$TOTAL"
echo "METRIC infra_fail=$INFRA_FAIL"
echo "METRIC fail_equiv=$EQUIV_FAIL"
echo "METRIC infra_timeout=$INFRA_TIMEOUT"
echo "METRIC infra_emu_exit=$INFRA_EMU_EXIT"
echo "METRIC infra_no_regdump=$INFRA_NO_REGDUMP"
echo "METRIC infra_multi_regdump=$INFRA_MULTI_REGDUMP"
echo "METRIC infra_sentinel=$INFRA_SENTINEL"
echo "METRIC infra_other=$INFRA_OTHER"
echo "METRIC risky_total=$RISKY_TOTAL"
echo "METRIC risky_pass=$RISKY_PASS"
echo "METRIC risky_fail=$RISKY_FAIL"
echo "METRIC risky_fail_equiv=$RISKY_FAIL_EQUIV"
echo "METRIC risky_infra_fail=$RISKY_INFRA_FAIL"
echo "METRIC score=$SCORE"
echo "METRIC selected_vectors=$TOTAL"
echo "METRIC validation_complete=1"

# Fail closed on every semantic or infrastructure failure. Metrics are evidence,
# not a substitute for process status: callers must never accept a partial run
# merely because the final metric-printing command succeeded.
if [ "$TOTAL" -eq 0 ] || [ "$FAIL" -ne 0 ] || [ "$INFRA_FAIL" -ne 0 ] || \
   [ "$RISKY_TOTAL" -ne "$TOTAL" ] || [ "$RISKY_PASS" -ne "$RISKY_TOTAL" ]; then
    exit 1
fi
exit 0

# DBNE_LOOP_CMPI: DBNE with CMPI condition, exits when D1==3
# BSR_IN_DBRA_LOOP: BSR to subroutine inside DBRA loop, 4 iterations
# TABLE_LOOKUP: PC-relative table read via scaled index
# DBRA_LOOP_1000: 1000-iteration loop
# SWAP_PACK: pack two words into a long via SWAP+MOVE.W+SWAP
# LEA_SCALED_INDEX: LEA (0,A0,D1.L*4) scaled indexed addressing
# MULTI_BRANCH: sequential BEQ+BNE with flag propagation
# ANDI_L_DN: AND.L immediate with register
# EOR_SELF: EOR.L Dn,Dn (self-XOR = clear, Z=1)
