#!/bin/bash
# Structural regression gate for the post-native GATE3 recovery contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CPU_CPP="$SCRIPT_DIR/../src/kpx_cpu/src/cpu/ppc/ppc-cpu.cpp"

region="$(sed -n '/pdi_jit_post:/,/if (!spcflags().empty())/p' "$CPU_CPP")"

fail() {
    echo "GATE3-CONTRACT: FAIL: $*" >&2
    exit 1
}

grep -Fq 'ppc_jit_aarch64_invalidate_pc(jblk.ppc_start_pc);' <<<"$region" || \
    fail 'offending native block is not invalidated'
grep -Fq 'ppc_jit_ratio_skip_jit_entries++;' <<<"$region" || \
    fail 'Gate3 skip ratio is not retained'
grep -Fq 'ppc_jit_skip_hist_record(jit_skip_pc, jit_skip_opcode, jit_skip_reason);' <<<"$region" || \
    fail 'Gate3 diagnostic is not recorded'
grep -Fq 'goto do_interpret;' <<<"$region" || \
    fail 'JIT-produced successor is not handed to uncached interpretation'

if grep -Fq 'set_register(powerpc_registers::PC' <<<"$region"; then
    fail 'Gate3 rewinds architectural PC after a committed native prefix'
fi
if grep -Fq 'goto skip_jit;' <<<"$region"; then
    fail 'Gate3 reuses the block-leader decode entry'
fi

echo 'GATE3-CONTRACT: PASS: committed successor preserved and decoded uncached'
