# SheepShaver PPC JIT — Next Phase Plan

## Goal

Move from basic-block JIT to a region JIT with register allocation and lazy flags,
delivering measurable MacBench improvement over interpreter baseline (838 CPU / 1027 FPU).

## Baseline (current)

- MacBench CPU: **835** (JIT ≈ interpreter — no improvement)
- MacBench FPU: **1027** (already > G3/300 baseline)
- Harness: 209/209 pass, score=100
- Block cache: 4096 direct-mapped
- Block size: 512 instructions max
- Register allocation: none (every insn does LDR/STR to struct)
- Flags: always materialized (emit_update_cr0 on every Rc=1 instruction)
- Block chaining: none (dispatch loop between every block)

## Implementation order

### Phase 1: Hash + chaining block cache
- [x] Replace direct-mapped `jit_bc[4096]` with hash table + linked list overflow
- [x] Size: 8192 buckets, chain via next pointer in entry struct
- [x] Keep invalidate_pc and flush semantics identical
- [x] Test: harness 209/209, boot Mac OS 8.1

### Phase 2: Lazy CR/flags
- [ ] Add `cr0_valid` flag to compilation state — tracks whether CR0 is current
- [ ] `emit_update_cr0()` sets `cr0_valid = true`
- [ ] Instructions that READ CR0 (bc with BI=0..3, mfcr, crand etc.) check `cr0_valid`
  - if invalid, materialise from last result register before reading
- [ ] Instructions with Rc=1 set `cr0_valid = false` (mark stale), save result reg identity
- [ ] Only emit CR0 writeback at block boundaries or when CR0 is read
- [ ] Test: harness 209/209 (critical — flags are the #1 source of JIT bugs)

### Phase 3: Register allocation within blocks
- [ ] Allocate ARM64 callee-saved x21–x28 (8 registers) as PPC GPR cache
- [ ] Track mapping: `gpr_host[32]` = -1 (not cached) or ARM64 reg number
- [ ] On first use of PPC GPR N: assign next free host reg, emit LDR from struct
- [ ] On subsequent use: reuse host reg directly (no LDR/STR)
- [ ] At block exit (epilogue): flush all dirty host regs back to struct via STR
- [ ] Eviction policy: LRU when all 8 slots full — STR the oldest back to struct
- [ ] Test: harness 209/209, MacBench CPU should show measurable improvement

### Phase 4: Region JIT (block chaining)
- [ ] After executing block A → block B, if B is cached, patch A's epilogue:
  - Replace A's `STR PC; LDP; RET` with `B imm` to B's code (skip dispatch)
- [ ] Chain must preserve register allocation: A's dirty regs flushed before chain
- [ ] Guard at chain entry: verify B's start PC matches expected (catch invalidation)
- [ ] On cache flush: break all chains (rewrite patched epilogues back to RET)
- [ ] Test: harness 209/209, boot Mac OS 8.1, MacBench CPU > 1000

## Success criteria

| Metric | Before | Target |
|--------|--------|--------|
| MacBench CPU | 835 | > 1200 |
| MacBench FPU | 1027 | > 1100 |
| Harness | 209/209 | 209/209 |
| Boot Mac OS 8.1 | ✅ | ✅ |

## Files to modify

- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.cpp` — all phases
- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.h` — API changes
- `SheepShaver/src/kpx_cpu/src/cpu/ppc/ppc-cpu.cpp` — block chaining dispatch

## Rules

- Every phase must pass harness 209/209 before moving to next
- Every phase must boot Mac OS 8.1 to desktop without crash
- Commit after each phase, not at the end
- If a phase causes regression, revert and investigate before proceeding
