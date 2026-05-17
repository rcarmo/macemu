# SheepShaver PPC JIT — Next Phase Plan

## Goal

Move from the current safe basic-block/chain JIT toward revalidated region-level optimizations.
Register allocation and lazy CR0 both have scaffolding in-tree, but are currently disabled after
boot-regression risk; the next phase is proof-driven re-enablement, not blind optimization.

## Baseline (current)

- MacBench CPU: **835** (JIT ≈ interpreter — no improvement)
- MacBench FPU: **1027** (already > G3/300 baseline)
- Harness: 209/209 pass, score=100
- Block cache: 8192-bucket hash table with 16384-entry pool
- Block size: 512 instructions max
- Register allocation: scaffolded but disabled; active path uses direct struct LDR/STR
- Flags: CR0 is currently materialized immediately; lazy CR0 scaffold is disabled
- Block chaining: compile-time `chain_code` plus runtime back-patching is implemented
- Fallback policy: only `jblk.complete` blocks execute natively; incomplete/barrier blocks are interpreted

## Implementation order

### Phase 1: Hash + chaining block cache
- [x] Replace direct-mapped `jit_bc[4096]` with hash table + linked list overflow
- [x] Size: 8192 buckets, chain via next pointer in entry struct
- [x] Keep invalidate_pc and flush semantics identical
- [x] Test: harness 209/209, boot Mac OS 8.1

### Phase 2: Lazy CR/flags
- [x] Add lazy CR0 scaffolding and consumers
- [x] Test: harness 209/209
- [ ] Revalidate before enabling: current active path materializes CR0 immediately (`lazy_update_cr0()` calls `emit_update_cr0()`) after a boot-regression risk

### Phase 3: Register allocation within blocks
- [x] Add x21–x28 PPC GPR cache scaffolding, LRU eviction, and dirty flush logic
- [x] Test: harness 209/209 during original tranche
- [ ] Revalidate before enabling: current active `emit_load_gpr()`/`emit_store_gpr()` path uses direct struct access after a boot-regression risk

### Phase 4: Region JIT (block chaining)
- [x] Fast JIT dispatch inner loop: after each block, check JIT cache directly without interpreter block cache round-trip (`a8afdf92`)
- [x] Compile-time block chaining: each compiled block records a `chain_code` entry point (after prologue); `emit_epilogue_with_pc` emits `B chain_code` instead of 6×LDP+RET when the target is already in JIT cache (`4bcd9336`)
- [x] Runtime back-patching: chain site pool (4096 entries) records unresolved epilogue sites; `jit_bc_insert` patches them with `B chain_code` when the target block is compiled (`e1f11657`)
- [x] Chain invalidation: full JIT cache flush atomically clears both jit_bc_pool and chain_site_pool
- [x] `rld*` correctness: rldicl/rldicr/rldic mask now applied; rldcl/rldcr emit ROL not ROR (`8ad71eed`)
- [ ] MacBench validation: runtime benefit requires actual Mac OS boot (ROM + disk); tight-loop harness uses intra-block CBNZ which is unaffected by inter-block chaining
- [x] Fallback safety audit: fallback-only instructions (`sc`, `tw`, `twi`/`tdi`, `lswx`/`stswx`, unknown SPR) now return `false` and are interpreted

Note: the tight `addi+bdnz` benchmark uses intra-block CBNZ (pre-existing) for the inner loop. Compile-time chaining fires when the target was compiled before the source block. Runtime patching captures the forward-branch case (target compiled after source).

## Success criteria

| Metric | Before | Target |
|--------|--------|--------|
| MacBench CPU | 835 historical | > 1200 after revalidated optimizations |
| MacBench FPU | 1027 historical | > 1100 after revalidated optimizations |
| Harness | 209/209 | 209/209 |
| Regression harness | 13/13 | 13/13 |
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
