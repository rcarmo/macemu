# SheepShaver PPC JIT — Next Phase Plan

## Goal

Move from the current safe basic-block/chain JIT toward revalidated region-level optimisations.
Lazy CR0 uses a callee-saved pending-result copy, and register allocation covers straight-line
blocks, including memory-touching blocks through per-access RA barriers. The next phase is
proof-driven per-label state for internal conditional branches, not blind optimisation.

## Baseline (current)

- MacBench CPU: **835 historical** (JIT ≈ interpreter in that run; not a current repeatable gate)
- MacBench FPU: **1027 historical** (> G3/300 in that run; not a current repeatable gate)
- Harness: 303/303 pass, score=100 (accepted 2026-08-02 gate)
- Block cache: 8192-bucket hash table with 16384-entry pool
- Block size: 512 instructions max
- Register allocation: active in straight-line blocks; guest-memory accesses flush/reset the cache at each access; internal conditional-branch blocks use direct struct access
- Flags: lazy CR0 active; Rc=1 result copied to x19 and materialised at CR consumers/exits
- Block chaining: compile-time `chain_code` plus runtime back-patching is implemented
- Fallback policy: only `jblk.complete` blocks execute natively; incomplete/barrier blocks are interpreted
- Bounded benchmark: warm steady-state direct JIT took 1.888748037× interpreter time on `ss-ppc-register-loop-v1`; this dispatch-heavy result is not an application-performance claim

## Implementation order

### Phase 1: Hash + chaining block cache
- [x] Replace direct-mapped `jit_bc[4096]` with hash table + linked list overflow
- [x] Size: 8192 buckets, chain via next pointer in entry struct
- [x] Keep invalidate_pc and flush semantics identical
- [x] Historical harness and boot gates passed; current full gate is 303/303 plus the canonical JIT desktop hold

### Phase 2: Lazy CR/flags
- [x] Add lazy CR0 scaffolding and consumers
- [x] Historical harness gate passed; current full gate is 303/303
- [x] Re-enabled safely: `lazy_update_cr0()` copies the result to x19 (`RCR0`) and materialises at consumers/exits

### Phase 3: Register allocation within blocks
- [x] Add x21–x28 PPC GPR cache scaffolding, LRU eviction, and dirty flush logic
- [x] Historical harness gate passed during the original tranche; current full gate is 303/303
- [x] Broadened to straight-line memory-touching blocks with per-access RA barriers
- [ ] Broaden to internal conditional-branch blocks only after implementing per-label RA state

### Phase 4: Region JIT (block chaining)
- [x] Fast JIT dispatch inner loop: after each block, check JIT cache directly without interpreter block cache round-trip (`a8afdf92`)
- [x] Compile-time block chaining: each compiled block records a `chain_code` entry point (after prologue); `emit_epilogue_with_pc` emits `B chain_code` instead of 6×LDP+RET when the target is already in JIT cache (`4bcd9336`)
- [x] Runtime back-patching: chain site pool (4096 entries) records unresolved epilogue sites; `jit_bc_insert` patches them with `B chain_code` when the target block is compiled (`e1f11657`)
- [x] Chain invalidation: full JIT cache flush atomically clears both jit_bc_pool and chain_site_pool
- [x] `rld*` correctness: rldicl/rldicr/rldic mask now applied; rldcl/rldcr emit ROL not ROR (`8ad71eed`)
- [ ] MacBench validation: runtime benefit requires actual Mac OS boot (ROM + disk); the old tight-loop `addi+bdnz` probe used intra-block CBNZ and is unaffected by inter-block chaining
- [x] Fallback safety audit: `sc`, `tw`, `twi`/`tdi`, and unknown SPR forms return `false` and are interpreted; runtime-count `lswx`/`stswx` later gained proven inline generators with RA barriers

Historical note: the old `addi+bdnz` throughput probe used intra-block CBNZ and was not methodologically comparable to the current interpreter/JIT benchmark. The accepted 2026-08-02 workload deliberately terminates a native block at `bdnz` on each iteration, preserves an exact `6*N+1` architectural denominator, and measures warm steady-state `cpu->execute()` only; see `docs/AARCH64_JIT_BENCHMARK_RESULT_20260802.md`. Compile-time chaining fires when the target was compiled before the source block. Runtime patching captures the forward-branch case (target compiled after source).

## Success criteria

| Metric | Before | Target |
|--------|--------|--------|
| MacBench CPU | 835 historical | > 1200 after revalidated optimizations |
| MacBench FPU | 1027 historical | > 1100 after revalidated optimizations |
| Harness | 303/303 current gate | 303/303 |
| Regression harness | 13/13 | 13/13 |
| Boot Mac OS 8.1 | ✅ | ✅ |

## Files to modify

- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.cpp` — all phases
- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.h` — API changes
- `SheepShaver/src/kpx_cpu/src/cpu/ppc/ppc-cpu.cpp` — block chaining dispatch

## Rules

- Every phase must pass the current complete harness (303/303 at this document revision) before moving to the next
- Every phase must boot Mac OS 8.1 to desktop without crash
- Commit after each phase, not at the end
- If a phase causes regression, revert and investigate before proceeding
