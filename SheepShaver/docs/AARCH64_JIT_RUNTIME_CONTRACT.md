# SheepShaver AArch64 JIT Runtime Contract

## Purpose

This document defines the runtime contract for the SheepShaver PPC → AArch64 direct-codegen JIT.

It is not a bring-up diary. It is not a frontier log.
It is the technical statement of what compiled code, the dispatch loop, and fallback paths
are allowed to assume about machine state at every boundary.

If code violates this contract, the code is wrong even if the current workload happens to boot.

---

## Scope

Primary implementation files:

- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.cpp` — block compiler
- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.h` — public API
- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit-glue.hpp` — dispatch integration
- `SheepShaver/src/kpx_cpu/src/cpu/jit/aarch64/jit-target-cache.hpp` — RWX cache and icache flush
- `SheepShaver/src/kpx_cpu/src/cpu/ppc/ppc-cpu.cpp` — kpx_cpu execute loop and JIT dispatch
- `SheepShaver/src/kpx_cpu/sheepshaver_glue.cpp` — SIGSEGV handler, test harness

---

## Terms

### Architectural state

State that the interpreter and the rest of the emulator are allowed to observe directly.

- `regs.pc` (at struct offset PPCR_PC = 1052)
- `regs.gpr[0..31]` (offsets 0..124)
- `regs.gpr_hi[0..31]` (offsets 128..252, G5/PPC64 upper halves)
- `regs.fpr[0..31]` (offsets 256..511, 64-bit doubles)
- `regs.cr` (offset PPCR_CR = 1024)
- `regs.xer` as bytes: SO (1028), OV (1029), CA (1030), byte_count (1031)
- `regs.fpscr` (offset PPCR_FPSCR = 1040)
- `regs.lr` (offset PPCR_LR = 1044)
- `regs.ctr` (offset PPCR_CTR = 1048)

### Virtual state

State temporarily held only in ARM64 registers and not yet written back to the struct.
This JIT has **limited virtual state**. Many blocks read and write directly to the struct via
`[RSTATE, #offset]` loads and stores. A conservative register allocator caches PPC GPRs in
x21–x28 for straight-line blocks (no internal conditional branches). Guest-memory accesses are
permitted in RA-enabled blocks: an **RA barrier** (`ra_flush_all()` + `ra_reset()`) is emitted
immediately before each guest-memory instruction, so the register struct is authoritative at
every memory boundary — exactly equivalent to direct struct access there — and no fallback,
fault, or helper/MMIO re-entry path ever observes dirty cached GPRs. Blocks with internal
conditional branches still use direct struct access (the cache scaffold is path-insensitive:
a branch target reached with a different mapping than the fall-through would read wrong regs).

### Materialized state

Architectural state written back to the struct so that the interpreter or fallback paths may
safely observe it.

### Boundary

Any transition where current compiled code can no longer assume it exclusively owns the state.

- block exit (epilogue emitted)
- interpreter fallback (compile_one returns false → `emit_epilogue_with_pc`)
- block terminator (blr, b, bclr, bcctr, bc* with Rc)
- EMUL_OP trap (opcode 6 class) — always an incomplete block → interpreter handles
- JIT disabled explicitly with `SS_USE_JIT=0` → interpreter handles entire block

---

## Register and state model

### 1. ABI

Generated blocks are called as:

```c
void compiled_block(void *regs);
```

`x0` on entry = pointer to `powerpc_registers` struct.
The prologue moves x0 to x20 (callee-saved):

```
STP   FP, LR, [SP, #-16]!
STP   x19, x20, [SP, #-16]!   // x20 = RSTATE
STP   x21..x28, ...
MOV   x20, x0
```

The epilogue restores and returns:

```
LDP   x27, x28, [SP], #16
...
LDP   FP, LR, [SP], #16
RET
```

Callee-saved host registers x19–x28 are always preserved across the block boundary.
Scratch registers x0–x3 (RTMP0/1/2/3) are caller-saved and have no meaning at block entry or exit.

### 2. PC model

There is exactly one PC representation: `regs.pc` at offset PPCR_PC.

**At block entry**: PPCR_PC = block start PC (set by the kpx_cpu interpreter's last `increment_pc`).

**During block execution**: PPCR_PC is NOT updated per-instruction. It retains the block entry value.

**At block exit**: PPCR_PC is written by `emit_epilogue_with_pc(next_pc)` — always the PC of the
next instruction to execute (i.e. the instruction after the last compiled one, or the branch target
for taken branches).

**Contract consequence**: If a fault occurs mid-block, PPCR_PC contains the block entry PC.
The SIGSEGV handler will restart from that PC. The interpreter will re-execute the entire block
cleanly. This is correct (restartability = block-level granularity, not instruction-level).

**Rule**: No path may read PPCR_PC mid-block and assume it reflects the currently executing
instruction. Only the block entry PC is valid mid-block.

### 3. Flag model

**Lazy CR0 is active**: Rc=1 results are copied into x19 (`RCR0`, callee-saved) and
materialised only when CR is consumed or the block exits. The x19 copy fixes the earlier
boot-regression class where the pending result lived in scratch state that later code could clobber.

**XER and FPSCR** are always materialised immediately.

- Instructions with RC=1 call `lazy_update_cr0()`, which saves the result in `RCR0` and marks CR0 pending.
- CR consumers (`mfcr`, CR logical ops, compare/CR writers that merge fields, conditional branches, epilogues) call `lazy_flush_cr0()` first.
- Every carry-setting instruction calls `emit_write_xer_ca_from_carry()` which writes PPCR_XER_CA.
- FPSCR rounding mode is synced to ARM64 FPCR on `mtfsfi`/`mtfsf`/`mtfsb0`/`mtfsb1`.

**Contract**: At every block boundary, CR, XER.CA, XER.SO, and FPSCR are architectural.
`lazy_flush_cr0()` is called by every epilogue path; no downstream code observes stale CR0.

**Rule**: Any new opcode handler that modifies CR, XER, or FPSCR must either materialize directly
or integrate with the lazy CR0 protocol before any consumer/fallback boundary.

### 4. GPR model

GPRs are read with `emit_load_gpr(rd, n)` and written with `emit_store_gpr(rs, n)`. When register
allocation is disabled for the block these are direct `LDR Wd, [RSTATE, #PPCR_GPR(n)]` /
`STR Wd, [RSTATE, #PPCR_GPR(n)]`. When RA is enabled they route through the x21–x28 cache
(`ra_load`/`ra_store`), and dirty values are written back by `ra_flush_all()` at every block exit
and at every RA barrier (immediately before a guest-memory access).

**Contract**: At every block boundary, and at every guest-memory access within an RA-enabled
block, all GPRs are architectural. Between those points an RA-enabled block may hold GPRs only
in x21–x28 (callee-saved, so preserved across the guarded-access helper BLR). Cached 32-bit PPC
GPR values must be canonical zero-extended in their host X register; all RA scratch/cache moves
for low GPRs therefore use a W-register move (`a64_mov_w_reg`), not an X move.

---

## Block lifecycle contract

### Block compiler entry (`ppc_jit_aarch64_compile`)

**Preconditions**:
- `pc` is a valid PPC address within `[ram, ram + ramsize)`
- `ram` and `ramsize` are consistent with the current MAC RAM mapping
- JIT cache has space (`jit_cache_wp < jit_cache_end - 2048`); the 2048-word (8KB) margin
  guarantees a fresh block compiles before the per-instruction overflow guard trips (large
  blocks: guarded load/store sequences, unrolled string ops)

**What the compiler does**:
1. Emits prologue (callee-save, x20 = regs ptr)
2. Fetches PPC instructions from `ram[pc - (uint32_t)(uintptr_t)ram]`
3. For each instruction, calls `compile_one(op, cur_pc)`
4. If `compile_one` fails: emits `emit_epilogue_with_pc(cur_pc)`, marks `complete = false`, stops
5. If block terminator hit: emits terminator epilogue, stops
6. After loop: if no `RET` emitted yet, emits `emit_epilogue_with_pc(cur_pc)`
7. Flushes icache for the generated code range
8. Returns `ppc_jit_block` with {code, code_size, ppc_start_pc, ppc_end_pc, n_insns, complete}

**Postconditions**:
- Generated code is executable
- `out->complete = true` iff every instruction in the block was compiled natively
- `out->complete = false` iff the block was truncated at an unhandled opcode

### Block execution path

In `ppc-cpu.cpp` (`pdi_execute` label):

```
1. Check `SS_USE_JIT=0` diagnostic override — if set, goto skip_jit
2. Call ppc_jit_aarch64_compile(pc(), RAMBaseHost, RAMSize, &jblk)
3. If compilation failed or `!jblk.complete`: goto `skip_jit` (interpreter handles it)
4. Call `fn(regs_ptr())` — executes the compiled block
5. Validate PC: if `jit_pc` is outside RAM/ROM range, log, invalidate the block, and fall back
6. Check spcflags (interrupts, cache invalidation)
7. Fast-dispatch to the next JIT block if already complete and cached; otherwise continue via the interpreter block cache
```

**Contract on step 4**: On return from fn(), PPCR_PC is the next PC to execute.
All GPRs, CR, XER, FPR, LR, CTR are architectural.

**Contract on step 5**: PC validation is a containment guard, not an expected code path.
A compiled block that sets PC to an illegal value is a compiler bug.

### Interpreter fallback contract

When `jblk.complete == false`, the dispatch loop calls `goto skip_jit` and the interpreter
executes the block instead. No state from the partial compilation attempt is observable —
the JIT only modifies the code cache, not the register struct, during compilation.

The interpreter starts from the same `pc()` value the JIT would have started from.
The two paths are observationally equivalent for any block that reaches this fallback.

---

## Gates — ownership and intent

### Gate 1: `SS_USE_JIT=0` environment variable

**Location**: `ppc-cpu.cpp` line ~698

**Classification**: DIAGNOSTIC OVERRIDE — JIT is enabled by default when compiled in.

**What it protects**: Ability to force interpreter-only execution for debugging and comparison.

**Invariant guarded**: Interpreter/JIT build parity (Invariant 5 from JIT-APPROACH-RESET).

**Expiry condition**: Keep as a runtime escape hatch while the JIT remains experimental.

**Replacement**: None needed for production packaging; default execution uses the JIT and `SS_USE_JIT=0` is opt-out.

**Proof workload**: boot-to-desktop + Speedometer benchmark green.

---

### Gate 2: `blk.complete` check in ppc-cpu.cpp

**Location**: `ppc-cpu.cpp` line ~702: `if (ppc_jit_aarch64_compile(...) && jblk.complete)`

**Classification**: CONTAINMENT — prevents executing partial blocks natively.

**What it protects**: Correctness of interpreter fallback and fallback-only instructions.
A failed compilation is a compile-time probe only; generated code from that probe is not executed.
The interpreter starts from the original block PC and owns the uncompiled instruction semantics.
This is required for barrier-worthy/fallback-only instructions such as `sc`, `tw`, `twi`/`tdi`,
`lswx`/`stswx`, and unknown SPR access.

**Invariant guarded**: Exact fallback semantics for privileged, trap, runtime-helper, and
unimplemented instructions.

**Status for relaxation**: Keep this gate active. Partial-block native execution would need a
separate proof that every `return false` point represents a resumable PC and not a semantic
barrier that must be interpreted from the original block entry.

**Proof workload**: opcode harness, targeted fallback probes, and boot-to-desktop workloads.

---

### Gate 3: `compile_one` returning false

**Location**: `ppc-jit.cpp` — every unrecognized opcode returns false.

**Classification**: PERMANENT SEMANTIC EXCLUSION for opcodes not yet implemented;
DIAGNOSTIC for opcodes that should be implemented but aren't.

**What it protects**: Prevents executing incorrect code for unimplemented instructions.

**Rule**: Every `return false` path in `compile_one` should have a comment classifying it as:
- `/* UNIMPLEMENTED: [opcode name] — not yet native, interpreter handles */`
- `/* EXCLUDED: [reason] — permanent interpreter delegation */`
- `/* FALLBACK: [reason] — exact interpreter/privileged/trap semantics required */`

The current audit has added classification for the highest-risk fallback-only paths; keep doing
this whenever a fallback site is touched.

---

### Gate 4: EMUL_OP class (opcode 6) — no handler in compile_one

**Location**: `ppc-jit.cpp` — opcode 6 has no case in the switch, returns false.

**Classification**: PERMANENT SEMANTIC EXCLUSION — EMUL_OP blocks invoke the Mac OS emulation
layer and are not amenable to native inline codegen without a full helper infrastructure.

**Invariant guarded**: This is the "exact runtime helper + block barrier" pattern from the
JIT-APPROACH-RESET document, applied correctly. EMUL_OP is always handled by the interpreter,
providing a clean block barrier.

**Status**: Correct and permanent. Do not attempt to inline EMUL_OP without a full
barrier-and-helper framework.

---

## Block cache

**Status**: ✅ IMPLEMENTED (Phase 4b, 2026-04).

The JIT uses a hash + chaining block cache: 8192 buckets with 16384 pool entries and an
8 MB production code cache (`ppc_jit_aarch64_init(8192)`). Lookup by `uint32_t ppc_pc`
before compilation; on hit, execute cached code directly.
Invalidation: cache-overflow and containment invalidations use a full `jit_bc_flush()` because
direct-chain back-patching means an older block may contain a raw `B chain_code` to a target; a
per-PC unlink cannot unpatch those emitted branches. The private `jit_bc_invalidate_pc()` is only
safe for internal table maintenance when no direct predecessor can still branch to the code.
**icbi** is handled by `ppc_jit_aarch64_icbi(ea)`: it full-flushes only when a live compiled
block's guest range `[pc, pc+n_insns*4)` overlaps the icbi'd 32-byte line, and otherwise skips
(nothing compiled there = nothing to invalidate). A conservative `[min,max)` span of all
compiled-block guest PCs (widened on insert, reset on flush; endpoints are uint64_t to avoid
32-bit wrap) lets the handler fast-reject the common no-overlap icbi without scanning the block
pool. This replaced an unconditional full flush on every icbi, which
measured ~3550 full cache wipes per desktop boot (each wiping a near-empty cache, so the
working set was recompiled thousands of times) — the dominant host-CPU sink. **isync** is a
block terminator only (serialization barrier; no cache invalidation). The production cache was
then increased from 4 MB to 8 MB, reducing cache-full flushes during a desktop boot from ~45
to ~2 while staying far below the 384 MB host-RSS budget.

Previous concern (now resolved): compiled blocks accumulated without reuse; the code cache
would fill and all subsequent blocks fell back to the interpreter.

---

## Helper contract

Compiled blocks call a small set of out-of-line C helpers for guest-memory accesses that fall
outside the statically-enumerated 1:1-mapped regions, and for atomic reservation ops:

- `sheepshaver_jit_safe_load` / `sheepshaver_jit_safe_store` — the slow path of a guarded
  D-form/indexed load/store. The fast path inlines the access when the EA is in a known-mapped
  region (`emit_direct_access_valid_check`); otherwise the helper mincore-probes the page on each
  slow-path access and reads/writes genuinely-mapped guest memory via Read/WriteMacInt like the
  interpreter, leaving the old value only for truly-unmapped MMIO. Positive mincore results are not
  cached, because guest/host mappings can change independently of JIT cache flushes. Both the inline
  valid-check and the helpers are
  access-size-aware: byte/half/word checks use the actual access size, zero-page store rejection
  is overlap-based, and direct valid ranges are represented by start+size/count arithmetic rather
  than wrapping 32-bit end-exclusive endpoints. This covers highmem
  `[0xffff0000, 0x1_0000_0000)` and ordinary RAM/ROM ranges. Framebuffer D-form accesses are
  intentionally helper-routed instead of direct-inlined because `screen_base`/`cur_mode` can change
  on video mode switches and `SheepShaver/src/SDL` is shared via the BasiliskII SDL symlink.
- `sheepshaver_jit_lwarx` / `sheepshaver_jit_stwcx` — real reservation semantics for atomic
  acquire/retry loops.

These helpers follow the AArch64 ABI, so callee-saved x19–x29 (RSTATE, RCR0, the RA cache, and saved
x29/A64_FP when used as a temporary EA scratch) survive the BLR. They may, however, re-enter the
emulator (MMIO handlers) and read — or modify — guest GPRs via RSTATE. The **RA barrier**
(flush-all-dirty + reset before each guest-memory access) exists precisely to keep the register
struct authoritative across these calls, so the helper and any re-entry observe coherent guest state.
Each helper call is otherwise a localized operation, not a full block barrier: the block continues
after it. For guarded scalar update-form load/store instructions, generated code preserves EA in
x29 across the helper and writes rA after the memory operation, matching interpreter ordering.

Any further helpers must be classified as H1 (exact + mandatory barrier) unless explicitly proven
to be H2 (continuation allowed after proof of state consistency — as the guarded-access helpers
are, via the RA barrier and callee-saved discipline).

---

## Fault recovery contract

### Scenario: fault in compiled code

If a compiled block faults (e.g., bad memory address from a LDR/STR in compiled code):
1. The host SIGSEGV fires at the ARM64 instruction that faulted.
2. `sigsegv_handler()` in `sheepshaver_glue.cpp` is called.
3. The handler checks `cpu->pc()` (reads PPCR_PC) to determine if we are in a Mac fault context.
4. PPCR_PC = block entry PC (see PC model above).
5. The handler can correctly identify the Mac context and either handle (known ROM faults) or dump+quit.

### Restartability guarantee

A compiled block is restartable from its entry PC. The interpreter will re-execute the block
cleanly from that PC. Because the JIT does not commit partial instruction results (each handler
is atomic from the struct's perspective), there is no partial-commit hazard.

**Rule**: Any future instruction handler that spans multiple struct writes must either:
1. Be atomic from a fault perspective (all writes or none), OR
2. Emit an explicit PC update mid-handler to enable per-write restartability.

---

## PC contract at dispatch loop boundaries

### Before JIT call (`fn(regs_ptr())`)

- `pc()` = `regs.pc` = current block entry PC (correct, set by interpreter's last `increment_pc`)
- All GPRs, CR, XER, LR, CTR = architectural

### After JIT call returns

- `pc()` = `regs.pc` = next PC to execute (set by epilogue)
- All GPRs, CR, XER, FPR, LR, CTR = architectural

### After fallback to interpreter

- `pc()` = same value as before JIT call (JIT compilation does not modify struct)
- All state = unchanged from pre-JIT-call

---

## Opcode classification

All PPC opcodes handled by the JIT are in one of three categories:

### Category A: Full inline codegen

The opcode is fully handled natively. On exit from the handler, all modified architectural
state is materialized. Examples: add, sub, or, and, ld/st, compare, branch.

### Category B: Interpreter delegation (compile_one returns false)

The opcode terminates the block. The interpreter handles it. This is the correct and safe
pattern for all unimplemented or barrier-worthy classes. Examples: EMUL_OP (opcode 6),
unimplemented AltiVec, unimplemented FPU families.

### Category C: (Not yet present) Helper dispatch

Future use: for complex opcodes that can be compiled to a helper call with a mandatory block
barrier. Not implemented in the current JIT.

---

## Invariant summary table

| # | Invariant | SheepShaver PPC JIT status |
|---|-----------|---------------------------|
| 1 | Exactly one authoritative PC at each boundary | ✅ PPCR_PC is the single source of truth. Written at block exit by epilogue. Block entry PC is stale mid-block (see note). |
| 2 | Lazy flags valid only while ownership is unambiguous | ✅ Lazy CR0 active with pending result in callee-saved x19; `lazy_flush_cr0()` at consumers/epilogues. XER/FPSCR always immediate. |
| 3 | Helper calls are semantic barriers | ✅ Guarded load/store and lwarx/stwcx helpers are localized H2 calls (callee-saved x19–x28 + RA barrier keep the struct coherent across re-entry). EMUL_OP and unhandled ops remain full block barriers via interpreter delegation. |
| 4 | Block chaining must not bypass validation | ✅ Compile-time chaining and runtime back-patching are implemented; chained targets use `chain_code`; containment/corrupt-entry invalidation is a full flush because per-PC unlinking cannot unpatch already-emitted direct branches. |
| 5 | Interpreter and JIT builds agree on shared semantics | ✅ 264/264 interp-vs-production-JIT opcode equivalence (the harness compares interpreter mode against the real JIT dispatch loop; 2026-06-22 this replaced a JIT-vs-JIT determinism check and surfaced+fixed nand/addme/subfme/divw codegen bugs; later added RA-width, string/multiple, SPR/FPSCR/AltiVec, addis/lis, vsel, AltiVec FP compare, vperm control-mask, bcctr CTR-decrement, fres delegation, AltiVec vector-sum delegation, AltiVec average/saturating add-sub delegation, and AltiVec merge delegation regressions). `bcl` LR update fixed (2026-05). |
| 6 | Fault recovery: restartable from coherent state | ✅ Block-level restartability. PPCR_PC = block entry on fault. Interpreter re-runs block. |
| 7 | Every exception path chooses exact model or barrier | ✅ EMUL_OP and unhandled opcodes → interpreter delegation (Category B). |

---

## Known weak seams

### Weak seam 1: ~~No block address cache~~ ✅ RESOLVED (Phase 4b)

Hash + chaining block cache (8192 buckets) implemented. Compiled blocks are reused on
subsequent visits. See `jit_bc_pool` / `jit_bc_heads` in `ppc-jit.cpp`.

### Weak seam 2: Partial-block execution remains disabled

`jblk.complete` is still required before native execution. This is intentionally conservative:
some `return false` paths are semantic barriers, not merely unimplemented inline code. Enabling
partial-block execution would require auditing every fallback site and proving resumability.

### Weak seam 3: Register allocation excludes only internal-branch blocks

The x21–x28 GPR cache is enabled for all straight-line blocks. Guest-memory accesses are
handled by an RA barrier (flush-all-dirty + reset before each access), so memory-touching
blocks now use RA — measured at ~72% of all compiled blocks (up from ~34%). Only blocks with
internal conditional branches remain excluded: the cache scaffold is path-insensitive and would
need per-label RA state before a branch target could be entered with a guaranteed mapping.

### Weak seam 4: PC validation guard after JIT call may mask compiler bugs

The PC range check after `fn(regs_ptr())` silently skips blocks that set an out-of-range PC.
This can mask JIT compiler bugs. It should log the occurrence rather than silently continuing.

### Weak seam 5: Fallback classification coverage

Several lower-risk `return false` paths in `compile_one` still lack explicit classification
comments. As a result, the distinction between "not yet implemented", "permanently excluded",
and "must fall back for exact interpreter semantics" is not always visible in code.

### Weak seam 6: FPSCR sync coverage

FPSCR rounding mode is synced on `mtfsfi`/`mtfsf`/`mtfsb0`/`mtfsb1`. It is not verified
that all ARM64 FP instructions correctly observe the rounding mode. This should be audited
systematically against the FPSCR-to-FPCR mapping.

### Weak seam 7: `bcl` with combined CTR+condition (`lk=1`) falls to interpreter

The `bc` handler correctly falls back to the interpreter for `lk=1` on the combined
CTR+condition path (`if (lk) return false`). The three simpler paths now correctly call
`emit_save_lr_if_link(pc, lk)` before branching (fixed 2026-05). The combined path remains
an interpreter delegation until a JIT helper for that BO combination is added.

---

## Contributor checklist

Before changing the JIT compiler, dispatch path, or fallback behavior:

1. Which boundary is being changed?
2. Is PPCR_PC authoritative at that boundary after the change?
3. Are CR and XER still materialized before the changed boundary?
4. Can the interpreter resume safely if the JIT path fails at that point?
5. Does this change affect the behavior of interpreter-only builds?
6. Which golden workload proves the change is safe?

If any answer is unclear, the change is not ready.
