# AArch64 JIT Audit — Area 4: Helper ABI and Register Ownership

## Scope

This audit covers C-helper calls, physical-register ownership, and scratch-register lifetime in the UAE2026 AArch64 JIT.

Primary files:

- `compiler/codegen_arm64.cpp`
- `compiler/compemu_midfunc_arm64.cpp`
- `compiler/compemu_support_arm.cpp`
- `compiler/compemu_legacy_arm64_compat.cpp`

## Runtime contract

1. A compiled block is a basic block. The tracer stops after every instruction classified by `end_block()` as control flow.
2. Every path leaving compiled code publishes a coherent `regs.pc_p`, `regs.pc_oldp`, and `regs.pc` snapshot before it may return to C.
3. A C helper call is an AAPCS64 ownership boundary:
   - x0–x7 remain argument registers;
   - the indirect call target must not overwrite an argument;
   - all dirty guest state is materialised before the call;
   - all caller-saved allocator associations are discarded before the call.
4. A locked physical register cannot be evicted. A lock remaining on an allocatable register at an opcode boundary is an invariant failure.
5. Scratch virtual-register IDs must be in the configured scratch range and owned exactly once until release.
6. Every scratch vreg must have a distinct in-bounds, pointer-width spill slot; allocator scratch cardinality, host-pointer width, and `regstruct` backing are one contract.
7. Generated opcode objects and JIT support code must be built from the same `regstruct` layout epoch; generated code inlines field addresses and cannot be mixed with stale objects.

## Confirmed defects and fixes

### Call target overwrote argument 3

`compemu_raw_call()` materialised its target in `REG_WORK1`, which is physical x2. Under AAPCS64 x2 carries argument 3. Helpers with three arguments therefore received the helper address in place of their third argument.

The target now uses x18, which is reserved by `always_used[]` and unavailable to the virtual-register allocator.

### Helper calls retained stale host-register associations

Generated `call_helper()` calls could follow `flush(1)` while leaving allocator associations intact. C was then free to clobber x0–x17, but later emitted endblock code could still treat those registers as live guest values.

`call_helper()` now runs `prepare_for_call_1()` and `prepare_for_call_2()` before the call, making the ABI transition local and mandatory.

### Diagnostic observers were not execution-transparent

`B2_JIT_TRACE_SETPC` inserted ordinary C calls inside low-level PC stores and allocator midfuncs. Those sites saved only the register carrying the observed PC. Other targeted observers had the same class of defect: block-entry tracing could clobber freshly restored NZCV, and fallback PC tracing overwrote x0/x1 immediately before the real interpreter handler consumed its opcode and `regstruct` arguments.

Read-only observation now uses one ABI-preserving emitter boundary. It saves/restores x0–x18, NZCV, FPCR, FPSR, and d0–d7 around the C call, then installs observer arguments inside that save window. Callee-saved x19–x28 and d8–d15 retain their normal AAPCS64 guarantees. Set-PC, targeted-PC, neighbour, add, verifier, flush-delta, fallback-resume, and native-entry observers all use this boundary; semantic helpers remain explicit state-materialising ABI transitions.

### Locked ownership failures were hidden

The ARM64 `evict()` path used to clear a lock and continue. `freescratch()` likewise cleared leaked locks at opcode boundaries and omitted allocatable x0/x1 from its check. Both behaviours converted allocator defects into guest corruption.

Locked eviction and leaked opcode-boundary locks now abort at the first violated invariant. Reserved registers are derived from `always_used[]`, rather than from a partial hard-coded range.

### Scratch release could index out of bounds

`release_scratch()` logged an invalid virtual-register ID and then indexed `scratch_in_use[i - S1]` anyway. Invalid IDs and double release now abort before indexing.

### Scratch spill backing was shorter than the allocator range

The allocator defines five integer scratch vregs (`S1..S5`) and maps all five through `regs.scratchregs[i - S1]`, but `regstruct` provided only three slots. A spill of `S4` or `S5` therefore wrote beyond `scratchregs` into adjacent FPU state.

`regstruct::scratchregs` now has five helper-argument elements, and `init_comp()` has a compile-time cardinality assertion against `SCRATCH_REGS`. The mapping can no longer silently outgrow its backing storage.

### Scratch spills truncated native host pointers

`get_n_addr*()` writes native host addresses into ordinary scratch vregs for MOVEM and MOVE16. Those values are 64-bit on AArch64, but generic scratch eviction used the 32-bit `tomem()`/`do_load_reg()` path. An allocator spill could therefore preserve only the low half of a valid host address.

Allocator spill backing is now separate from the 32-bit helper-argument array: `jit_scratch_vregs[S1..S5]` is `uintptr_t`, and scratch reload, dirty writeback, and constant writeback all use X-register loads/stores. Compile-time assertions enforce both cardinality and element width.

### Generated opcode objects retained an obsolete `regstruct` layout

Adding `jit_scratch_vregs[S1..S5]` moved every later `regstruct` field, but the Unix build only rebuilt `compemu_support.o`; `compemu1.o..compemu8.o` had no header dependency and retained old inlined field addresses. Measured BFEXTU code stored extension `0x0022` at old offset 360 while its C helper loaded offset 400, so all helper metadata after the inserted field was read from the wrong slot.

The Unix make rules now give the complete JIT object family an explicit shared dependency on configuration and layout-defining headers. They also model the textual `.cpp` includes that make up the aggregate `compemu_support.o` translation unit; an edit to the ARM64 support, compatibility, codegen, preferences, or MIDFUNC fragments can no longer be reported as up to date. The opcode-equivalence harness also deletes the complete `compemu*.o` family before building, so it cannot validate a mixed layout even with an older generated Makefile.

## Structural regression gate

`jit-test/structural-audit.ts` checks emitter ordering and source-level ownership contracts that ordinary opcode vectors cannot trigger deterministically:

- generated opcode/support objects share explicit `regstruct` layout dependencies, and the harness rebuilds all of them;
- call target uses reserved x18, not x2;
- set-PC observers preserve the complete caller-saved JIT state;
- helper call performs both allocator barrier phases;
- locked eviction and scratch misuse are fail-fast;
- scratch spill backing covers the full `S1..S5` range and preserves `uintptr` values;
- all endblock return paths publish the complete successor PC first;
- trace construction stops at every control-flow boundary.

`jit-test/run.sh` runs this gate after a successful build and before the opcode equivalence workload.

## Verification at landing

- clean AArch64 build;
- structural metrics all `1`;
- opcode equivalence `320/320`, `fail_equiv=0`;
- frozen-clock boot advanced from the early corrupt-PC/RTE failures to the established `040b6c20` scanner/driver frontier after basic-block and call-target fixes;
- Finder desktop framebuffer target `42849` is not yet reached.

## Contributor rule

Do not repair allocator ownership violations by unlocking, reusing, or reconstructing state after the fact. Materialise at explicit boundaries and fail at the first broken ownership invariant.
