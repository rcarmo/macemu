# AArch64 JIT `f_forget_about` scratch-lifetime audit

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `15972e10`

## Scope

This checkpoint audits exactly MIDFUNC `f_forget_about`. It does not promote
integer `forget_about`, `dont_care_fflags`, `fflags_into_flags`, floating
conversion MIDFUNCs, generic FP emitters, or runtime shadow-sync boundaries.

`FS1` is the configured AArch64 floating scratch virtual register. Unlike FP0
through FP7 and `FP_RESULT`, it has `NF_SCRATCH` ownership and no architectural
writeback obligation. Every compiled opcode boundary must retire any live FS1
mapping so the next opcode cannot inherit stale allocator ownership.

## Configured ownership contract

Configured preprocessing finds exactly one root:

```c
static void freescratch(void)
{
    ...
#ifdef USE_JIT_FPU
    f_forget_about(FS1);
#endif
}
```

On the ordinary path that continues compiling the block, `compile_block()`
invokes `freescratch()` after the opcode compiler and before the next opcode.
Four hard-endblock classes exit first: ordinary guest-memory writers, runtime
semantic helpers, dynamic returns, and conditional DBcc back-edges. The first,
third, and fourth call `flush(1)` locally; the runtime-helper constructors call
`flush(1)` before setting their forced-endblock marker. Since `flush(1)` also
disassociates every `NF_SCRATCH` floating value, these exits retire FS1 without
requiring the later `freescratch()` call. No generated compiler, FPP selector,
compatibility wrapper, or other MIDFUNC calls `f_forget_about`.

The MIDFUNC performs two ordered actions:

1. if FS1 is currently resident, `f_disassociate()` marks it `CLEAN` before
   eviction, clearing its physical-register hold without emitting the
   `f_tomem_drop()` store that is reserved for `DIRTY` values;
2. it marks the virtual scratch `UNDEF`, including the already non-resident
   case.

This is discard-only bookkeeping. Architectural FP0-FP7 and the lazy
`FP_RESULT` carrier are not selected. The physical home is d7; it becomes free
for later scratch allocation after the hold count is cleared.

## Exact-native consecutive-operation matrix

`jit-test/f-scratch-lifecycle-native-matrix.ts` supplies supporting runtime
coverage around the per-opcode boundary. Each case places multiple native FPU
operations in one strict block so FS1 is produced, retired by `freescratch()`,
and reused by a later operation. The six cases cover:

- consecutive single FMOVEs to FP0 and FP1;
- byte conversions to FP0 and maximum-field FP7;
- long conversions to FP0 and FP3;
- double conversion followed by negative zero into FP6;
- FTST/`FP_RESULT` publication followed by a word conversion into FP2;
- FP7 double followed by a negative byte conversion into FP0.

Every case requires forced RAM L2, two-pass replay, exact native block entry,
strict no-fallback policy, interpreter/JIT equality for integer architectural
state and FPSR, preserved full CCR, and exact intended JIT destination shadows.
Interpreter binary64 shadow fields are excluded from equality because they are
not its architectural MPFR register dump path. CoW disk and temporary HOME
state are released in `finally` blocks.

Focused result:

```text
F_SCRATCH_LIFECYCLE_NATIVE_MATRIX pass=6 fail=0 total=6
```

The runtime matrix demonstrates safe consecutive use; it is not claimed to
uniquely attribute compile-time allocator cleanup. Direct attribution comes
from the fail-closed configured-root and state-transition checks above.

## Closure decision

Promote exactly `midfunc,f_forget_about` from **unreviewed** to **audited**.
Whole-engine closure is not claimed. `forget_about`, `fflags_into_flags`, all
floating conversion MIDFUNCs, generic emitters, and shadow-sync boundaries
remain independently classified.

## Acceptance

- focused consecutive-operation matrix: **6/6 exact-native**;
- structural audit: pass, including the sole configured FS1 root,
  clean-before-evict then `UNDEF`, ordinary continuing-path cleanup, and all
  four pre-cleanup hard-endblock retirement classes;
- deterministic inventory: **998 rows**, exactly `f_forget_about` unreviewed ->
  audited; MIDFUNC totals become 278 audited / 119 unreachable / 25 unreviewed;
  all other layers are unchanged and total unreviewed becomes **187**;
- closure CSV: `488950608f6f4e5fa2b6e7d83d1d72145f368852e9103db816b7906a3846f4e8`;
- closure Markdown: `ff18d921188938689d6f04d029dbe785dfcba9aec42798c75f935839b0a28fde`;
- independent bounded review: **APPROVE** after correcting the report and
  structural proof to distinguish ordinary cleanup from four earlier flushing
  hard-endblock classes;
- executable source is unchanged from canonical `15972e10`. The carried
  integration baseline from `696a9e46` therefore remains active corpus
  **904/904**, allocator pressure **33/33**, strict policy pass, clean AArch64
  `USE_JIT_FPU` build, and stable generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Shell/Bun parsing, source hygiene, `git diff --check`, and CoW scratch release
also pass. Acceptance logs are removed after publication.
