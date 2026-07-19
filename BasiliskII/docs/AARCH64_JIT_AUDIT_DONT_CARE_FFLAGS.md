# AArch64 JIT `dont_care_fflags` ownership audit

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `fddfa74b`

## Scope

This checkpoint audits exactly MIDFUNC `dont_care_fflags`. It does not promote
`fflags_into_flags`, `f_forget_about`, FMOVE conversion MIDFUNCs, generic FP
emitters, or runtime shadow-sync boundaries.

`FP_RESULT` is the JIT's lazy floating-condition carrier. FCMP/FTST make it
dirty; FScc/FBcc later consume it. Before a new native ordinary FMOVE begins,
`dont_care_fflags()` must invalidate the old carrier so the operation's final
`MAKE_FPSR` can publish the new source class without an obsolete dirty value
being flushed first.

## Ownership contract

The ARM64 MIDFUNC contains one operation:

```c
f_disassociate(FP_RESULT);
```

This is intentionally a discard, not a flush. `f_disassociate()` first marks an
in-register value `CLEAN`, then calls `f_evict()`. Because `f_tomem_drop()`
writes only `DIRTY` values, the stale carrier is detached without writing back
to `regs.jit_fp_result`.

In the sole configured native AArch64 ordinary-FMOVE selector, ordering is:

1. `dont_care_fflags()`;
2. `get_fp_value()` operand acquisition;
3. `fmov_rr(reg, src)` destination publication;
4. `MAKE_FPSR(src)` / `fmov_rr(FP_RESULT, src)` publication of the new class.

The raw source has 33 `dont_care_fflags()` calls. Configured AArch64
preprocessing removes one x86-only FINTRZ call under `USE_X86_FPUCW`; among the
32 retained AArch64 spellings, every call except ordinary memory/immediate FMOVE
follows a `FAIL(1); return;` service boundary and is not a native configured
consumer. `fflags_into_flags` is the separate later condition consumer;
`f_forget_about` owns scratch cleanup at opcode boundaries.

## Exact-native stale-condition matrix

`jit-test/dont-care-fflags-native-matrix.ts` constructs each case in one native
block:

1. FMOVE.S immediate to FP0;
2. FTST FP0, making `FP_RESULT` dirty with a stale class;
3. a second native FMOVE that must discard and replace that class;
4. FBcc selecting a distinct A0 marker from the new class.

The six cases cover:

- stale negative -> positive single;
- stale zero -> negative single;
- stale positive -> zero single;
- stale negative -> positive byte;
- stale positive -> negative word;
- stale negative -> positive double into maximum field FP7.

Every case uses forced RAM L2, two-pass replay, exact native block entry,
strict no-fallback checks, CoW disk isolation, architectural interpreter/JIT
state equality, full integer CCR preservation, exact FPSR class, and the taken
FBcc marker. Binary64 shadow registers are deliberately excluded from
interpreter equality because they are JIT implementation state, not guest
architectural FP state.

Focused result:

```text
DONT_CARE_FFLAGS_NATIVE_MATRIX pass=6 fail=0 total=6
```

## Closure decision

Promote exactly `midfunc,dont_care_fflags` from **unreviewed** to **audited**.
Whole-engine closure is not claimed. `fflags_into_flags`, `f_forget_about`, and
all generic floating emitters remain independently classified.

## Acceptance

- focused stale-condition matrix: **6/6 exact-native**;
- structural audit: pass, including one configured pre-return root, 33 raw
  source calls, 32 configured calls, discard-before-evict ordering, and all six
  matrix discriminators;
- deterministic inventory: **998 rows**, exactly `dont_care_fflags`
  unreviewed -> audited; MIDFUNC totals become 277 audited / 119 unreachable /
  26 unreviewed; all other layers are unchanged and total unreviewed becomes
  **188**;
- closure CSV: `656f2099ec1f98b781fa2bd94fdb6182aade6cf7ed3c8610643a1ff01ca90347`;
- closure Markdown: `6e63e33cf50d937f23f8fa5bbc99af5d25fbed44ac077ceaae3ad26af54010fc`;
- independent bounded review: **APPROVE** after correcting the report to
  distinguish the raw 33-call source from the configured 32-call AArch64 unit;
- executable source is unchanged from canonical `fddfa74b`. The carried
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
