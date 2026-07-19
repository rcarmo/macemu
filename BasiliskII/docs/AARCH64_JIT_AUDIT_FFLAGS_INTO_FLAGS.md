# AArch64 JIT floating-condition materialisation audit

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `63120f4a`

## Scope

This graph/runtime-evidence checkpoint audits only the reachable AArch64
MIDFUNC `fflags_into_flags`. The helper composes the lazy `FP_RESULT` allocator
state with a host `FCMP`-against-zero predicate and publishes that temporary
relation in native NZCV for its two configured consumers, FScc and FBcc.

This checkpoint does **not** promote `raw_fflags_into_flags`; that lower wrapper
remains a separately selected raw-boundary row. `FCMP_d0` is already closed by
`AARCH64_JIT_AUDIT_FCMP_EMITTERS.md`, while the complete FScc and FBcc consumers
are already closed by their lifecycle reports.

## Source and ownership contract

The configured AArch64 graph has exactly two compiler roots:

1. `comp_fscc_opp()` preserves architectural integer CCR, calls
   `fflags_into_flags()`, consumes the relation through `fp_fscc_ri()`, then
   discards the temporary host NZCV;
2. `comp_fbcc_opp()` preserves architectural integer CCR, calls
   `fflags_into_flags()`, and records a floating-condition branch edge whose
   block finalisation preserves the saved integer CCR.

The MIDFUNC itself has a strict composition order:

1. `clobber_flags()` saves live architectural integer CCR when necessary and
   marks native NZCV stale;
2. `f_readreg(FP_RESULT)` acquires the lazy floating condition value read-only,
   loading its fixed home only when it is not resident;
3. `raw_fflags_into_flags()` emits one `FCMP_d0` against that value;
4. `f_unlock()` is called before state publication. On this fixed-home floating
   allocator it is intentionally a no-op, so no fictitious lock-count claim is
   made;
5. `live_flags()` marks the newly emitted relation as live and important for
   the immediate FScc/FBcc consumer.

The read path neither marks `FP_RESULT` dirty nor modifies its runtime dirty
mask. The existing `FCMP_d0` conformance proves all 32 source-register fields,
exact encoding, native IEEE relation NZCV, operand preservation, FPCR/FPSR
handling, and caller-saved floating-register discipline.

## Runtime evidence

`bun jit-test/fflags-into-flags-native-matrix.ts` is a bounded fail-closed
composition matrix with eight strict cases:

- four FScc consumers across positive, zero, negative, and unordered
  classifications;
- D0 and maximum-field D7 destination selection;
- four FBcc consumers spanning FTST and FCMP producers plus word and long
  displacement forms;
- exact predicate result, FPSR relation, and unchanged `SR=0x271f`;
- second-pass native attribution, replay, no fallback, and isolated CoW disk
  cleanup.

Focused result:

```text
FFLAGS_INTO_FLAGS_NATIVE_MATRIX pass=8 fail=0 total=8
```

This focused matrix supplements rather than replaces the accepted broad
consumer and primitive evidence:

- FScc lifecycle: **326/326**;
- FBcc lifecycle: **160/160**;
- FPP FCMP classification: **176/176**;
- generic FCMP emitters: **1,056** exact words and **72** native vectors.

No production-source defect reproduced in this checkpoint.

## Fail-closed structural evidence

The inventory and structural audit reject:

- any configured root count other than exactly two;
- any root outside the configured FPU compiler;
- loss or reordering of CCR preservation, predicate materialisation, and the
  FScc/FBcc consumer;
- mutation of the read-only `f_readreg()` path;
- a non-fixed-home `f_unlock()` contract being silently substituted;
- any MIDFUNC ordering change around acquisition, comparison, release, and
  `live_flags()`;
- any raw wrapper cardinality other than one `FCMP_d0`;
- drift in the exact eight-case matrix or strict-native/CoW assertions.

## Closure decision

`midfunc,fflags_into_flags` is **audited** by this composition evidence.
`raw_boundary,raw_fflags_into_flags` remains **unreviewed**, as do all
neighbouring floating MIDFUNC and raw rows not named above. Whole-engine closure
is not claimed.

## Acceptance

- focused composition matrix: **8/8 exact-native**;
- structural audit: pass, including the exact two configured roots, complete
  read/compare/release/state ordering, read-only lazy-result acquisition,
  fixed-home unlock semantics, one raw `FCMP_d0`, and both immediate consumers;
- deterministic inventory: **998 rows**, exactly `fflags_into_flags`
  unreviewed -> audited; MIDFUNC totals become 279 audited / 119 unreachable /
  24 unreviewed; all other layers are unchanged and total unreviewed becomes
  **186**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `4acaa92c48834d1f5f366c1b8a9d9545e521615e24237f5f75626d320a0fcd15`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `dd20efb6fc8fd67d402b01dadbddd6dbe6fdd9a301ff15071759801a0cce770d`;
- independent bounded review: **APPROVE** for source claims, all eight opcode
  streams and anchors, strict attribution, fail-closed checks, and exact
  one-row promotion;
- executable source is unchanged from canonical `63120f4a`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Bun transpilation, shell syntax, source hygiene, `git diff --check`, and scoped
CoW scratch release also pass. Acceptance logs are removed after publication.
