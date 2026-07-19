# AArch64 JIT FScc lifecycle audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `027eceb7`

## Scope

This tranche audits the configured `USE_JIT_FPU` native lifecycle for
`i_FScc`, the newly live `fp_fscc_ri` MIDFUNC and `raw_fp_fscc_ri` lower
boundary, and their direct low-byte helpers `CLEAR_LOW8_xx` and
`SET_LOW8_xx`.

It covers all 32 defined condition encodings (the sixteen predicates and their
bit-4 signalling aliases), D0 and maximum-field D7 destinations, five exact
FPSR classes, low-byte replacement with upper-lane preservation, integer CCR
and X preservation, strict exact-native replay, exact semantic service for
representative writable-memory EA classes, and fail-closed invalid-condition
and strict-inline memory probes. The compfpu-disabled semantic service remains
independently covered.

## Defects found and repaired

1. `comp_fscc_opp()` imported floating predicates into host NZCV but allowed
   block flush to publish that temporary relation as guest integer CCR. A
   positive FSF replay changed `SR=0x271f` to `0x2711`. The AArch64 route now
   saves architectural CCR before `FCMP` and discards predicate NZCV after
   selecting the result byte; `regflags.nzcv` and X remain authoritative.
2. The live CMOV table inherited x86 condition-number semantics. AArch64
   `FCMP` publishes direct IEEE relations (`less=1000`, `equal=0110`,
   `greater=0010`, `unordered=0011`), so ordered greater-than was inverted for
   positive and negative values. The live compiler now enters the dedicated
   FP pseudo-condition namespace and uses `fp_fscc_ri`/`raw_fp_fscc_ri`.
3. The retained raw lowerer lacked explicit false, not-equal, and true cases in
   the FP pseudo-condition namespace. It now implements all sixteen exact
   predicates and fails closed on any out-of-range internal condition.

## Runtime evidence

`bun jit-test/fscc-native-matrix.ts` is fail-closed and runs 326 cases:

- five FPSR classes: positive, zero, negative, positive NaN, negative NaN;
- all 32 defined condition encodings, proving bit-4 aliasing;
- both D0 and D7 destinations;
- exact low-byte `0x00`/`0xff` result and upper-24-bit preservation;
- untouched non-destination register;
- exact `SR=0x271f` and unchanged FPSR;
- strict full-JIT with no fallback and exact second-pass native entry;
- four exact serviced-memory forms: `(A0)`, `(A0)+`, `-(A0)`, and `d16(A0)`,
  spanning false, true/signalling-alias, unordered, and equal predicates with
  guard bytes and exact A0 writeback;
- illegal condition `0x20` and strict-inline memory `(A0)` rejection before
  native mutation.

Accepted focused result:

```text
FSCC_NATIVE_MATRIX pass=326 fail=0 total=326
```

The complete condition cross-product is 320 inline-native cases; the remaining
six are four architectural memory-service cases and two strict negative probes.

## Structural and allocator contracts

- `i_FScc` consumes its extension word and selects `comp_fscc_opp` only under
  configured JIT FPU support; the non-JIT-FPU route remains fail-closed/service
  owned.
- `extra & 0x20` and non-Dn mode bits reject before CCR preservation,
  `FCMP`, destination allocation, or mutation.
- The AArch64 condition ID is exactly `16 + (extra & 0x0f)`; bit 4 does not
  alter truth values.
- `fp_fscc_ri` acquires the destination through `rmw`, preserving its upper
  24 bits and allocator ownership through `raw_fp_fscc_ri`.
- The raw table has exactly sixteen cases, eleven clear sites, eleven set
  sites, four `CSETM_wc`/`BFXIL_xxii` compositions, and ten guarded
  ordered/unordered joins. Local branch displacements were independently
  reviewed against the emitted instruction counts.
- D0 and D7 exact-native cases prove ordinary and maximum guest-register fields.
  The lowerer has one RMW operand and only fixed reserved work-register use, so
  no distinct two-operand allocator collision exists; the full 31-cell global
  allocator campaign remains the integration gate rather than adding a fake
  FScc collision cell.
- `discard_flags_in_nzcv()` runs only after the result byte is complete and
  cannot modify X.

## Closure decision

The following rows are audited by this lifecycle evidence:

- `generator,i_FScc`;
- `midfunc,fp_fscc_ri`;
- `raw_boundary,raw_fp_fscc_ri`;
- `emitter_api,CLEAR_LOW8_xx`;
- `emitter_api,SET_LOW8_xx`.

This deliberately supersedes the earlier graph-only retirement in
`AARCH64_JIT_AUDIT_FPP_LEGACY_FSCC_RAW.md`: runtime fidelity required reusing
and completing that lower chain. Broad shared helpers such as `CSETM_wc`,
`BFXIL_xxii`, `BVS_i`, and `B_i` retain their independent classifications;
this tranche does not promote them.

## Acceptance gates

Accepted pre-publication evidence:

- focused lifecycle matrix: **326/326** (320 inline-native, four serviced
  memory, two strict rejection);
- complete active-risky corpus: **904/904**, `fail=0`, `infra_fail=0`, score
  100;
- complete allocator-pressure regression matrix: **31/31**;
- strict full-JIT negative policy: ordinary allocation fallback plus expected
  aborts for allocation, optlev-0, opcode-fallback, and verifier-reference
  paths;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced an AArch64 ELF;
- generated outputs remained byte-identical across the clean build:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic closure regeneration retained **998 rows** and exactly the
  five intended promotions; two serial generations produced:
  - CSV: `559a4758f95b5f17a0bb80beaf86584e5cf536fe0c4a6e602c4986b797ce45c1`;
  - Markdown: `15f43d770f850ee8cbfc4dee583afd433fa61d692b62fb75e361926d4eacebcb`;
- structural audit, shell syntax, source hygiene, and `git diff --check`
  passed.

A bounded independent review found no blocker in the native predicate,
CCR/lane, allocator, branch-displacement, or fail-closed contracts. A later
expanded review attempt timed out and is not counted as additional approval;
the four memory-service forms were subsequently checked against the generated
opcode table and exact fallback attribution.
