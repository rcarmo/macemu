# AArch64 JIT legacy binary64 guest-address load-chain retirement

Date: 2026-07-26
Base: `ac4ba8f2`

## Scope

This checkpoint classifies only:

- `midfunc,fp_to_double_rm`;
- `raw_boundary,raw_fp_to_double_rm`.

The pair loads a byte-swapped binary64 value directly from a guest virtual
address register. It is a retained compatibility chain, distinct from the live
ordinary double-memory import:

```text
ordered guest reads -> host temp_fp -> fmov_rm -> raw_fmov_d_rm
```

## Configured reachability

Configured preprocessing retains only the explicit `fp_to_double_rm` extern in
`compemu_fpp.cpp`. There is no compatibility macro, generated compiler call,
support call, FPP call, or reachable MIDFUNC parent. Its MIDFUNC is therefore
definition-only and `raw_fp_to_double_rm` is reachable only from that dead
parent.

The direct guest-address raw load is not interchangeable with the live path.
Ordinary FMOVE.D first performs ordered guest-memory reads, preserving special
memory, fault, endian, and EA semantics, then imports the assembled host
binary64 value through the already audited `fmov_rm -> raw_fmov_d_rm` chain.
Retiring this synonym does not reclassify that live chain or its generic load
emitters.

## Positive runtime control

`jit-test/fp-to-double-rm-retirement-matrix.sh` reruns all ten accepted strict
exact-native double-source cases from the live sibling:

```text
FMOV_RM_NATIVE_MATRIX pass=10 fail=0 total=10
FP_TO_DOUBLE_RM_RETIREMENT live_sibling=10 fail=0 total=10
```

The cases cover `(An)`, postincrement, predecrement, displacement, indexed,
absolute short/long, PC-relative displacement/indexed, FP7, exact binary64
bits, FPSR, integer CCR, writeback, native attribution, and CoW isolation.

## Closure decision

Exactly two rows move from **unreviewed** to **unreachable**. No production or
generated source and no generic emitter classification changes. Whole-engine
closure is not claimed.

## Acceptance

- focused live-sibling strict exact-native matrix: **10/10**;
- structural audit: pass for declaration-only configured census,
  definition-only MIDFUNC/raw chain, ownership/load ordering, and focused
  wrapper;
- deterministic closure regeneration: 998 rows with an exact two-row delta:
  - CSV: `379bfc81f35fb0daab20d747feedc58f23e59580298d5c3cf3f9e1d16afc49d0`;
  - Markdown: `bf86ec50b9bd2568c6738711d20c51448f42646fc4d2a0c921e9e091d93bc5a9`;
- independent bounded review: **APPROVE** for the configured caller census,
  declaration-only MIDFUNC root, definition-only raw child, live ordered-read
  sibling distinction, and exact two-row inventory scope;
- executable/generated source unchanged from `ac4ba8f2`;
- shell syntax and `git diff --check`: pass.
