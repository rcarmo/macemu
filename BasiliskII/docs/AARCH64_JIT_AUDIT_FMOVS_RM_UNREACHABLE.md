# AArch64 JIT legacy single-memory wrapper retirement

Date: 2026-07-26
Base: `2667fdef`

## Scope

This checkpoint classifies only:

- `midfunc,fmovs_rm`;
- `raw_boundary,raw_fmovs_rm`.

The pair loads a host-memory binary32 value and widens it to the native
binary64 FP shadow. It is retained for other backends but is not selected by the
configured AArch64 `USE_JIT_FPU` compiler.

## Configured reachability

Raw `compemu_fpp.cpp` has one legacy `extern fmovs_rm` declaration and two call
sites. Both calls are confined to `#else` arms of explicit AArch64 branches:

- direct Dn single sources use `fmov_s_rr(FS1, reg)` on AArch64;
- fetched memory/immediate single sources first use ordered guest-memory access
  into `S2`, then `fmov_s_rr(FS1, S2)` on AArch64.

The configured preprocessor therefore retains only the declaration and neither
call. No generated, support, compatibility, or reachable MIDFUNC parent calls
`fmovs_rm`.

`raw_fmovs_rm` becomes definition-only once its sole MIDFUNC is retired. Its
`LDR_sXi` and `FCVT_ds` operations remain independently reachable and
classified through the accepted `fmov_s_rr` chain and generic emitter audits.

## Positive runtime control

`jit-test/fmovs-rm-retirement-matrix.sh` runs the accepted live replacement
wrapper and requires **18/18 strict exact-native** single-source cases:

```text
FMOV_S_RR_NATIVE_MATRIX pass=18 fail=0 total=18
FMOVS_RM_RETIREMENT live_replacement=18 fail=0 total=18
```

These cover both configured AArch64 roots plus `(An)`, postincrement,
predecrement, d16/indexed/absolute/PC-relative EAs, exact payload/FPSR/CCR,
writeback, strict native attribution, and CoW isolation.

## Closure decision

Exactly two rows move from **unreviewed** to **unreachable**. MIDFUNC totals
become 285 audited / 126 unreachable / 11 unreviewed; raw-boundary totals become
36 audited / 23 unreachable / 24 unreviewed. No production or generated source
and no generic-emitter classification changes. The 998-row inventory next
selects `forget_about`.

## Acceptance

- focused strict exact-native live replacement: **18/18**;
- structural audit: pass for the two branch pairs, raw/configured source
  census, definition-only MIDFUNC/raw bodies, and focused wrapper;
- deterministic closure regeneration: pass twice with stable artifacts:
  - CSV: `2de1634d641a8faea025927cccebdec53d1533e7aa2dcadb69df5bb462862644`;
  - Markdown: `745b7e2406afa905f51c89ea767a79a5e451e24fdb325f2e8b98be64fb7ef94b`;
- independent bounded review: **APPROVE** for current build configuration,
  absent macro/generated/support parents, inactive-arm dominance, definition-
  only raw status, exact two-row delta, live replacement, and retained emitter
  classifications;
- executable/generated source is unchanged from `2667fdef`; its clean AArch64
  build and generated hashes remain current;
- shell syntax and `git diff --check`: pass.
