# AArch64 JIT split-double destination chain retirement

Date: 2026-07-26
Base: `18d2f7e3`

## Scope

This mechanically selected checkpoint classifies only:

- `midfunc,fmov_to_d_rrr`;
- `raw_boundary,raw_fmov_to_d_rrr`.

These wrappers split a native binary64 FP shadow into two integer words for the
old ordinary `FMOVE FPn,<double ea>` destination path. They are distinct from
the already unreachable source-side `fmov_d_rrr` / `raw_fmov_d_rrr` chain and
from the live double-memory import `fmov_rm` / `raw_fmov_d_rm`.

## Configured reachability

Raw `put_fp_value(size=5)` source retains exactly one textual
`fmov_to_d_rrr(S2, S3, val)` call. It is not control-flow reachable in the
configured AArch64 `USE_JIT_FPU` build. `comp_fpp_opp()` handles every ordinary
FMOVE destination in one selector block and, for format field 5, performs:

1. the configured AArch64 format test;
2. `FAIL(1)` into exact MPFR semantic service;
3. immediate return;
4. only later, for other formats, `put_fp_value()` and EA acquisition.

The gate therefore dominates the sole retained root before operand acquisition,
EA calculation, address-register writeback, or native MIDFUNC dispatch. No
other configured root or MIDFUNC parent names `fmov_to_d_rrr`.

The raw boundary is consequently definition-only: its LOWFUNC/LENDFUNC pair
contains one `FMOV_xd` followed by one `LSR_xxi`, both of which remain
independently reachable/classified elsewhere.

## Positive runtime control

`jit-test/fmov-to-d-rrr-retirement-matrix.sh` wraps the accepted ordinary-double
destination matrix and requires:

```text
FPP_DOUBLE_DEST_MATRIX service_pass=28 strict_pass=3 fail=0 total=31
FMOV_TO_D_RRR_RETIREMENT service=28 strict=3 fail=0 total=31
```

The 28 service cases cover all FPCR directions, exact/inexact and range edges,
signed zero/infinity/NaN, signalling-NaN source preservation, FP0/FP7,
writable basic and 68020 indexed EAs, guarded stores, writeback, CCR, exact
fallback attribution, and CoW isolation. Three strict cases require rejection
before native execution for `(An)`, predecrement, and indexed destinations.

## Closure decision

Exactly two rows move from **unreviewed** to **unreachable**. The deterministic
inventory remains 998 rows. MIDFUNC totals become 284 audited / 125 unreachable
/ 13 unreviewed; raw-boundary totals become 35 audited / 22 unreachable / 26
unreviewed. No production/generated source or generic emitter classification
changes. The next mechanically selected family is `fmov_to_s_rr`.

## Acceptance

- configured exact-service/strict control: **28 + 3 / 31**;
- structural audit: pass for the dominating pre-EA gate, sole retained root,
  definition-only MIDFUNC/raw bodies, raw operation order, and focused wrapper;
- deterministic closure regeneration: pass twice with stable artifacts:
  - CSV: `bfc3e2408ef3b84bf98138aee79493b1cf21eba3d8b6d1c0ade9a4192af2de88`;
  - Markdown: `ba9633d6f2883e1ce7256599d582eef008047c5806596746f212a99da9c97265`;
- independent bounded review: **APPROVE** for current build configuration,
  exhaustive caller proof, control-flow dominance, definition-only raw status,
  exact two-row delta, and continued generic-emitter reachability;
- executable/generated source is unchanged from `18d2f7e3`; its clean AArch64
  build and generated hashes remain current;
- shell syntax and `git diff --check`: pass.
