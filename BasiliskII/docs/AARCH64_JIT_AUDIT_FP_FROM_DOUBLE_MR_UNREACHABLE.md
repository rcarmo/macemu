# AArch64 JIT legacy binary64-memory store-chain retirement

Date: 2026-07-26
Base: `f1200ebf`

## Scope

This checkpoint classifies only:

- `midfunc,fp_from_double_mr`;
- `raw_boundary,raw_fp_from_double_mr`.

The pair byte-swaps a native binary64 FP shadow and stores it through an old
host-memory-oriented compatibility path. It is distinct from the already
retired split-word guest destination chain `fmov_to_d_rrr`, and from live
binary64 import `fmov_rm -> raw_fmov_d_rm`.

## Configured reachability

`compemu_fpp_arm64_compat.h` maps legacy `fmov_mr(m,s)` to
`fp_from_double_mr(m,s)`, but the sole raw source call is inside the non-AArch64
`#else` arm of `put_fp_value(size=5)`. The configured AArch64 arm uses
`fmov_to_d_rrr` followed by ordered guest-memory stores; every configured
ordinary double destination now enters exact MPFR service and returns before
`put_fp_value()` in any event.

Configured preprocessing consequently retains only the explicit extern
`fp_from_double_mr` declaration and no call. No generated compiler, support
path, compatibility wrapper, or reachable MIDFUNC parent calls it.

`raw_fp_from_double_mr` is therefore definition-only. Its two operations remain
independently classified: `REV64_dd` converts lane byte order and `STR_dXx`
performs the store.

## Positive runtime control

`jit-test/fp-from-double-mr-retirement-matrix.sh` reruns the accepted ordinary
binary64 destination matrix and requires:

```text
FPP_DOUBLE_DEST_MATRIX service_pass=28 strict_pass=3 fail=0 total=31
FP_FROM_DOUBLE_MR_RETIREMENT service=28 strict=3 fail=0 total=31
```

The 28 service cases cover every FPCR direction, exact/inexact and range edges,
signed zero/infinity/NaN, signalling-NaN source preservation, FP0/FP7, basic
and indexed writable EAs, guarded memory, writeback, CCR, exact fallback
attribution, and CoW isolation. Three strict cases require rejection before
native execution for `(An)`, predecrement, and indexed destinations.

## Closure decision

Exactly two rows move from **unreviewed** to **unreachable**. No executable or
generated source and no generic emitter classification changes. Whole-engine
closure is not claimed.

## Acceptance

- configured service/strict control: **28 + 3 / 31**;
- structural audit: pass for declaration-only configured census, exact inactive
  branch containment, definition-only MIDFUNC/raw chain, raw operation order,
  and focused wrapper;
- deterministic closure regeneration: 998 rows, exact two-row delta:
  - CSV: `46f790e383f37c48ee2ab6a951cb85c2f3e41f3c68032aa0ba5a3213ffb80e97`;
  - Markdown: `a2d6542d659d577cd2a9c89a859c9333bcd8b47dd66bfe533821111463345d2d`;
- independent bounded review: **APPROVE** after correcting the report/status date; configured branch containment, caller census, definition-only raw status, and exact two-row delta had no semantic blocker;
- executable/generated source unchanged from `f1200ebf`;
- shell syntax and `git diff --check`: pass.
