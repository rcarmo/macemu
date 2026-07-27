# AArch64 JIT host-pow FTWOTOX-chain retirement

Date: 2026-07-27
Base: `e2d4a9cc`

## Scope

This checkpoint classifies:

- `midfunc,fpowx_rr`;
- `raw_boundary,raw_fpowx_rr`.

The compatibility header maps `ftwotox_rr(d,s)` to `fpowx_rr(2,d,s)`. The raw
boundary narrows the source to binary64 and calls host `pow(2.0, source)`. That
cannot implement Motorola extended-source, FPCR precision/rounding, range, NaN,
or FPSR semantics.

## Configured reachability

The sole configured root is the retained `ftwotox_rr(reg,src)` spelling in
ordinary FPP selector `0x11`. In the configured AArch64 arm, unconditional
`FAIL(1); return;` precedes `dont_care_fflags()`, `get_fp_value()`, and the
compatibility call. FTWOTOX therefore enters the accepted MPFR `exp2` service
before operand acquisition or any native binary64 state mutation.

No generated compiler, support path, other FPP selector, or reachable MIDFUNC
parent calls `fpowx_rr`. Its raw child is consequently definition-only.
Generic call/FMOV/stack emitters used by the retained body remain independently
classified.

## Positive runtime control

`jit-test/fpowx-retirement-matrix.sh` selects nine cases from the accepted
49+4 native-transcendental service matrix:

```text
FPOWX_RETIREMENT service=8 strict=1 fail=0 total=9
```

The service subset covers FPCR single and double results, signed infinity,
quiet-NaN metadata, finite single overflow and underflow, and FP7 self-alias.
Every case requires exact 80-bit output/FPSR/CCR, compiled-block entry followed
by visible semantic fallback, and CoW isolation. The strict FP7 companion
requires rejection before native completion.

## Closure decision

Exactly two rows move from **unreviewed** to **unreachable**. No production or
generated source and no generic emitter classification changes. Whole-engine
closure is not claimed.

## Acceptance

- focused exact MPFR service/strict control: **8 + 1 / 9**;
- structural audit: pass for the sole selector root, pre-operand service
  dominance, definition-only MIDFUNC/raw chain, retained host-call body, and
  focused wrapper;
- deterministic closure regeneration: 998 rows with an exact two-row delta:
  - CSV: `ac47fbacf3d2a68389455e3489332f6934ca8680801d8471e0d9d5419cda52d9`;
  - Markdown: `27384eda56ec79158d4030e75df42803bb1fbba676896a09d290ed978ae15ce1`;
- independent bounded review: **APPROVE** for the sole configured macro/root,
  selector `0x11` dominance, absence of another AArch64 caller, host-`pow` versus
  MPFR-`exp2` distinction, exact two-row scope, and focused case selection;
- executable/generated source unchanged from `e2d4a9cc`;
- shell syntax and `git diff --check`: pass.
