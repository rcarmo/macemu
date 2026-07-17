# AArch64 JIT FPP hyperbolic/log1p batch

## Scope

This bounded `i_FPP` batch covers four adjacent ordinary MPFR selectors:

- `FSINH` (`0x02`);
- `FLOGNP1` (`0x06`);
- `FETOXM1` (`0x08`); and
- `FTANH` (`0x09`).

All four configured AArch64 compiler cases unconditionally fail before operand
acquisition and execute through the MPFR semantic service. Other circular and
inverse functions, exponential/logarithmic selectors, binary arithmetic,
remainder/scale, FSINCOS, FMOVEM/control operations, and the complete `i_FPP`
lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
individual instruction descriptions and operation/exception tables:

- each source is converted to extended precision before the operation;
- the completed result obeys FPCR precision, exponent range, and rounding
  direction;
- all four retain the sign of zero;
- `FSINH(±infinity)` returns the same infinity;
- `FLOGNP1(+infinity)` returns positive infinity, `FLOGNP1(-1)` returns
  negative infinity with DZ, and values below `-1` return NaN with OPERR;
- `FETOXM1(+infinity)` returns positive infinity and
  `FETOXM1(-infinity)` returns `-1`;
- `FTANH(±infinity)` returns `±1`;
- signalling NaNs are quieted with SNAN status; quiet NaN payload and sign are
  retained; and
- ordinary inexact, overflow, and underflow publication follows the manual's
  shared FPSR rules.

The manual was downloaded from the public Bitsavers Motorola archive only for
source verification and removed after these rules were transcribed.

## Defect found and repaired

`fpuop_general()` allocated its shared source/result temporary at the selected
FPCR precision and exponent range. Under FPCR single or double, operand
acquisition therefore narrowed the architectural source before the operation.
That violates the explicit extended-source conversion contract.

The repair separates the two boundaries:

1. acquire each of these four sources with a 64-bit MPFR significand and the
   extended exponent range;
2. restore the selected FPCR format; and
3. evaluate the transcendental operation directly into a separate target-width
   MPFR result.

Direct target-width evaluation is deliberate. Computing a transcendental
result at 64 bits and rounding it again would introduce double-rounding risk.
The separate result also carries the source NaN payload/sign metadata into the
architectural destination and synchronises the MPFR NaN sign for later
consumers.

Independent MPFR searches found exact source-lifecycle discriminators. At
FPCR-single nearest, the old pre-rounded-source path and repaired direct-result
path differ as follows:

```text
FSINH   source 4003:88e97bddaf7ef73f  repaired 4016:ce8ac00000000000  old 4016:ce8ac30000000000
FLOGNP1 source 3ffb:e871dca4e3a1c97a  repaired 3ffb:dc2c850000000000  old 3ffb:dc2c860000000000
FETOXM1 source 4001:bfb88505a2a310b6  repaired 4007:c776440000000000  old 4007:c776430000000000
FTANH   source 3ffe:cba8d28c33e5ad93  repaired 3ffe:a95a990000000000  old 3ffe:a95a9a0000000000
```

Four additional FPCR-double witnesses distinguish the same lifecycle at
53-bit result precision.

## Focused runtime evidence

`bun jit-test/fpp-hyperbolic-log1p-fallback-matrix.ts` passes:

```text
FPP_HYPERBOLIC_LOG1P_MATRIX service_pass=48 strict_pass=4 fail=0 total=52
```

The fixed matrix covers:

- all four selectors under every FPCR-single rounding direction;
- one source-sensitive FPCR-double result per selector;
- positive and negative zero for every selector;
- all defined infinity and `FLOGNP1` domain-boundary results;
- quiet/signalling NaN payload, sign, and operation-local status;
- minimum extended denormal input rounded through single underflow;
- exact 80-bit guarded output, FP7 self-alias, accrued FPSR, and integer CCR
  preservation; and
- strict full-JIT rejection before native execution for all four selectors.

The service stream snapshots FPSR into D0 immediately after the operation.
The following `FMOVE.X FP7,(A0)` legitimately clears current exception status
while retaining accrued status, so final FPSR alone is not used as proof of
operation-local DZ, OPERR, SNAN, UNFL, or INEX2.

## Shared acceptance epoch

One clean-binary validation batch passed all seven selected phases in 2,397
seconds:

- structural audit and standalone strict full-JIT negative contracts;
- adjacent FINT/FINTRZ **55+2 strict** and FGETEXP/FGETMAN **38+2 strict**
  service replay;
- this batch's **48+4 strict** focused matrix;
- complete active-risky replay: **1,259/1,259**, with zero semantic or
  infrastructure failures; and
- complete allocator-pressure replay: **31/31**, with zero failures.

A clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced the expected
AArch64 ELF. Pre-clean, post-clean, and two explicit generator runs were
byte-identical and left no generated diff:

```text
compemu.cpp   55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

Shell syntax, Bun parsing, `git diff --check`, deterministic 998-row closure
regeneration, independent MPFR discriminator generation, and independent
bounded review also pass. Downloaded reference material, oracle programs, and
acceptance logs were removed.

## Structural contracts

The structural audit requires:

- all four configured AArch64 service exits;
- the exact four-selector direct-result predicate;
- extended source precision/range before operand acquisition;
- selected result format before target-width operation;
- direct MPFR `sinh`, `log1p`, `expm1`, and `tanh` evaluation;
- NaN payload/sign metadata propagation and MPFR sign coherence;
- target-range checking before architectural publication; and
- the fail-closed maintained matrix total of 48+4.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all remaining selector groups. These MPFR service semantics do not classify
the still-reachable generic raw FPU emitters, which retain their independent
closure obligations.
