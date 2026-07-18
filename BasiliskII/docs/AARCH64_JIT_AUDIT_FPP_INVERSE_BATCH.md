# AArch64 JIT FPP inverse-function batch

## Scope

This bounded `i_FPP` batch covers three adjacent ordinary MPFR selectors:
`FATAN` (`0x0a`), `FASIN` (`0x0c`), and `FATANH` (`0x0d`). All three
configured AArch64 compiler cases unconditionally fail before operand
acquisition and execute through MPFR. Native `FSIN`, serviced `FTAN`, other
transcendentals, arithmetic, FSINCOS, control operations, and the complete
`i_FPP` lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
individual instruction and exception tables:

- every source is converted to extended precision before evaluation;
- the result obeys FPCR precision, exponent range, and rounding direction;
- all three preserve signed zero;
- `FATAN(±infinity)` returns `±pi/2` with ordinary inexact publication;
- `FASIN` accepts the closed interval `[-1,+1]`, returning `±pi/2` at the
  endpoints, and returns NaN plus OPERR outside it;
- `FATANH(±1)` returns signed infinity plus DZ, while values with magnitude
  greater than one return NaN plus OPERR; and
- signalling NaNs are quieted with SNAN status while quiet NaN payload/sign
  metadata is retained.

The manual was downloaded from the public Bitsavers Motorola archive only
while extracting these rules, then deleted.

## Defects found and repaired

The shared ordinary MPFR path allocated its source/result temporary at FPCR
single or double precision before source acquisition. The three selectors now
join the extended-source/direct-result contract established for the adjacent
hyperbolic batch: acquire under 64-bit extended precision/range, restore the
selected FPCR format, then evaluate directly into a separate target-width MPFR
temporary. Direct evaluation avoids transcendental double rounding and retains
architectural NaN payload/sign metadata.

The audit also found an independent status defect. MPFR returned the correct
signed infinity for `FATANH(±1)` and raised its internal divide-by-zero flag,
but the emulator did not set the explicit Motorola DZ status before
publication. The selector now distinguishes equality from the out-of-domain
case: magnitude one sets DZ; larger magnitude sets OPERR.

Independent MPFR searches produced exact source-lifecycle witnesses for every
selector at FPCR single and double precision. Representative FPCR-single
nearest results include:

```text
FATAN  source 3ffd:e3205362e1782eb8 -> 3ffd:d5c5b40000000000
FASIN  source bffe:97417f79c65f5fc3 -> bffe:a1d18a0000000000
FATANH source 3ffe:f87a25d6990b44b1 -> 4000:8694140000000000
```

Each differs from evaluating a pre-rounded single source.

## Focused runtime evidence

`bun jit-test/fpp-inverse-fallback-matrix.ts` passes:

```text
FPP_INVERSE_MATRIX service_pass=38 strict_pass=3 fail=0 total=41
```

The fixed matrix covers all three selectors through every FPCR-single rounding
direction and one source-sensitive double result; signed zero; infinities and
`±pi/2`; `FASIN` and `FATANH` boundary/domain rules; qNaN/sNaN payload, sign,
and operation-local status; extended-to-single underflow; exact guarded 80-bit
output; FP7 self-alias; accrued FPSR and integer CCR preservation; and strict
full-JIT rejection before native execution.

FPSR is snapshotted into D0 immediately after the operation. The following
extended store legitimately clears current exception status while preserving
accrued state, so final FPSR alone is not accepted as evidence for DZ, OPERR,
SNAN, UNFL, or INEX2.

## Shared acceptance epoch

One clean-binary batch passed all six selected phases in 2,369 seconds:

- structural and standalone strict full-JIT negative gates;
- adjacent hyperbolic/log1p **48+4 strict** replay;
- this batch's **38+3 strict** focused matrix;
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
regeneration, standalone MPFR oracle generation, and independent bounded
review also pass. Temporary reference/oracle/log files were removed.

## Structural contracts

The structural audit requires all three configured service exits; their exact
membership in the direct-result selector set; direct target-width `atan`,
`asin`, and `atanh`; explicit FATANH equality-DZ versus greater-than-one OPERR;
the shared NaN metadata and range-publication contract; and the fail-closed
38+3 fixed matrix.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all remaining selector groups. This MPFR service batch does not classify the
still-reachable generic raw FPU emitters.
