# AArch64 JIT FPP square-root subtranche

## Scope

This bounded `i_FPP` subtranche covers the three square-root selectors:
ordinary extended-precision `FSQRT`, forced-single `FSSQRT`, and forced-double
`FDSQRT`. It relies on the mixed native/interpreter FPU ownership boundary
accepted with the preceding sign-operation tranche.

Other arithmetic, transcendental, remainder/scale, FMOVEM/control operations,
and the complete `i_FPP` lifecycle remain separate.

## Defect found and repaired

The AArch64 compiler acquired all three operands through the binary64 native
shadow and emitted host `FSQRT D`. That cannot implement the architectural
contract:

- ordinary `FSQRT` operates over the extended exponent range and 64-bit
  significand, with FPCR-selected extended/single/double precision and four
  rounding directions;
- `FSSQRT` and `FDSQRT` force 24- and 53-bit result precision respectively;
- architectural signed zero, NaN payload/quieting, operation exceptions,
  accrued exceptions, and FPSR condition codes must survive mixed execution.

The old path could narrow the operand before the operation, overflow values
that are finite in extended precision, omit forced precision and directed
rounding, and derive incomplete FPSR state from the binary64 result.

On AArch64 all three selectors now fail before `get_fp_value()` and execute
through the existing MPFR service. No guest effective-address side effect has
occurred at that point.

The distinguishing forced-double/FPCR-single case also exposed a shared MPFR
service defect: the result temporary used the required 53-bit precision, but
the source temporary had already been allocated at FPCR single precision.
Forced single/double operations now acquire the architectural source at full
extended precision and apply 24/53-bit precision only to their result. The
previously accepted explicit-move and sign-family service matrices pass against
this repair.

## Runtime evidence

`bun jit-test/fpp-sqrt-fallback-matrix.ts` contains 54 fixed 80-bit/FPSR
service vectors and three strict full-JIT rejections. Every service sequence
loads an 80-bit MPFR source, executes one square-root selector, stores the
80-bit result, and re-enters the compiled sequence. It requires exactly three
visible service boundaries, guarded output bytes, unchanged A0 and integer
`SR=271f`, and no crash.

Covered semantics include:

- positive and negative zero;
- exact one, positive infinity, and invalid negative finite input;
- quiet-NaN payload preservation and signalling-NaN quieting/exception;
- maximum finite and minimum normal extended-range operands;
- a low significand bit beyond binary64 precision;
- exact ordinary extended results beyond binary64 precision;
- extended FPCR precision under all four rounding modes;
- ordinary forced-single and forced-double FPCR precision under all four
  rounding modes;
- `FSSQRT` and `FDSQRT` under all four rounding modes;
- each forced selector's signed zero, invalid negative input, infinity,
  qNaN/sNaN canonicalisation, overflow, underflow, opposite FPCR precision
  override, and accrued-FPSR replay contract;
- forced-single and forced-double sources outside their result exponent range
  whose square roots remain representable, proving extended-range acquisition;
- FP7 self-alias with maximum source/destination fields;
- prior accrued FPSR preservation and replay beside native integer execution.

Accepted focused result:

```text
FPP_SQRT_FALLBACK_MATRIX service_pass=54 strict_pass=3 fail=0 total=57
```

The strict cases cover all three selectors with FP7 self-alias and require
opcode rejection at the square-root instruction, no native entry, and no
SIGSEGV.

## Structural contracts

- all three AArch64 selectors must issue `FAIL(1)` and return before
  `get_fp_value()`;
- MPFR forced operations must set both source precision and active exponent
  format to `EXTENDED_PREC` before `get_fp_value()`, then restore the forced
  result format before operating into the 24/53-bit result temporary;
- the maintained matrix must retain its special-value, extended-range,
  low-bit, all-rounding-mode, alias, accrued-FPSR, replay, and strict cases;
- service accounting must remain fail-closed at 54 vectors and strict
  accounting at three rejections;
- the shared dirty-shadow and CCR rematerialisation contracts remain pinned by
  the sign-family structural gate and adjacent regressions.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all remaining selector groups. `midfunc,fsqrt_rr`, `emitter_api,FSQRT_dd`, and
`raw_boundary,raw_fsqrt_rr` remain reachable from the now-retired source but
are not promoted by an MPFR-service tranche; they require a separate generic
emitter/MIDFUNC closure decision or proof of source unreachability after the
complete FPP lifecycle is exhausted.
