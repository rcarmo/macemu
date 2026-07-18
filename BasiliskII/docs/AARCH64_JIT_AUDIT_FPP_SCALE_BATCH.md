# AArch64 JIT FPP FSCALE batch

## Scope

This bounded checkpoint covers `FSCALE` (`0x26`) only. `FSGLDIV`, `FSGLMUL`,
control operations, and complete `i_FPP` closure remain separate.

## Semantics and repairs

FSCALE computes `destination * 2^INT(source)`. A nonintegral source is chopped
toward zero independently of FPCR direction; both operands retain architectural
extended precision, then normal instruction termination rounds the completed
result at FPCR precision/range. Either infinity operand produces NaN plus OPERR.

The compiler already exited to semantic service before operand acquisition; the
residual unreachable path was structurally forbidden. MPFR service now loads
the source at extended precision, preserves the destination significand, scales
from destination by the chopped exponent, post-rounds once, and applies binary
NaN metadata/quieting. Invalid infinity results retain the selected operand sign
in NaN metadata and FPSR condition codes.

The original finite-source fallback used one fixed shift for values outside
`long`, which could leave extreme destination exponents finite. It now derives
the forcing shift from the destination exponent, guaranteeing architectural
range publication for either sign.

## Focused evidence

`bun jit-test/fpp-scale-service-matrix.ts` passes:

```text
FPP_SCALE_MATRIX service_pass=30 strict_pass=1 fail=0 total=31
```

The matrix covers:

- positive and negative fractional chopping and extended values immediately
  below `+1` and above `-1`;
- extended destination low-bit preservation;
- FPCR single/double post-rounding and directed results;
- single and extended overflow, exact extended subnormal output, and the
  extended underflow threshold;
- two exact non-`long` branch records: huge positive with the minimum extended
  destination overflows, while huge negative with maximum extended destination
  underflows;
- signed zeros;
- positive/negative source and destination infinity OPERR with NaN sign;
- source/destination qNaN and SNaN metadata/quieting;
- FP7 alias/reseed, postincrement/predecrement EA effects, accrued FPSR, integer
  CCR preservation, native entry, and exact strict rejection.

## Structural and review decision

The structural audit pins the no-acquisition compiler boundary, operation 38
extended-source membership, truncation mode, destination-relative huge-scale
fallback, post-rounding, NaN/sign ownership, all high-risk complete records,
native entry, opcode-specific fallback attribution, strict rejection, and 30+1
accounting.

Independent review found the original fixed huge-scale shift and invalid-NaN
sign loss. Both were repaired and directly witnessed before acceptance.

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending all
selector groups.
