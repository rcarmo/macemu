# AArch64 JIT FPP FREM batch

## Scope

This bounded checkpoint covers `FREM` (`0x25`) only. `FMOD`, `FSCALE`,
`FSGLDIV`, `FSGLMUL`, control operations, and complete `i_FPP` closure remain
separate.

## Semantics and repairs

FREM computes `destination - source*N`, where `N` is the nearest integer to the
exact quotient and a half-way quotient selects the even integer. FPSR receives
the quotient sign and low seven magnitude bits. Both operands are architectural
extended values; FPCR precision and direction apply to the completed remainder.

The compiler's residual unreachable host-native remainder code was removed.
FREM now exits to semantic service before operand acquisition on every host.
The MPFR path now loads the source at extended precision, post-rounds the result
once at FPCR precision/range, applies common quiet-then-destination NaN
ownership, publishes signed zero/infinity quotient rules, and preserves the
prior quotient on invalid and NaN paths.

## Focused runtime evidence

`bun jit-test/fpp-frem-service-matrix.ts` passes:

```text
FPP_FREM_MATRIX service_pass=33 strict_pass=1 fail=0 total=34
```

The fixed matrix covers:

- `7 REM 4 = -1`, distinguishing nearest quotient from truncating FMOD;
- both half-way parity directions: `2.5/1 -> N=2, +0.5` and
  `3.5/1 -> N=4, -0.5`;
- quotient sign combinations and the exact `195 REM 3` record: zero result and
  FPSR `0x04410000`, whose quotient magnitude `0x41` retains bit 6 and therefore
  differs from narrower low-bit masks;
- independent source/destination extended-low-bit witnesses;
- FPCR single/double result rounding and finite range publication;
- the corrected negative single-overflow result selected by nearest quotient;
- signed-zero/source-infinity results and source-zero/destination-infinity
  OPERR with quotient preservation;
- qNaN/SNaN payload, sign, quieting, and destination precedence;
- FP7 alias/reseed, postincrement/predecrement EA effects, accrued FPSR, and
  integer CCR preservation; and
- exact strict rejection.

Every service case enters natively at PC `0x1008` before configured semantic
service. FPSR is snapshotted into D0 before the following extended store clears
operation-local exception status.

## Structural and review decision

The structural audit forbids operand acquisition/native remainder publication
in the compiler case and pins extended-source membership, destination/source
order, `mpfr_remquo`, quotient sign/seven-bit publication, special/NaN paths,
all high-risk complete vectors, native entry, strict rejection, and 33+1
accounting.

Independent review required explicit ties-to-even witnesses and a quotient
whose low seven bits cannot be confused with a narrower mask. Both were added;
review completion is recorded with the checkpoint evidence.

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending all
selector groups.
