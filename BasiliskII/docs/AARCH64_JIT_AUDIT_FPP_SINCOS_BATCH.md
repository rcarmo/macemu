# AArch64 JIT FPP FSINCOS batch

## Scope

This bounded checkpoint covers all eight `FSINCOS` cosine-register selectors
(`0x30–0x37`). Control moves and complete `i_FPP` closure remain separate.

## Semantics and repairs

FSINCOS converts its source to architectural extended precision once, evaluates
sine and cosine from that same source, and rounds each completed result at FPCR
precision/range. Sine is written to FPn and determines FPSR condition codes;
cosine is written to FPc without replacing those codes. If FPc equals FPn, the
architectural sine result wins.

The MPFR service previously acquired at FPCR width and evaluated in place. It
now retains the extended source and writes directly into separate FPCR-width
sine/cosine temporaries, avoiding source pre-rounding and result double
rounding. NaN sign is explicitly restored on both MPFR results before storing
payload/sign metadata and deriving sine condition codes.

## Focused evidence

`bun jit-test/fpp-sincos-service-matrix.ts` passes:

```text
FPP_SINCOS_MATRIX service_pass=18 strict_pass=1 fail=0 total=19
```

The matrix covers signed zero, pi/2, pi, extended-source single/double results,
plus/minus directed single rounding with different sine/cosine discriminators,
same-register sine-wins ordering, FP7 sine destination, infinity OPERR,
negative qNaN FPSR sign, SNaN quieting, sine underflow, postincrement and
predecrement EA effects, accrued FPSR, integer CCR preservation, exact native
entry/fallback attribution, and strict rejection.

## Structural and review decision

The structural audit forbids native operand acquisition in the service-only
compiler group and pins extended-source acquisition, separate direct result
temporaries, both NaN sign restorations, cosine no-flags/sine flags ordering,
all high-risk records, FP7 and same-register destinations, EA attribution,
strict rejection, and 18+1 accounting.

Independent review found missing MPFR NaN-sign restoration, a wrong negative
qNaN FPSR oracle, fixed FP0 sine coverage, and absent directed modes. All were
repaired and re-review approved the checkpoint.

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending all
selector groups.
