# AArch64 JIT FPP ordinary FMOVE packed-format subtranche

## Scope

This is the ninth bounded subtranche of the reachable `i_FPP` audit. It covers
ordinary static and dynamic packed-decimal FMOVE as an exact MPFR service
boundary.

Packed conversion is decimal, K-factor-dependent, and cannot be represented as
a native binary64 copy. The AArch64 compiler already rejects packed source and
destination formats before memory-EA calculation. This checkpoint proves that
ordering, the exact interpreter service, static/dynamic K handling, rounding,
and fail-closed strict behavior.

FMOVEM, FMOVECR, control moves, explicit precision, arithmetic, and the complete
`i_FPP` lifecycle remain separate.

## Source finding

Both `get_fp_value()` and `put_fp_value()` classify packed size 3 as unsupported
before their memory-EA switches. No native EA calculation, postincrement,
predecrement, conversion, or store can occur. Unlike the extended-format slice,
no implementation repair was required.

The MPFR boundary implements:

- packed decimal parsing into the 64-bit MPFR register;
- static K from the extension word;
- dynamic K from the selected Dn low seven bits;
- decimal significant-digit rounding;
- signed mantissa and signed three-digit exponent;
- zero, infinity, NaN, and OPERR handling.

## Runtime evidence

`bun jit-test/fpp-fmove-packed-fallback-matrix.ts` has two parts.

Nine normal-service cases load packed data from absolute memory and store it
through `(A0)`. They require both source and destination JIT fallbacks, guarded
exact output bytes, unchanged A0/SR, and preserved dynamic-K D1:

- static and dynamic K=17 exact 17-digit values;
- static and dynamic K=5 decimal rounding;
- negative mantissa with negative exponent;
- positive and negative zero;
- positive and negative infinity.

Four strict cases require opcode-fallback abort, no native completion, and no
SIGSEGV for immediate/postincrement sources and postincrement static plus
predecrement dynamic destinations.

Accepted result:

```text
FPP_FMOVE_PACKED_FALLBACK_MATRIX service_pass=9 strict_pass=4 fail=0 total=13
```

Composition evidence remains:

```text
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=26 fail=0 total=26
FPP_FMOVE_DEST_INVALID_MATRIX pass=3 fail=0 total=3
```

## Structural contracts

- Packed size 3 must return failure in both ordinary source and destination
  decoders before the first memory-EA case.
- The service matrix must retain static/dynamic K=17, K=5 decimal rounding,
  signed exponent/mantissa, signed zero, infinities, guarded output, preserved
  D1, two visible fallbacks, and an exact total of 9.
- The strict matrix must retain source and destination writeback forms, reject
  native entry, require strict opcode fallback, forbid SIGSEGV, and total 4.

## Closure decision

No closure row is promoted. The deterministic inventory remains 997 rows. This
checkpoint closes ordinary packed FMOVE as an exact serviced boundary while
`generator,i_FPP` remains **unreviewed** pending its other subfamilies.
