# AArch64 JIT FPP ordinary-FMOVE double destination batch

## Scope

This incremental `i_FPP` checkpoint covers ordinary `FMOVE FPn,<ea>` with an
IEEE binary64 destination. It includes conversion from architectural extended
register state, all FPCR rounding directions, exact and inexact normal values,
range boundaries, signed specials and NaNs, and every writable basic/indexed
EA class.

IEEE-single, integer, extended, and packed destinations were accepted in
separate checkpoints. No closure row is promoted and `generator,i_FPP` remains
unreviewed.

## Defect and repair

The residual AArch64 path stored the native binary64 shadow directly. That is
not equivalent to converting the architectural extended register at instruction
execution:

- low significand bits may already have been discarded;
- extended exponents may already have overflowed or underflowed;
- NaN signalling state and payload metadata may already have been narrowed; and
- the FMOVE instruction's replacement exception status was cleared instead of
  reporting INEX2, OVFL, UNFL, or SNAN.

AArch64 double destinations now exit to configured MPFR service before
`put_fp_value()` and therefore before EA acquisition, writeback, or guest-memory
mutation. MPFR performs the 64-to-53-bit conversion under the selected FPCR
rounding direction, emits the two guest-endian words, and publishes replacement
status plus accrued exceptions. Its NaN conversion now quiets a local payload
copy rather than mutating the source FP register's architectural signalling
metadata.

## Focused evidence

`bun jit-test/fpp-fmove-double-destination-matrix.ts` passes **28 service + 3
strict** cases:

```text
FPP_DOUBLE_DEST_MATRIX service_pass=28 strict_pass=3 fail=0 total=31
```

The matrix proves:

- positive/negative zero and infinity;
- exact maximum finite, minimum normal, and minimum subnormal binary64 values;
- halfway normal rounding under nearest-even, plus-infinity, and minus-infinity;
- positive and negative overflow result selection;
- halfway minimum-subnormal rounding and exact-vs-inexact underflow status;
- positive/negative quiet-NaN sign and payload mapping;
- signalling-NaN quieting with SNAN status and accrued IOP, followed by an
  FPSR snapshot and exact extended serialization proving the source remains the
  original signalling payload;
- FP0 and maximum-field FP7 sources;
- `(An)`, A7 postincrement/predecrement, d16, brief indexed, full direct,
  full preindexed/postindexed, absolute short, and absolute long destinations;
- guarded eight-byte stores, exact A7 updates, base/index/source preservation,
  and integer `SR=0x271f`;
- native block entry followed by exact serviced-fallback attribution; and
- strict rejection before native entry.

Every service run replays the exact architectural 80-bit source and an FPSR
with all status bits poisoned, preventing stale binary64-shadow or status
success. The signalling-NaN case separately snapshots the conversion FPSR
before its preservation probe replaces instruction status. All runs use a CoW
disk and remove temporary profiles and clones.

## Incremental gate

The checkpoint requires the affected AArch64 build, focused 28+3 matrix,
structural audit, bounded independent review, clean local commit, and temporary
cleanup. The broad corpus/pressure/strict/clean/hash epoch remains deferred to
the 32-checkpoint boundary absent a demonstrated shared-seam regression.
