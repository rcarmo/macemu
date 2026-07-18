# AArch64 JIT FPP ordinary register-FMOVE batch

## Scope

This incremental `i_FPP` checkpoint covers ordinary `FMOVE FPm,FPn` only. It
exhausts every one of the 64 source/destination register pairs, including all
eight self aliases, exact architectural extended values, NaN metadata, FPSR
classification, and integer-state preservation.

Dn/immediate/memory sources, explicit-precision moves, memory destinations,
FMOVEM, control transfers, and arithmetic selectors are accepted separately.
No closure row is promoted and `generator,i_FPP` remains unreviewed.

## Defect and repair

The residual AArch64 path lowered an FP-register move through `fmov_rr`, whose
raw boundary emits `FMOV Dd,Ds`. That copies only the binary64 shadow. An
ordinary 68040 FMOVE is an architectural extended-precision copy and therefore
must preserve:

- low significand bits below binary64 precision;
- exponents above and below binary64 range;
- signed zero and infinity; and
- NaN sign, payload, and signalling state before architectural quieting rules.

AArch64 register-source FMOVE now exits to configured MPFR service before
`get_fp_value()` or either FP allocator operand is acquired. MPFR copies the
extended source, applies untrapped signalling-NaN quieting/status semantics,
publishes the destination condition code, and leaves distinct sources
unchanged.

This does not retire `midfunc,fmov_rr` or `raw_boundary,raw_fmov_rr`: they remain
reachable allocator primitives in FPSR/compare and register-relocation paths,
so their general closure is separate.

## Focused evidence

`bun jit-test/fpp-fmove-register-service-matrix.ts` passes **66 service + 3
strict** cases:

```text
FPP_REGISTER_MOVE_MATRIX service_pass=66 strict_pass=3 fail=0 total=69
```

For each FP0-FP7 source and each FP0-FP7 destination, the matrix:

- replays all eight architectural registers with distinct exact 80-bit values;
- executes the audited move at `0x1008`;
- snapshots the move's FPSR through a previously accepted direct control read;
- serializes source and destination independently as exact extended frames;
- proves distinct sources are unchanged and self aliases retain the expected
  architectural result;
- checks all integer registers except the intentional D6 snapshot and A6
  sentinel, plus `SR=0x271f`;
- requires native block entry followed by exact serviced-fallback attribution;
  and
- requires strict rejection before native entry.

Two additional low-significand cases replay single and double FPCR precision,
proving that ordinary register FMOVE remains an exact extended copy independent
of the arithmetic precision field.

The eight value classes include an extended-only low significand bit, maximum
finite extended, a normal value below binary64 range, negative zero, positive
infinity, quiet and signalling NaN payloads, and a negative extended finite
value. The signalling case proves quieted destination metadata and SNAN/accrued
IOP while a distinct source retains its original signalling payload.

All runs use a CoW disk and remove temporary profiles and clones.

## Incremental gate

The checkpoint requires the affected AArch64 build, focused 66+3 matrix,
structural audit, bounded independent review, clean local commit, and temporary
cleanup. The broad corpus/pressure/strict/clean/hash epoch remains deferred to
the 32-checkpoint boundary absent a demonstrated shared-seam regression.
