# AArch64 JIT FPP static FMOVEM batch

## Scope

This incremental `i_FPP` checkpoint covers floating-register FMOVEM with
static register lists only. It includes exact FP0/FP1/FP7 transfer order,
regular and predecrement mask encoding, basic/indexed/PC-relative EAs, and
legal address-update modes.

Dynamic register lists remain a separate checkpoint. Control-register FMOVEM
was accepted separately. No closure row is promoted and `generator,i_FPP`
remains unreviewed.

## Defect and repair

The residual AArch64 compiler path materialised each FPU register through the
native binary64 shadow and then wrote an extended-format frame. That cannot
preserve architectural extended values with:

- significand bits below binary64 precision;
- exponent range beyond binary64; or
- exact NaN payload/sign metadata.

Static lists now exit to configured MPFR semantic service before EA acquisition
or mutation. The service serialises and imports the architectural 80-bit MPFR
register representation directly.

Dynamic lists retain their existing fail-closed path and are not claimed here.

## Static-list contract

Regular static lists use reversed mask bits (`0x80 >> FPn`) and transfer in
FP0-to-FP7 order. Predecrement uses direct bits and visits FP7-to-FP0 while
allocating each 12-byte extended frame downward. Legal address-update forms are
asymmetric:

- FPP-to-memory supports predecrement, but not postincrement;
- memory-to-FPP supports postincrement, but not predecrement.

Non-updating basic, indexed, and PC-relative source EAs follow normal ordering.

## Focused evidence

`bun jit-test/fpp-fmovem-static-service-matrix.ts` passes **10 service + 3
strict** cases:

```text
FPP_FMOVEM_STATIC_MATRIX service_pass=10 strict_pass=3 fail=0 total=13
```

The exact FP values are:

- FP0: `3fff:8000000000000001` (extended low bit beyond binary64);
- FP1: `7ffe:ffffffffffffffff` (maximum finite extended value); and
- FP7: `ffff:c000deadbeef1234` (negative quiet-NaN payload).

The matrix proves:

- all-register and sparse FP0+FP7 static masks;
- regular reversed mask and predecrement direct-mask interpretation;
- `(An)`, legal postincrement/predecrement, brief indexed, full preindexed,
  full postindexed, PC brief, and PC full-preindexed EAs;
- exact guarded 80-bit memory order and address updates;
- poisoned FP replay registers for memory-to-FPP cases, followed by exact
  80-bit stores, preventing stale second-pass success;
- base/index preservation and integer `SR=0x271f`;
- native entry followed by exact serviced-fallback attribution; and
- strict rejection before native entry.

All runs use a CoW disk and remove temporary profiles and clones.

## Incremental gate

The checkpoint requires the affected AArch64 build, focused 10+3 matrix,
structural audit, bounded independent review, clean local commit, and temporary
cleanup. The broad corpus/pressure/strict/clean/hash epoch remains deferred to
the 32-checkpoint boundary absent a shared-seam regression.
