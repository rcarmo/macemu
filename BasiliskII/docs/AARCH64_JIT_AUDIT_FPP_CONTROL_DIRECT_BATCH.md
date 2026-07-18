# AArch64 JIT FPP direct control-register batch

## Scope

This incremental `i_FPP` checkpoint covers only FPCR, FPSR, and FPIAR
transfers whose effective operand is a data register, address register, or
immediate long. Memory effective-address forms and floating-register FMOVEM
remain separate.

No closure row is promoted. `generator,i_FPP` remains unreviewed until the
remaining FPP lifecycle is exhausted.

## Defect and repair

The AArch64 compiler had mixed handling inside one architectural family:
FPCR and FPSR usually forced fallback, while selected FPIAR Dn/An/immediate
routes emitted native loads or stores. A combined control mask could also emit
one mutation before encountering an unsupported register and calling
`FAIL(1)`. That is not a fail-closed whole-instruction boundary.

AArch64 now exits to the configured semantic service before any direct or
immediate control-register mutation. The MPFR interpreter implementation owns
all list validation, CPU-model masking, state conversion, and PC consumption.
This also avoids trying to reconstruct complete FPCR/FPSR state from the old
partial native fields.

## Architectural contracts

- Dn accepts exactly one selected control register; multi-register masks are
  illegal rather than sequentially overwriting one Dn.
- An is legal only for FPIAR in this service implementation.
- Immediate transfers are FPU destinations only and likewise require one
  selected register.
- On a 68040, FPCR reads expose the low 16 bits; upper bits are masked.
- FPSR import/export preserves only represented condition, quotient, exception,
  and accrued fields; reserved bits do not reappear.
- FPIAR remains a full 32-bit value.
- Integer CCR is preserved.
- The exact opcode at PC `0x1008` is attributed as the serviced fallback after
  native block entry; strict full-JIT rejects the same opcode before native
  entry.

## Focused evidence

`bun jit-test/fpp-control-direct-service-matrix.ts` passes **11 service + 4
strict** cases:

```text
FPP_CONTROL_DIRECT_MATRIX service_pass=11 strict_pass=4 fail=0 total=15
```

The matrix covers FPCR/FPSR/FPIAR in both directions where legal, D7 and A7
maximum fields, immediate values, sequential read-back, 68040 FPCR masking,
FPSR reserved-bit masking, full-width FPIAR, exact native entry/fallback
attribution, strict rejection, and `SR=0x271f`.

FPIAR read witnesses seed architectural state with a legal first-pass immediate
transfer rather than a test-only FPIAR hook. All runs use a CoW disk and remove
temporary profiles and clones.

## Incremental gate

This checkpoint requires only:

1. the affected AArch64 `BasiliskII` rebuild;
2. the 11+4 focused matrix;
3. structural contract audit;
4. bounded independent review; and
5. a clean local commit and temporary-storage check.

No active-risky corpus, allocator-pressure epoch, clean rebuild, or publication
runs before the 32-checkpoint batch boundary unless a shared-seam regression is
demonstrated.
