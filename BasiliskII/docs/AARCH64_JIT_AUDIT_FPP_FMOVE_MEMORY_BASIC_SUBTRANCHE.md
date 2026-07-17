# AArch64 JIT FPP ordinary FMOVE basic-memory subtranche

## Scope

This is the third bounded subtranche of the reachable `i_FPP` generator audit.
It closes ordinary FMOVE source reads for the three basic address-register modes:

- `(An)`;
- `(An)+`;
- `-(An)`.

The matrix covers signed byte/word/long, IEEE single, and IEEE double values,
exact address-register writeback, A7 byte geometry, maximum A7/FP7 fields,
FPSR condition classes, integer-CCR preservation, and exact native entry.

It does **not** promote `generator,i_FPP`. Displacement, indexed, absolute,
PC-relative, extended-precision, explicit-precision, FMOVE stores, FMOVECR,
FMOVEM, control-register, arithmetic, and exception subfamilies remain separate.

## Result

No implementation change was required beyond the accepted ordinary-source
conversion repair. The existing `get_fp_value()` ordering composes correctly:

1. copy the original An or commit predecrement;
2. commit architectural postincrement where applicable;
3. fetch the guest value through the chosen effective address;
4. convert the fetched S2 value through the typed AArch64 FP MIDFUNC;
5. publish the destination FP register and result class.

`bun jit-test/fpp-fmove-memory-basic-matrix.ts` runs 18 fail-closed cases:

- five formats over `(A0)`, `(A0)+`, and `-(A0)`;
- byte `(A7)+` and `-(A7)` proving two-byte stack-pointer geometry;
- long `(A7)` to FP7 proving maximum address and FP register fields;
- exact FP shadow bits, exact FPSR CCB, exact An/A7 value, `SR=0x271f`,
  restored replay memory, strict full-JIT, and exact native entry.

Accepted result:

```text
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
```

Integrated evidence:

```text
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
```

The first pressure run had a single EXG infrastructure miss with no native or
interpreter-op evidence; its isolated replay passed, and the complete second
run passed 31/31.

## Structural contracts

- The matrix must contain `(An)`, `(An)+`, and `-(An)` generators.
- All five bounded formats must be present.
- Both A7 byte directions and maximum A7/FP7 fields must be present.
- Every case requires restored guest-memory fixtures, exact FP/FPSR/SR/An,
  strict full-JIT, exact native entry, CoW disk isolation, and an exact total of
  18.

## Closure decision

No closure status changes. The inventory remains 997 rows and
`generator,i_FPP` remains **unreviewed**. This evidence depends on conversion
MIDFUNCs already classified reachable/unreviewed by the preceding source
checkpoint. The next subtranche should cover d16/indexed/absolute/PC-relative
ordinary FMOVE source addressing without mixing in stores or explicit precision.
