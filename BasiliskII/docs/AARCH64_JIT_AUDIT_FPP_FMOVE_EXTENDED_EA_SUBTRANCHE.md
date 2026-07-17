# AArch64 JIT FPP ordinary FMOVE extended-EA subtranche

## Scope

This is the fourth bounded subtranche of the reachable `i_FPP` audit. It covers
ordinary FMOVE source reads for:

- `d16(An)`;
- indexed An, both brief and 68020 full formats;
- absolute short and long;
- `d16(PC)`;
- indexed PC, both brief and 68020 full formats.

All five bounded source formats (byte, word, long, IEEE single, IEEE double)
are covered across the ordinary modes, together with positive/negative
displacements, index word/long and scaling, full-format direct/preindexed/
postindexed indirection, maximum register fields, exact FP/FPSR/SR values, and
source-register preservation.

It does **not** promote `generator,i_FPP`. Extended precision, explicit
precision, FMOVE stores, FMOVECR, FMOVEM, control-register, arithmetic, and
exception subfamilies remain separate.

## Defect found and repaired

The generated `FPP` handlers include the PC-indexed source opcode (`0xf23b`),
but `get_fp_value()` unconditionally returned `-1` for mode 7/register 3. Under
strict translation this was a live native-coverage gap; ordinary execution
could leave the block through the FPP compiler failure path.

PC-indexed sources now:

1. compute the architectural base as the extension-word PC;
2. materialise that base in private S2;
3. parse the brief/full extension word;
4. call the shared `calc_disp_ea_020` decoder with S1 as the distinct target and
   S3 as scratch;
5. fetch and convert through the already accepted ordinary-source path.

The base and target must remain distinct because the indexed-EA decoder may
write the target before consuming the base.

## Exact-native evidence

`bun jit-test/fpp-fmove-memory-extended-ea-matrix.ts` runs 39 fail-closed cases:

- five formats for d16 An, brief indexed An, absolute short, absolute long, and
  forward d16 PC;
- negative d16 and backward PC-relative cases;
- maximum A7/D7/FP7 fields and word-index scale-eight semantics;
- An full-format direct, preindexed indirect, and postindexed indirect;
- all five formats for brief PC indexing;
- PC full-format direct and preindexed indirect;
- exact FP shadow bits, FPSR CCB, `SR=0x271f`, preserved source/address
  registers, restored replay fixtures, strict full-JIT, and exact native entry.

Accepted result:

```text
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
```

Integrated evidence:

```text
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
```

The first pressure run was invalid because it ran concurrently with the full
904-case suite and six cells recorded neither native nor interpreter-op entry.
The isolated complete rerun passed 31/31.

## Structural contracts

- The matrix names every bounded EA class and all five value formats.
- Brief and full-format indexed An and PC paths are mandatory.
- Full direct/preindexed/postindexed An cases and PC indirect cases are
  mandatory.
- `get_fp_value()` must materialise the PC extension-word base distinctly and
  route PC indexing through `calc_disp_ea_020`.
- Every case requires exact FP/FPSR/SR, preserved input registers, CoW disk,
  restored memory, strict native entry, and an exact total of 39.

## Closure decision

No row is promoted to audited. The 997-row inventory remains intact and
`generator,i_FPP` remains **unreviewed**. This checkpoint closes ordinary FMOVE
source addressing other than extended-precision semantics; the next bounded
subtranche should begin ordinary FMOVE destinations/stores without mixing in
explicit-precision or arithmetic operations.
