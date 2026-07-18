# AArch64 JIT FPP dynamic FMOVEM batch

## Scope

This incremental `i_FPP` checkpoint covers floating-register FMOVEM with a
register-supplied list only. It audits D0, D3, and maximum-field D7 masks,
exact FP0/FP1/FP7 transfer order, regular and predecrement mask encoding,
basic/indexed/PC-relative EAs, legal address updates, and empty lists.

Static floating-register lists and control-register FMOVEM were accepted in
separate checkpoints. No closure row is promoted and `generator,i_FPP` remains
unreviewed.

## Compiler and service boundary

The AArch64 compiler already fails every dynamic-list form before
`get_fp_ad(opcode)`. No effective address, address register, FPU register, or
guest byte can therefore be mutated by the abandoned native path. Configured
fallback enters the MPFR service, which derives the architectural list from:

```text
D[(extra >> 4) & 7] & 0xff
```

No source repair was justified by this checkpoint.

## Dynamic-list contract

Regular lists use reversed mask bits (`0x80 >> FPn`) and transfer in FP0-to-FP7
order. Predecrement uses direct bits and visits FP7-to-FP0 while allocating each
12-byte extended frame downward. Legal address-update forms are asymmetric:

- FPP-to-memory supports predecrement, but not postincrement;
- memory-to-FPP supports postincrement, but not predecrement.

Only the low byte of the selected Dn controls the list. Empty lists transfer no
bytes, mutate no FPU register, and do not update predecrement/postincrement
address registers.

## Focused evidence

`bun jit-test/fpp-fmovem-dynamic-service-matrix.ts` passes **12 service + 3
strict** cases:

```text
FPP_FMOVEM_DYNAMIC_MATRIX service_pass=12 strict_pass=3 fail=0 total=15
```

The non-empty exact FP values are:

- FP0: `3fff:8000000000000001` (extended low bit beyond binary64);
- FP1: `7ffe:ffffffffffffffff` (maximum finite extended value); and
- FP7: `ffff:c000deadbeef1234` (negative quiet-NaN payload).

The matrix proves:

- D0, D3, and D7 list-register selection and high-24-bit irrelevance;
- all-register, sparse FP0+FP7, and empty masks;
- regular reversed-mask and predecrement direct-mask interpretation;
- `(An)`, legal postincrement/predecrement, brief indexed, full preindexed,
  full postindexed, PC brief, and PC full-preindexed EAs;
- exact guarded 80-bit memory order and address updates;
- poisoned FP replay registers for memory-to-FPP cases, followed by exact
  80-bit stores, preventing stale second-pass success;
- empty-list preservation of memory, FP0/FP1/FP7, and A0;
- base/index/list-register preservation and integer `SR=0x271f`;
- native entry followed by exact serviced-fallback attribution; and
- strict rejection before native entry.

All runs use a CoW disk and remove temporary profiles and clones.

## Incremental gate

The checkpoint requires the focused 12+3 matrix, structural audit, bounded
independent review, clean local commit, and temporary cleanup. It is
evidence-only, so no affected source build is required. The broad
corpus/pressure/strict/clean/hash epoch remains deferred to the 32-checkpoint
boundary absent a demonstrated shared-seam regression.
