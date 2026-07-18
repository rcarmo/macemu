# AArch64 JIT FPP indexed control-memory batch

## Scope

This evidence-only incremental `i_FPP` checkpoint audits FPCR, FPSR, and FPIAR
memory transfers through 68020/68040 indexed effective addresses only.

Covered forms are:

- An-relative brief indexing with word/long index, scale, and displacement;
- An-relative full direct indexing;
- An-relative full preindexed and postindexed memory indirection;
- PC-relative brief indexing;
- PC-relative full direct indexing; and
- PC-relative full preindexed and postindexed memory indirection.

Basic memory EAs were accepted in the preceding checkpoint. Floating-register
FMOVEM remains separate. No closure row is promoted and `generator,i_FPP`
remains unreviewed.

## Result

The existing MPFR service correctly routes indexed address calculation through
`get_disp_ea_020()` and then applies the accepted FPCR/FPSR/FPIAR transfer
order. No source defect was reproduced, so no implementation change is made.

The matrix independently seeds all pointer cells and payloads. Base and index
registers must remain exact after every transfer. It covers all-register and
sparse FPCR+FPIAR masks in both directions, including D7.W*8 sign extension and
maximum index field.

PC-relative witnesses use the extension-word PC as the base. The full
postindexed sparse case uses a positive word base displacement `0x0ff4` to
reach pointer cell `0x2000`; after indirection, D1 is added to reach payload
`0x3000`. An earlier negative `0xfff4` test oracle correctly faulted and was
discarded.

## Focused evidence

`bun jit-test/fpp-control-memory-indexed-matrix.ts` passes **14 service + 3
strict** cases:

```text
FPP_CONTROL_MEMORY_INDEXED_MATRIX service_pass=14 strict_pass=3 fail=0 total=17
```

The matrix proves:

- five An-relative forms per direction: brief, full direct, full preindexed,
  full postindexed, and a maximum word-index sparse case;
- four PC-relative memory-to-control forms: brief, full direct, full
  preindexed, and full postindexed;
- exact guarded memory bytes and independent indirection pointer cells;
- exact base/index preservation;
- represented FPCR/FPSR and full-width FPIAR readback;
- second-pass independence: read cases replay distinct FPCR/FPSR poison values,
  and the first pass overwrites FPIAR with `0x0badc0de` after capturing D6, so
  stale/no-op second-pass loads fail every imported control-register oracle;
- integer `SR=0x271f` preservation;
- native entry followed by exact serviced-fallback opcode attribution; and
- strict full-JIT rejection before native entry.

Every run uses a CoW disk and removes its profile and clone in `finally` paths.

## Incremental gate

The checkpoint requires the focused 14+3 matrix, structural audit, bounded
independent review, a clean local commit, and temporary-storage cleanup. No
broad corpus, allocator-pressure epoch, clean rebuild, or publication runs
before the 32-checkpoint boundary absent a demonstrated shared seam.
