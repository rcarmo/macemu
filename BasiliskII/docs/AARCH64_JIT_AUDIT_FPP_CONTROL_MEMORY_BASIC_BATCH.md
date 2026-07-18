# AArch64 JIT FPP basic control-memory batch

## Scope

This evidence-only incremental `i_FPP` checkpoint audits FPCR, FPSR, and FPIAR
transfers through basic memory effective addresses:

- `(An)`;
- `(An)+`;
- `-(An)`;
- `(d16,An)`;
- absolute word and long; and
- `(d16,PC)` for memory-to-control transfers.

Brief/full indexed EAs and floating-register FMOVEM are excluded and remain
separate checkpoints. No closure row is promoted; `generator,i_FPP` remains
unreviewed.

## Result

The configured AArch64 path already exits to MPFR semantic service for these
forms. No implementation defect was reproduced, so this checkpoint adds no
speculative source change. It records exact runtime and structural evidence for
the existing contract.

The service processes selected registers in architectural memory order:
FPCR, FPSR, then FPIAR. Sparse FPCR+FPIAR masks remain contiguous in memory.
For predecrement, the complete selected frame is allocated before the first
transfer. Postincrement advances by exactly four bytes per selected register.
The tested A7 all-register frame moves by twelve bytes in both directions.

Memory-to-control imports pass through `set_fpcr()` and `set_fpsr()`, so readback
observes 68040 FPCR and represented-FPSR masking. FPIAR remains full width.
Control-to-memory exports use the same represented values.

## Focused evidence

`bun jit-test/fpp-control-memory-basic-matrix.ts` passes **15 service + 3
strict** cases:

```text
FPP_CONTROL_MEMORY_BASIC_MATRIX service_pass=15 strict_pass=3 fail=0 total=18
```

The matrix proves:

- all-register and sparse FPCR+FPIAR ordering in both directions;
- guarded exact guest-memory bytes;
- `(An)`, A7 postincrement/predecrement, positive `(d16,A0)`, absolute word,
  absolute long, and PC-relative source addressing;
- exact A0/A7 updates and preservation;
- exact FPCR/FPSR/FPIAR readback after memory import;
- integer `SR=0x271f` preservation;
- native entry followed by exact serviced-fallback opcode attribution; and
- strict full-JIT rejection before native entry.

Every run uses a CoW disk and removes its profile and clone in `finally` paths.

## Incremental gate

The checkpoint requires the focused 15+3 matrix, structural audit, bounded
independent review, a clean local commit, and temporary-storage cleanup. No
broad corpus, allocator-pressure epoch, clean rebuild, or publication runs
before the 32-checkpoint batch boundary absent a demonstrated shared seam.
