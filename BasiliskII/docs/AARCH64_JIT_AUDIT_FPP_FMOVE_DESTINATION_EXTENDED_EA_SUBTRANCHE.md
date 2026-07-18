# AArch64 JIT FPP ordinary FMOVE extended-destination-EA subtranche

## Scope

This is the seventh bounded subtranche of the reachable `i_FPP` audit. It
covers ordinary FMOVE stores through the remaining alterable destination EAs:

- `d16(An)`;
- brief and full `d8(An,Xn)`, including direct, preindexed-indirect, and
  postindexed-indirect forms;
- absolute short and absolute long;
- byte, word, long, IEEE-single, and IEEE-double values;
- maximum data/address/FP register fields and an all-integer-registers-live
  indexed-store case.

PC-relative and immediate EAs are source-only and are required to fail
compilation. Extended and packed formats, explicit precision, FMOVEM/control
moves, arithmetic, and the complete `i_FPP` lifecycle remain separate.

## Defect found and repaired

### Source-only EAs were accepted as destinations

`put_fp_value()` rejected indexed-PC stores but still accepted `d16(PC)` and
immediate destination encodings. Both could compile natively and emit writes to
non-alterable addresses. The destination decoder now rejects all three
source-only modes before consuming their extensions or emitting a write.

A strict negative matrix reproduced the original defect: `d16(PC)` and
immediate completed natively before the repair, while indexed PC already fell
back. After the repair all three terminate through the fail-closed opcode
fallback contract.

## Exact-native evidence

`bun jit-test/fpp-fmove-destination-extended-ea-matrix.ts` runs 26 writable
cases:

- five formats over positive `d16(A0)`, brief indexed A0/D1, absolute short,
  and absolute long;
- negative `d16(A7)` from FP7 and maximum D7.W indexed fields;
- full direct, preindexed-indirect, and postindexed-indirect formats;
- one brief indexed store with all D0-D7 and available A0-A5 live;
- guarded bytes before and after every destination;
- exact memory bytes, base/index preservation, stale FPSR status replacement,
  `SR=0x271f`, strict full-JIT, and exact native entry.

Accepted result:

```text
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=26 fail=0 total=26
```

`bun jit-test/fpp-fmove-destination-invalid-matrix.ts` requires strict opcode
fallback for `d16(PC)`, indexed PC, and immediate destinations:

```text
FPP_FMOVE_DEST_INVALID_MATRIX pass=3 fail=0 total=3
```

Historical composition evidence at landing (the former 43-case source aggregate
was later split into 29 native plus 66+3 serviced register routes):

```text
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_COMPARE_NATIVE_MATRIX pass=176 fail=0 total=176
FPP_FTST_NATIVE_MATRIX pass=128 fail=0 total=128
FBCC_NATIVE_MATRIX pass=160 fail=0 total=160
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure (isolated): pass=31 fail=0
```

An earlier integrated attempt exhausted the tmpfs and a parallel comparison
attempt lost X11; neither produced a semantic mismatch and neither is counted.
After volatile-storage cleanup, the complete corpus and allocator suite passed
serially with zero infrastructure failures.

## Structural contracts

- `put_fp_value()` must retain d16/indexed An and absolute short/long destination
  calculations through the typed conversion and guest-memory write boundary.
- PC-relative and immediate destinations must return failure before extension
  consumption or write emission.
- The writable matrix must retain all five ordinary formats, brief/full indexed
  forms, guarded writes, maximum fields, live-register pressure, CoW disk, and
  an exact total of 26.
- The invalid matrix must retain all three non-alterable modes and require the
  strict opcode-fallback diagnostic with no native completion.

## Closure decision

No closure row is promoted. The deterministic inventory remains 997 rows with
zero classification changes; its CSV movement is source-line metadata only.
`generator,i_FPP`, the reachable destination-conversion MIDFUNCs, and their raw
boundaries remain **unreviewed** until the remaining formats and broader FPP
lifecycle are closed.
