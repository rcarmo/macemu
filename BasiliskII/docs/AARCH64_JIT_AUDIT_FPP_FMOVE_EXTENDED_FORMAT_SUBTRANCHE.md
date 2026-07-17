# AArch64 JIT FPP ordinary FMOVE extended-format subtranche

## Scope

This is the eighth bounded subtranche of the reachable `i_FPP` audit. It covers
ordinary FMOVE 80-bit extended-format sources and destinations as a serviced
runtime boundary.

The AArch64 JIT stores FP registers in a binary64 native shadow. It therefore
cannot represent the 68881 extended format's 64-bit significand and 15-bit
exponent exactly. Correctness requires ordinary FMOVE.X to leave native
compilation before EA side effects and execute through the MPFR interpreter.

Packed decimal, FMOVEM, FMOVECR, control moves, explicit precision, arithmetic,
and the complete `i_FPP` lifecycle remain separate. The legacy extended helper
APIs remain reachable from those unaudited paths and are not promoted here.

## Defects found and repaired

### Pointer-as-vreg extended source crash

The AArch64 compatibility macro mapped `fmov_ext_rm()` to `fp_to_exten_rm()`,
whose second argument is a guest virtual address register. `get_fp_value()`
passed the host `temp_fp` pointer instead. An immediate FMOVE.X source entered
native code and hit a null-address SIGSEGV.

### Silent binary64 destination approximation

`raw_fp_from_exten_mr()` derives an 80-bit memory image from the binary64 native
shadow. It necessarily loses eleven significand bits and cannot preserve most
of the extended exponent range. The old ordinary destination path nevertheless
completed natively and advanced address-register writeback by twelve bytes.

Both source and destination size-2 gates now return failure on AArch64 before EA
calculation, postincrement/predecrement, conversion, or storage. The normal
engine then executes exact MPFR semantics; strict full-JIT aborts at the opcode
fallback boundary.

## Runtime evidence

`bun jit-test/fpp-fmove-extended-fallback-matrix.ts` has two fail-closed parts.

Eight normal-service cases load an extended value through absolute memory and
store it back through `(A0)`. They require a visible JIT fallback, guarded
output bytes, unchanged A0/SR, and byte-exact round trips for:

- positive and negative one;
- a low significand bit beyond binary64 precision;
- all 64 significand bits set;
- maximum finite extended value;
- minimum normal extended value;
- positive and negative zero.

Four strict cases require opcode-fallback abort with no native completion and no
SIGSEGV for immediate and postincrement sources plus postincrement and
predecrement destinations.

Accepted result:

```text
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
```

Composition evidence:

```text
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=26 fail=0 total=26
FPP_FMOVE_DEST_INVALID_MATRIX pass=3 fail=0 total=3
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure (isolated): pass=31 fail=0
```

## Structural contracts

- Both ordinary source and destination size switches must reject extended format
  under AArch64 before the first memory-EA case.
- The normal-service matrix must retain values outside binary64 precision/range,
  exact byte guards, exact-PC replay, visible fallback, and an exact total of 8.
- The strict matrix must retain source and destination writeback forms, reject
  native entry, require the strict opcode-fallback diagnostic, forbid SIGSEGV,
  and have an exact total of 4.
- Existing typed byte/word/long/single/double ordinary FMOVE routes must remain
  covered by their accepted matrices.

## Closure decision

No closure row is promoted. The deterministic inventory remains 997 rows with
zero classification changes. `generator,i_FPP`, `fp_to_exten_rm`,
`fp_from_exten_mr`, and their raw boundaries remain **unreviewed** because
FMOVEM/FMOVECR and other generated compositions still reach them. This
checkpoint closes only ordinary FMOVE.X by making its exact MPFR service
boundary explicit and fail-closed.
