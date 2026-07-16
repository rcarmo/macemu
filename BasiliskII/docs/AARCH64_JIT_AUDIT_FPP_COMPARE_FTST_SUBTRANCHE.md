# AArch64 JIT FPP FCMP/FTST subtranche

## Scope

This is the first bounded subtranche of the reachable `i_FPP` generator audit.
It closes the condition-result producers `FCMP` and `FTST` for the configured
`USE_JIT_FPU` AArch64 path across exact FPSR condition classes, integer-CCR
preservation, native entry, and MPFR/native-double transition behavior.

It does **not** promote `generator,i_FPP`. Arithmetic, conversion, FMOVE,
FMOVECR, control-register, FMOVEM, precision, exception, and semantic-service
subfamilies remain to be audited before that row can close.

## Defects found and repaired

1. Native FCMP used `FP_RESULT = destination - source` as a comparison proxy.
   Arithmetic subtraction is not comparison-equivalent for IEEE infinities:
   equal infinities produce NaN, while unequal infinite comparisons can publish
   the forbidden FPSR Infinity class. FCMP now emits a direct AArch64 `FCMP`
   classifier and materialises only `-1.0`, signed/unsigned zero, `+1.0`, or
   canonical quiet NaN into the lazy result carrier.
2. Equality requires more than predicate equivalence. The 68k condition result
   is `N|Z` for equal negative zero and equal negative infinity, but plain `Z`
   for equal negative finite numbers. The classifier therefore materialises
   `-0.0` only for equal `-0` and `-Inf`, and `+0.0` for other equal values.
3. FCMP and FTST operand plumbing can overwrite host NZCV even though FPP
   instructions do not alter integer CCR. Both producers now save integer CCR
   before any AArch64 comparison or conversion that may clobber NZCV.
4. The existing FTST self-alias repair remains required: when the source virtual
   register is `FP_RESULT`, publication goes through distinct `FS1` ownership so
   `fmov_rr` cannot elide the write and expose stale condition state.
5. REGDUMP previously omitted FPSR, allowing branch-equivalent but
   architecturally wrong condition classes to pass. It now includes `FPSR`, and
   the focused matrices assert exact CCB values.

## Runtime evidence

`bun jit-test/fpp-compare-native-matrix.ts` runs 176 fail-closed strict cases:

- eleven destination/source classes, including finite less/equal/greater,
  negative finite equality, signed-zero equality, equal and unequal infinities,
  and NaN in either operand;
- all sixteen 68881 predicates;
- exact second-pass native entry at FCMP;
- exact successor, full integer `SR=0x271f`, and exact FPSR CCB.

Accepted result:

```text
FPP_COMPARE_NATIVE_MATRIX pass=176 fail=0 total=176
```

`bun jit-test/fpp-ftst-native-matrix.ts` runs 128 fail-closed strict cases:

- positive/negative finite, positive/negative zero, positive/negative infinity,
  and positive/negative NaN;
- all sixteen 68881 predicates;
- exact second-pass native entry at FTST;
- exact successor, full integer `SR=0x271f`, and exact FPSR CCB including NaN
  sign.

Accepted result:

```text
FPP_FTST_NATIVE_MATRIX pass=128 fail=0 total=128
```

Integrated evidence after the FPSR dump contract changed:

```text
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
strict negative gate: allocation fallback plus 4/4 expected abort probes
```

A clean configured AArch64 build produced an AArch64 ELF. Generated opcode
sources were byte-identical before clean, after clean, and after two explicit
regenerations:

```text
compemu.cpp  55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260
compstbl.cpp 45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h    67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

The deterministic inventory remains 997 rows. Its regenerated source-location
and caller-count hashes are:

```text
CSV       be3b8b7ae7e434d0f52c3c9fd06667b9b3ba37d2cf28638154e23be075a6b932
Markdown  f6b7db6a4ddb897b9c246a04b21c51000debf8bcaf01357e7682c73b6ac174ee
```

## Structural contracts

- `fcompare_result_rr` owns distinct result, destination, and source FP virtual
  registers and lowers through `raw_fcompare_result_rr`.
- The raw classifier uses AArch64 `FCMP`, never FP subtraction.
- Exact constants cover negative, zero, positive, unordered, and signed-equal
  classes.
- FCMP and FTST preserve integer CCR before host-NZCV clobbers.
- Both focused matrices require strict full-JIT, exact native entry, CoW disk
  isolation, exact SR, exact FPSR, and exact totals.
- Structural audit reports 176 FCMP and 128 FTST exact-native vectors.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** until all
reachable FPP subfamilies have direct evidence or an explicit serviced/
unreachable classification. The next FPP chunk is source conversion and FMOVE
register/immediate behavior, which supplies operands to this accepted producer
slice.
