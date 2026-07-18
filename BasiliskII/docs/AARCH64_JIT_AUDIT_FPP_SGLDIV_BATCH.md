# AArch64 JIT FPP FSGLDIV batch

## Scope

This bounded checkpoint covers `FSGLDIV` (`0x24`) only. `FSGLMUL`, control
operations, and complete `i_FPP` closure remain separate.

## Semantics and repairs

FSGLDIV accepts arbitrary-precision inputs but rounds the quotient significand
to single precision while retaining the extended exponent range. It therefore
must not pre-round either operand and must not report single-format overflow or
underflow merely because the exponent lies outside IEEE single range.

AArch64 now enters semantic service before native operand acquisition. MPFR
service loads both operands as extended values and divides destination by source
directly into a 24-bit result while extended exponent limits are active. This is
a single rounding of the exact quotient, not extended rounding followed by a
second single rounding. Binary NaN ownership and Motorola DZ/OPERR status are
published at the shared result boundary.

## Focused evidence

`bun jit-test/fpp-sgldiv-service-matrix.ts` passes:

```text
FPP_SGLDIV_MATRIX service_pass=23 strict_pass=1 fail=0 total=24
```

The matrix covers:

- independent one-sided destination/source operand-retention witnesses;
- a quotient immediately above a single midpoint that fails under
  extended-then-single double rounding;
- nearest, zero, plus and a negative round-minus discriminator, independent of
  FPCR precision selection;
- maximum and minimum extended exponent results that must not become
  single-format overflow/underflow;
- divide by zero, zero/zero and infinity/infinity OPERR, and zero/infinity;
- qNaN/SNaN suppression, quieting and destination precedence;
- FP7 alias/reseed, postincrement/predecrement EA effects, accrued FPSR,
  integer CCR preservation, exact native entry and strict rejection; and
- exact fallback opcode attribution at PC `0x1008` for register and EA forms.

The complete two-pass service profile is pinned as one initial
`f239@0x1000` destination load followed by two identical source/FSGLDIV,
FPSR-capture, and store triples. Absolute-long source uses PCs
`0x1008/0x1010/0x1014`; register, postincrement, and predecrement forms use
`0x1008/0x100c/0x1010` with their exact `f200`/`f218`/`f220` source opcode.
This replaces the stale six-boundary exception for the signalling-destination
case; clean runtime records seven non-duplicative boundaries.

## Structural and review decision

The structural audit pins the AArch64 pre-acquisition service guard, operation
36 extended-source membership, direct 24-bit divide under extended exponent
limits, exact midpoint and one-sided records, special/NaN classes, fallback
attribution, strict rejection, and 23+1 accounting.

Independent review found an initial extended-then-single double-rounding path,
missing midpoint/directed witnesses, and generic fallback attribution. All were
repaired. A final source review also removed accidental FSGLMUL membership from
the new predicate, keeping this checkpoint bounded.

No closure row is promoted to **audited**. `generator,i_FPP` remains
**unreviewed** pending all selector groups.

A later combined divide-root audit established that this selector and the
FDIV/FSDIV/FDDIV block are the only configured `fdiv_rr` roots, and both
service before operand acquisition. With no MIDFUNC caller, `fdiv_rr` and
`raw_fdiv_rr` are therefore **unreachable**. This matrix remains the **23+1**
runtime-fidelity proof for the FSGLDIV root.

A subsequent lower-chain audit established that `fsgldiv_rr` also has no
configured caller, `raw_fsgldiv_rr` is definition-only, and its `FDIV_sss` call
is the sole binary32 divide-emitter site. The raw wrapper and `FDIV_sss` are now
**unreachable**, guarded by exact parent, ordered
`FCVT_sd`→`FDIV_sss`→`FCVT_ds`, site-count, and future-caller checks.
A later paired remainder lower-chain audit also classifies all three retained
`FDIV_ddd` sites unreachable: ordinary, FMOD, and FREM wrappers are all dead
after configured service. Direct binary64 evidence remains historical; shared
FCVT emitters remain audited/reachable. This is retirement, not native
acceptance, and `generator,i_FPP` remains unreviewed.
