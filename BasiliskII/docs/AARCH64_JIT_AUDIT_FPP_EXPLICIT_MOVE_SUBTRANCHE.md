# AArch64 JIT FPP explicit-precision move subtranche

## Scope

This bounded `i_FPP` subtranche covers `FSMOVE` and `FDMOVE`, the explicit
single- and double-precision register moves. These operations force 24- or
53-bit precision independently of the normal extended-precision register
format and publish rounding/range exceptions.

On AArch64 they are now exact MPFR service boundaries. Ordinary FMOVE remains
on its previously audited native routes. Explicit-precision arithmetic,
FMOVECR, FMOVEM/control moves, and the complete `i_FPP` lifecycle remain
separate.

## Defect found and repaired

`comp_fpp_opp()` grouped FMOVE, FSMOVE, and FDMOVE into one `fmov_rr()` copy.
That copy applied no forced precision and published no explicit-operation
rounding status. A reproduced FSMOVE halfway value remained
`0x3ff0000010000000` in the native binary64 shadow instead of rounding to
binary32 precision.

The AArch64 shadow also cannot hold every MPFR value that FDMOVE must round to
binary64. Reusing the existing single helper would still leave exception and
wide-source boundaries incomplete. FSMOVE/FDMOVE therefore fail before operand
acquisition or copy emission and execute through the exact MPFR service.
Ordinary FMOVE falls through to its existing native implementation.

## Runtime evidence

`bun jit-test/fpp-explicit-move-fallback-matrix.ts` runs thirteen normal-service
cases. Each sequence loads an 80-bit source into FP1, executes FSMOVE/FDMOVE to
FP0, and stores FP0 back as 80-bit memory. It requires three visible service
fallbacks, guarded exact bytes, exact FPSR, unchanged A0/SR, and whole-sequence
replay so MPFR owns the wide source continuously.

Covered semantics:

- positive and negative FSMOVE halfway values under nearest, zero,
  minus-infinity, and plus-infinity;
- FDMOVE halfway rounding under nearest and plus-infinity;
- finite maximum-extended to double overflow/infinity;
- exact positive infinity and negative zero;
- INEX accrued state, OVFL/accrued OVFL+INEX, and exact CCB classes.

Two strict cases use FP7 self-alias and maximum source/destination fields for
FSMOVE and FDMOVE. They require strict opcode fallback, no native entry, and no
SIGSEGV.

Accepted result:

```text
FPP_EXPLICIT_MOVE_FALLBACK_MATRIX service_pass=13 strict_pass=2 fail=0 total=15
```

Historical composition evidence at landing (the former 43-case source aggregate
was later split into 29 native plus 66+3 serviced register routes):

```text
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=26 fail=0 total=26
FPP_FMOVE_DEST_INVALID_MATRIX pass=3 fail=0 total=3
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
FPP_FMOVE_PACKED_FALLBACK_MATRIX service_pass=9 strict_pass=4 fail=0 total=13
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure (isolated): pass=31 fail=0
```

## Structural contracts

- AArch64 FSMOVE/FDMOVE cases must issue `FAIL(1)` and return before
  `get_fp_value()` or `fmov_rr()`.
- Ordinary FMOVE must remain after the explicit service gate and retain its
  existing native route.
- The service matrix must retain all four FPCR directions, both signs, single
  and double halfway cases, double overflow, exact special values, guarded
  80-bit output, FPSR, and an exact total of 13.
- Strict coverage must retain FP7 self-alias maximum fields for both operations
  and total 2.

## Closure decision

The original explicit-move checkpoint promoted no closure row. `fmovs_rr` and
`fcuts_r` were already unreachable; `generator,i_FPP` remains **unreviewed**
pending the other FPP subfamilies.

A later configured-root audit established that `raw_fcuts_r` is definition-only
beneath unreachable `fcuts_r`. Its exact MIDFUNC parent, narrowing-then-widening
body, `LOWFUNC`/`LENDFUNC`-only reference count, and future-caller absence are
now fail-closed structural contracts, so `raw_fcuts_r` is **unreachable**.

This is raw-boundary retirement, not native acceptance. The accepted **13+2**
FSMOVE/FDMOVE matrix remains configured guest runtime evidence. `FCVT_sd` and
`FCVT_ds` remain audited and reachable through their other compositions, with
all **7/6** configured sites retained.

A subsequent graph-only checkpoint also retired the definition-only
`raw_fmovs_rr` wrapper beneath unreachable `fmovs_rr`. That distinct-destination
narrow/widen primitive had no configured guest selector and is not evidence for
FSMOVE/FDMOVE service; direct FCVT conformance and the live ordinary
single-destination matrix own its lower shared operations.
