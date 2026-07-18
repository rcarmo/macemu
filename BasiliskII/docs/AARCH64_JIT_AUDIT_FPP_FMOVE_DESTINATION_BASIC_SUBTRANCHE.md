# AArch64 JIT FPP ordinary FMOVE basic-destination subtranche

## Scope

This is the fifth bounded subtranche of the reachable `i_FPP` audit. It covers
ordinary FMOVE destinations for:

- byte, word, long, and IEEE-single Dn writes;
- byte, word, long, IEEE-single, and IEEE-double stores through `(An)`, `(An)+`,
  and `-(An)`;
- byte A7 postincrement/predecrement geometry;
- FP7-to-D7 maximum register fields;
- integer rounding, saturation, exception publication, lane preservation, and
  basic writable-EA ordering.

The integer conversion boundary is closed here. IEEE-single special-value and
range exception fidelity, displacement/indexed/absolute/PC-relative stores,
extended/packed formats, explicit precision, FMOVEM/control moves, arithmetic,
and the complete `i_FPP` lifecycle remain separate.

## Defects found and repaired

### Pointer-as-vreg destination conversion

The AArch64 compatibility path in `put_fp_value()` inherited the historical
`temp_fp` memory-conversion sequence. ARM64 compatibility macros interpret its
argument as a virtual register, so native FP-to-integer stores could write zero
or unrelated state. Byte, word, long, and single destinations now use the typed
AArch64 MIDFUNC conversion routes directly. Double stores split the native
double into guest-order words and retain normal guest-memory write boundaries.

### MPFR-compatible integer saturation and exceptions

AArch64 `FCVTAS` alone does not implement the MPFR interpreter contract: NaN
converts to zero, and invalid conversion does not publish 68k OPERR/accrued IOP.
The shared integer destination emitter now:

1. rounds under the active guest FPCR mode;
2. converts and saturates byte/word/long results by architectural source sign;
3. preserves upper Dn lanes for byte/word writes;
4. distinguishes exact, inexact, and invalid/range cases;
5. replaces the FPSR exception-status byte with INEX2 or OPERR as required;
6. accumulates INEX or IOP without changing CCB or quotient;
7. preserves guest integer NZCV around private classification.

### FPCR and signed-NaN boundary fidelity

JIT entry previously did not map the 68k FPCR rounding mode into AArch64 FPCR.
It now maps nearest/zero/minus-infinity/plus-infinity to AArch64 RMode and
restores the host FPCR before returning to C.

MPFR stores NaN sign outside `mpfr_t`; `mpfr_get_d()` therefore lost negative
NaN at the native shadow boundary. Entry and exit sync now preserve NaN sign in
the double shadow and MPFR `nan_sign`, which is required for sign-directed
integer saturation.

## Exact-native evidence

`bun jit-test/fpp-fmove-destination-basic-matrix.ts` runs 45 fail-closed cases:

- exact byte/word/long and single Dn writes;
- exact signed bounds and one-unit overflow around byte/word/long limits;
- nearest-even, toward-zero, toward-minus-infinity, and toward-plus-infinity;
- positive/negative finite overflow, fractional overflow, infinity, and NaN;
- exact FPSR CCB/quotient preservation plus exception-status replacement and
  accrued exception accumulation;
- FP7-to-D7 maximum fields and byte/word upper-lane preservation;
- exact single and double destinations clearing stale prior exception status;
- five formats over `(A0)`, `(A0)+`, and `-(A0)`;
- A7 byte geometry;
- exact memory bytes, writeback, `SR=0x271f`, strict full-JIT, and exact native
  entry.

Accepted result:

```text
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
```

Composition evidence:

```text
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_COMPARE_NATIVE_MATRIX pass=176 fail=0 total=176
FBCC_NATIVE_MATRIX pass=160 fail=0 total=160
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
```

## Structural contracts

- `put_fp_value()` must use typed byte/word/long/single conversion MIDFUNCs.
- Double stores must remain on normal guest-memory write boundaries.
- One shared integer classifier owns FPCR rounding, signed saturation,
  OPERR/INEX publication, accrued IOP/INEX, and NZCV preservation.
- Entry/exit sync must preserve host FPCR and MPFR NaN sign.
- The exact-native matrix must retain all four rounding modes, both NaN signs,
  integer boundaries, maximum register fields, basic writable EAs, CoW disk,
  and an exact total of 45.

## Closure decision

This guest-semantic subtranche does not promote `generator,i_FPP`, which remains
**unreviewed**. The reachable integer conversion MIDFUNC/raw rows remain
unreviewed until their remaining generated compositions and the broader
destination lifecycle are closed; single conversion remains explicitly outside
this integer checkpoint.

A later direct generic-emitter audit independently exhausts all 1,024
`FCVTAS_wd` encodings and 256 native result/state vectors, including W0/W30/W31,
D31, four FPCR modes, fractional IXC, invalid IOC, saturation, NaNs, and external
AAPCS/FP-state restoration. Its mechanically selected strict-native integer
composition subset passes 36/36 byte/word/long cases; ordinary double stores
now belong to their accepted semantic-service matrix. It promotes only
`emitter_api,FCVTAS_wd` to **audited**; see
`AARCH64_JIT_AUDIT_FCVTAS_EMITTER.md`.
The deterministic inventory remains 997 rows. Its exact classification delta
is reachability-only: `fmov_to_b_rr`, `fmov_to_w_rr`, and `fmov_to_d_rrr` move
from unreachable to reachable/unreviewed through `put_fp_value()`, while
`CLZ_ww` moves from unreviewed to unreachable after removal of the old
count-leading-zero saturation sequence.
