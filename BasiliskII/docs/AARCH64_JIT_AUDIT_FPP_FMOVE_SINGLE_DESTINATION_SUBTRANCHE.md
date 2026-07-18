# AArch64 JIT FPP IEEE-single destination subtranche

## Scope

This is the sixth bounded subtranche of the reachable `i_FPP` audit. It closes
ordinary FMOVE conversion from the native double shadow to IEEE single for Dn
and the already accepted basic `(An)` store boundary.

Covered semantics:

- signed zero, finite normal values, minimum normal, and minimum subnormal;
- exact and inexact rounding under all four FPCR modes;
- positive and negative overflow result selection;
- exact subnormal versus tiny inexact underflow;
- signed infinity;
- quiet-NaN payload and sign preservation across MPFR/native shadows;
- 68k FPSR exception-status replacement and accrued-exception accumulation;
- integer CCR, host FPSR, and host FPCR preservation.

Signalling-NaN construction through the current public exact-native fixture,
extended destination EAs, double/extended/packed range semantics, explicit
precision, FMOVEM/control moves, arithmetic, and the complete `i_FPP` lifecycle
remain separate.

## Defects found and repaired

### Native status was not published

`raw_fmov_to_s_rr()` used AArch64 `FCVT S,D`, which produced correct rounded
single values but left all architectural 68k exception fields untouched. The
emitter now:

1. saves guest NZCV and host FPSR;
2. clears host FPSR for an isolated conversion window;
3. runs `FCVT S,D` and captures IOC/OFC/UFC/IXC;
4. restores host FPSR exactly;
5. replaces the 68k exception-status byte with SNAN/OVFL/UNFL/INEX2;
6. accumulates IOP/OVFL/UNFL/INEX according to `update_exceptions()`;
7. restores guest NZCV.

Accrued underflow requires both UFC and IXC, and accrued INEX includes overflow,
matching the MPFR interpreter boundary.

### MPFR NaN payload was discarded

The earlier shadow synchronisation preserved only NaN sign. This was sufficient
for integer saturation but not for IEEE-single stores. JIT entry now reconstructs
the native double NaN from MPFR `nan_bits` and `nan_sign` using the same payload
mapping as `extract_to_double()`. JIT exit maps the native payload and sign back
to MPFR metadata. Quiet-NaN single stores therefore retain their high-order
payload and sign through dispatcher entry and exit.

## Exact-native evidence

`bun jit-test/fpp-fmove-single-destination-matrix.ts` runs 21 fail-closed cases:

- positive/negative zero and infinity;
- maximum finite, minimum normal, and minimum subnormal;
- exact and inexact normal conversion;
- overflow under nearest, zero, minus-infinity, and plus-infinity;
- negative overflow under zero and minus-infinity;
- halfway-to-minimum-subnormal under nearest and directed rounding;
- negative tiny directed rounding;
- positive/negative quiet NaNs with payload `0x412345`;
- one `(A0)` overflow store through the guest-memory boundary;
- exact output bits, FPSR, `SR=0x271f`, strict full-JIT, and exact native entry.

Accepted result:

```text
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
```

Historical composition evidence at landing (the former 43-case source aggregate
was later split into 29 native plus 66+3 serviced register routes):

```text
FPP_FMOVE_DEST_BASIC_MATRIX pass=45 fail=0 total=45
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
FPP_FMOVE_MEMORY_BASIC_MATRIX pass=18 fail=0 total=18
FPP_FMOVE_EXTENDED_EA_MATRIX pass=39 fail=0 total=39
FPP_COMPARE_NATIVE_MATRIX pass=176 fail=0 total=176
FBCC_NATIVE_MATRIX pass=160 fail=0 total=160
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure (isolated): pass=31 fail=0
```

The first pressure run was invalid because it ran concurrently with the full
904-case suite; three cells recorded neither native nor interpreter-op entry.
The isolated complete replay passed 31/31.

## Structural contracts

- `raw_fmov_to_s_rr()` must save/restore NZCV and host FPSR.
- Native IOC/OFC/UFC/IXC must map to the exact 68k status/accrued fields.
- MPFR/native sync must preserve NaN payload and sign in both directions.
- The matrix must retain all four rounding modes, normal/subnormal/range classes,
  signed special values, payload cases, CoW disk, and an exact total of 21.

## Closure decision

This guest-semantic checkpoint does not promote `generator,i_FPP`,
`midfunc,fmov_to_s_rr`, or `raw_boundary,raw_fmov_to_s_rr`; they remain
**unreviewed**. It closes the ordinary IEEE-single conversion boundary but does
not claim the remaining destination-EA or broader FPP lifecycle.

A later direct generic-emitter audit independently exhausts all 2,048
`FCVT_sd`/`FCVT_ds` encodings and 256 native conversions, including 64 aliases,
all raw AArch64 FPCR modes, range/subnormal edges, qNaN/SNaN, exact host FPSR,
and external AAPCS/FP-state restoration. It promotes only those two emitter rows
to **audited**; see `AARCH64_JIT_AUDIT_FCVT_EMITTERS.md`.
