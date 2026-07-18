# AArch64 generic FMOV X/D bit-transfer emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `783ced00`

## Scope

This checkpoint audits the complete reachable reciprocal 64-bit bit-transfer
pair:

- `FMOV_dx(Dd,Xn)`: copy an X register's 64 bits into a D lane;
- `FMOV_xd(Xd,Dn)`: copy a D lane's 64 bits into an X register.

These are exact bit transfers, not floating-point arithmetic or conversion.
The checkpoint does not promote any raw boundary, MIDFUNC, memory path, compare
helper, extended-format path, or `generator,i_FPP`.

## Configured source sites

Configured AArch64 source has six `FMOV_dx` and four `FMOV_xd` sites. They are
used by:

- split integer-pair ↔ binary64 transfers;
- integer destination publication;
- floating compare-result construction;
- extended-format memory unpacking and packing.

The exact 6/4 counts and authoritative source spellings are structural. A new
source site does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-fmov-dx-xd-conformance.cpp` directly includes the production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts all register fields:

- **1,024** `FMOV_dx` words;
- **1,024** `FMOV_xd` words.

Native execution exhausts both 32×32 field matrices:

- **1,024** `FMOV_dx` routes;
- **1,024** `FMOV_xd` routes;
- **64** same-number cross-bank routes.

The bit corpus covers positive/negative zero, infinities, quiet/signalling NaN
images, the minimum nonzero bit, and low-significand payloads. The oracle pins:

- exact 64-bit copying without arithmetic conversion or canonicalisation;
- X31 as XZR source and X31 destination discard semantics, not SP;
- D31, X0/result-pointer collision, X30/LR, all callee-saved field numbers, and
  same-number cross-bank non-aliasing;
- source-register/lane preservation;
- NZCV, FPCR, and FPSR preservation;
- externally measured D8-D15, FPCR, and FPSR restoration.

The callable fixture preserves LR, its result pointer, D8-D15, X19-X30, and
saved FPCR/FPSR through stack slots, so no tested X field doubles as hidden
fixture state.

Accepted result:

```text
METRIC emitter_fmov_dx_xd_exact_words=2048
METRIC emitter_fmov_dx_xd_native_routes=2048
METRIC emitter_fmov_dx_xd_same_number_routes=64
```

## Closure decision

The directly evidenced rows are promoted:

- `emitter_api,FMOV_dx` → **audited**;
- `emitter_api,FMOV_xd` → **audited**.

No raw boundary, MIDFUNC, memory path, compare helper, extended-format path, or
generator row is promoted. `generator,i_FPP` remains **unreviewed**.
