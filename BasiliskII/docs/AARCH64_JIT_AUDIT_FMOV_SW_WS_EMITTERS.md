# AArch64 generic FMOV W/S bit-transfer emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `3128f6f9`

## Scope

This checkpoint audits the complete reachable reciprocal scalar bit-transfer
pair:

- `FMOV_sw(Sd,Wn)`: copy a W register's 32 bits into an S lane;
- `FMOV_ws(Wd,Sn)`: copy an S lane's 32 bits into a W register.

These are bit transfers, not floating-point conversions. The checkpoint does
not promote `raw_fmov_s_rr`, `raw_fmov_to_s_rr`, their MIDFUNC wrappers, memory
paths, conversion emitters, or `generator,i_FPP`.

## Reachability

Configured AArch64 source has exactly one site for each API:

- `raw_fmov_s_rr`: `FMOV_sw` precedes `FCVT_ds` when importing binary32 bits;
- `raw_fmov_to_s_rr`: `FCVT_sd` precedes `FMOV_ws` when publishing binary32
  bits to a W register.

The exact 1/1 counts, raw-function boundaries, and ordering are structural. A
new source site or reordered conversion does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-fmov-sw-ws-conformance.cpp` includes the production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes the words on the AArch64 host.

Encoding coverage exhausts all fields:

- **1,024** `FMOV_sw` words;
- **1,024** `FMOV_ws` words.

Native execution exhausts both 32×32 field matrices:

- **1,024** `FMOV_sw` routes;
- **1,024** `FMOV_ws` routes;
- **64** same-number cross-bank routes.

The pattern corpus covers signed zero, infinities, quiet/signalling NaN bit
patterns, low payload bits, and deliberately nonzero upper input halves. The
oracle pins:

- exact low-word transfer without arithmetic conversion;
- architectural zeroing of the S lane's upper 32 bits after `FMOV_sw`;
- architectural zero extension of W writes after `FMOV_ws`;
- W31 as WZR source and destination discard semantics;
- S31, W0/result-pointer collision, W30/LR, and all callee-saved field numbers;
- source-lane preservation and same-number cross-bank non-aliasing;
- NZCV, FPCR, and FPSR preservation;
- externally measured D8-D15, FPCR, and FPSR restoration.

The callable fixture preserves LR, its result pointer, D8-D15, X19-X30, and
saved FPCR/FPSR through stack slots so no tested W field doubles as hidden
fixture state.

Accepted result:

```text
METRIC emitter_fmov_sw_ws_exact_words=2048
METRIC emitter_fmov_sw_ws_native_routes=2048
METRIC emitter_fmov_sw_ws_same_number_routes=64
```

## Closure decision

The directly evidenced rows are promoted:

- `emitter_api,FMOV_sw` → **audited**;
- `emitter_api,FMOV_ws` → **audited**.

No raw boundary, MIDFUNC, memory path, conversion family, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
