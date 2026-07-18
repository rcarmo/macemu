# AArch64 generic SCVTF signed-int32 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `b5a84c1e`

## Scope

This checkpoint audits the complete reachable generic
`SCVTF_dw(Dd,Wn)` API: signed 32-bit integer to scalar binary64 conversion.
Every int32 value is exactly representable in binary64, so this instruction has
no rounding ambiguity or conversion exception for the accepted input domain.

The checkpoint does not promote raw boundaries, MIDFUNC wrappers, source-width
preparation, pair splitting, memory paths, Motorola status publication, or
`generator,i_FPP`.

## Configured source sites

Configured AArch64 source has exactly six `SCVTF_dw` sites. They serve:

- direct signed-long import;
- signed-word and signed-byte imports after explicit sign extension;
- two `fmov_to_int_emit()` int32-candidate re-conversion/compare sites used by
  integer-result classification and representability/OPERR publication;
- the exact floating constant 100 path.

The exact count and authoritative source spellings are structural. A new source
site does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-scvtf-conformance.cpp` includes the production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts all fields:

- **1,024** exact `Dd×Wn` words.

Native execution exhausts all fields under all raw AArch64 FPCR rounding modes:

- **4,096** routes: 32 destinations × 32 sources × four modes;
- **128** same-number cross-bank routes.

The independent C++ integer-derived IEEE-754 oracle covers zero, ±1, signed
int32 extrema, values around large powers of two, and deliberately poisoned X
upper halves. The direct contract pins:

- exact sign extension and binary64 representation for every selected int32;
- W31 as WZR source;
- ignored and preserved X-source upper halves;
- D31, W0/result-pointer collision, W30/LR, all callee-saved field numbers, and
  same-number cross-bank behavior;
- FPCR-mode independence and exact preservation;
- no new FPSR exception or cumulative-bit mutation;
- NZCV and source preservation;
- externally measured D8-D15, FPCR, and FPSR restoration.

The callable fixture preserves LR, its result pointer, D8-D15, X19-X30, and
saved FPCR/FPSR through stack slots so no tested W field doubles as hidden
fixture state.

Accepted result:

```text
METRIC emitter_scvtf_exact_words=1024
METRIC emitter_scvtf_native_routes=4096
METRIC emitter_scvtf_same_number_routes=128
```

## Closure decision

The directly evidenced row is promoted:

- `emitter_api,SCVTF_dw` → **audited**.

No raw boundary, MIDFUNC, memory path, Motorola-status path, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
