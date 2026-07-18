# AArch64 generic FMOV binary64-immediate emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `fd35e621`

## Scope

This checkpoint audits the complete reachable `FMOV_di(Dd,imm8)` API. It emits
AArch64 scalar-binary64 immediate expansion. The architectural imm8 domain is
finite and exhaustible.

The checkpoint does not promote constant wrappers, raw boundaries, MIDFUNCs,
compound arithmetic users, or `generator,i_FPP`.

## Configured source sites

Configured AArch64 source has exactly five `FMOV_di` sites. They produce the
encodable constants 1, 10, and 2 for constant wrappers, compare-result
construction, and logarithm composition.

The exact five-site count and authoritative immediate spellings are structural.
A new source site does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-fmov-di-conformance.cpp` includes production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts the architectural domain:

- **8,192** exact words: 32 D destinations × 256 imm8 values.

Native execution exhausts all values, destinations, and raw FPCR modes:

- **32,768** routes: 32 destinations × 256 imm8 values × four modes.

The expected bits come from an independent implementation of AArch64
`VFPExpandImm`: sign, complemented/repeated exponent prefix, exponent tail, and
four-bit fraction expansion are assembled without invoking the production
macro or host floating arithmetic. This covers every positive/negative finite
encodable value, not a sample.

The direct contract pins:

- exact binary64 bits for all 256 immediate values;
- exact D field placement including D0, D31, and D8-D15;
- FPCR-mode independence;
- NZCV, FPCR, and seeded FPSR preservation;
- externally measured D8-D15, FPCR, and FPSR restoration;
- RW→RX permission transition and instruction-cache publication.

The callable fixture preserves LR, its result pointer, and D8-D15 while
restoring the caller's FPCR/FPSR.

Accepted result:

```text
METRIC emitter_fmov_di_exact_words=8192
METRIC emitter_fmov_di_native_routes=32768
METRIC emitter_fmov_di_immediates=256
```

## Closure decision

The directly evidenced row is promoted:

- `emitter_api,FMOV_di` → **audited**.

No wrapper, raw boundary, MIDFUNC, arithmetic path, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
