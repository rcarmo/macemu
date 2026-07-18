# AArch64 generic FMUL scalar-binary64 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `1cd8a79a`

## Scope

This checkpoint audits the complete reachable `FMUL_ddd(Dd,Dn,Dm)` API. It
closes generic scalar-binary64 encoding, rounding, exception, alias, and state
semantics only.

It does not promote `raw_fmul_rr`, a MIDFUNC wrapper, the serviced guest
FMUL/FSMUL/FDMUL family, Motorola status publication, or `generator,i_FPP`.

## Configured source site

Configured AArch64 source has exactly one `FMUL_ddd` site, inside
`raw_fmul_rr`, with destination-as-left-source composition. The exact count,
raw-function boundary, and operand order are structural.

## Direct generic evidence

`jit-test/emitter-fmul-conformance.cpp` includes production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Evidence comprises:

- **32,768** exact words across every Dd/Dn/Dm field;
- **604** native semantic routes under all four FPCR modes;
- **272** destination/source, equal-source, or all-field aliases;
- a separate sweep covering every D field number.

The oracle covers exact signed products, the exact halfway product
`(1+2^-52)^2`, positive/negative overflow, positive/negative half-minimum
subnormal underflow, exact minimum-subnormal multiplication, signed zero,
infinity×finite, both zero×infinity invalid operand orders, and left/right
quiet and signalling NaNs. It pins:

- raw FPCR directed rounding;
- IXC, UFC, OFC, and IOC publication;
- default quiet NaN for zero×infinity;
- NaN payload propagation and signalling quieting on either operand;
- exact operand order and all alias topologies;
- source, NZCV, FPCR, and seeded FPSR preservation;
- D0-D31 and externally measured D8-D15/FP-state restoration;
- RW→RX permission transition and instruction-cache publication.

Accepted result:

```text
METRIC emitter_fmul_exact_words=32768
METRIC emitter_fmul_native_routes=604
METRIC emitter_fmul_alias_routes=272
```

## Closure decision

The directly evidenced row is promoted:

- `emitter_api,FMUL_ddd` → **audited**.

No raw boundary, MIDFUNC, guest family, Motorola-status path, or generator row
is promoted. `generator,i_FPP` remains **unreviewed**.
