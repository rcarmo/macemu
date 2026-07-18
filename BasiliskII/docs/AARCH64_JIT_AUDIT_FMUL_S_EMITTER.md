# AArch64 generic FMUL scalar-binary32 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `ba8604ef`

## Scope

This checkpoint audits the complete reachable `FMUL_sss(Sd,Sn,Sm)` API. It
closes generic scalar-binary32 encoding, rounding, exception, lane, alias, and
state semantics only.

It does not promote `raw_fsglmul_rr`, a MIDFUNC wrapper, the serviced guest
FSGLMUL or FMUL/FSMUL/FDMUL families, conversion wrappers, Motorola status, or
`generator,i_FPP`.

## Configured source site

Configured AArch64 source has exactly one `FMUL_sss` site inside
`raw_fsglmul_rr`, between binary64→binary32 operand narrowing and binary32→
binary64 result widening. That complete order is structural.

## Direct generic evidence

`jit-test/emitter-fmul-s-conformance.cpp` executes the production encoder from
RW→RX memory on the AArch64 host. Evidence comprises:

- **32,768** exact words across every Sd/Sn/Sm field;
- **608** native semantic routes under all four FPCR modes;
- **276** aliases plus a sweep covering every S field number.

The independent binary32 oracle covers exact signed products, an exact
24-bit-significand halfway product, signed overflow, signed half-minimum-
subnormal underflow, exact minimum-subnormal multiplication, signed zero,
infinity×finite, both zero×infinity invalid orders, and left/right quiet and
signalling NaNs. Full D→X snapshots prove exact 32-bit lane values and cleared
upper halves. A distinct-value `Sn==Sm` witness loads 2.0 then 3.0 into the
same S field and requires 9.0, proving second-load ownership.

The direct contract pins FPCR-directed rounding; IXC/UFC/OFC/IOC; default quiet
NaN and payload propagation; source and alias semantics; NZCV/FPCR/FPSR
preservation; all S fields; externally measured D8-D15/FP-state restoration;
and instruction-cache publication.

Accepted result:

```text
METRIC emitter_fmul_s_exact_words=32768
METRIC emitter_fmul_s_native_routes=608
METRIC emitter_fmul_s_alias_routes=276
```

## Closure decision

The directly evidenced row is promoted:

- `emitter_api,FMUL_sss` → **audited**.

No raw boundary, MIDFUNC, conversion wrapper, guest family, Motorola-status
path, or generator row is promoted. `generator,i_FPP` remains **unreviewed**.
