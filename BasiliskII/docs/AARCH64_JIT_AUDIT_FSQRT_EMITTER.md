# AArch64 generic FSQRT scalar-binary64 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `41cfba11`

## Scope

This checkpoint directly audited the then-reachable `FSQRT_dd(Dd,Dn)` API. It
closed the generic scalar-binary64 encoding, rounding, exception, alias, and
state contract only.

It does not promote `raw_fsqrt_rr`, a MIDFUNC wrapper, guest FPP operation
semantics, Motorola status publication, or `generator,i_FPP`.

## Configured source site

Configured AArch64 source has exactly one `FSQRT_dd` site, inside
`raw_fsqrt_rr`. The exact count and raw-function boundary are structural. A new
source site does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-fsqrt-conformance.cpp` includes production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Coverage is exhaustive across fields and raw AArch64 FPCR modes:

- **1,024** exact words;
- **4,096** native routes: 32 destinations × 32 sources × four modes;
- **128** in-place aliases.

The direct oracle covers positive/negative zero, exact roots 1 and 4,
irrational √2 with directed rounding, the exact root of minimum binary64
subnormal, positive infinity, negative finite/infinity invalid inputs, quiet
NaN, and signalling NaN. It pins:

- raw AArch64 FPCR mode order and exact directed √2 results;
- signed-zero retention;
- exact subnormal-root handling;
- IXC for irrational finite results;
- default quiet NaN plus IOC for negative nonzero inputs;
- qNaN payload preservation and sNaN quieting with IOC;
- source preservation for distinct fields and exact replacement for aliases;
- NZCV, FPCR, and seeded FPSR preservation;
- D0-D31, including D8-D15 and externally measured caller FP-state
  restoration;
- RW→RX permission transition and instruction-cache publication.

Accepted result:

```text
METRIC emitter_fsqrt_exact_words=1024
METRIC emitter_fsqrt_native_routes=4096
METRIC emitter_fsqrt_alias_routes=128
```

## Closure decision

At this checkpoint the directly evidenced row was promoted:

- `emitter_api,FSQRT_dd` → **audited**.

No raw boundary, MIDFUNC, guest instruction family, Motorola-status path, or
generator row was promoted. `generator,i_FPP` remained **unreviewed**.

A later complete configured-root audit established that every AArch64
FSQRT/FSSQRT/FDSQRT selector enters exact semantic service before `fsqrt_rr`,
and that no other configured caller exists. The current inventory therefore
classifies `fsqrt_rr`, `raw_fsqrt_rr`, and `FSQRT_dd` as **unreachable**. This
report remains the direct encoding/host-semantic evidence for the retained dead
emitter definition; it does not override configured reachability.
