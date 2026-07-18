# AArch64 generic FSUB scalar-binary64 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `918b2293`

## Scope

This checkpoint directly audited the then-reachable `FSUB_ddd(Dd,Dn,Dm)` API.
It closed generic scalar-binary64 encoding, rounding, exception, alias, and
state semantics only.

It does not promote `raw_fsub_rr`, a MIDFUNC wrapper, the already serviced guest
FSUB/FSSUB/FDSUB family, Motorola status publication, or `generator,i_FPP`.

## Configured source site

Configured AArch64 source has exactly one `FSUB_ddd` site, inside
`raw_fsub_rr`, with destination-as-left-source composition. The exact count,
raw-function boundary, and operand order are structural.

## Direct generic evidence

`jit-test/emitter-fsub-conformance.cpp` includes production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts all fields:

- **32,768** exact words: 32 destinations × 32 left sources × 32 right sources.

Native semantic coverage comprises:

- **576** routes under all four raw AArch64 FPCR modes;
- **256** routes with destination/source, equal-source, or all-field aliases;
- an additional sweep covering every D field number.

The oracle covers exact positive/negative results, positive/negative midpoint
rounding, positive/negative overflow, exact cancellation and signed-zero rules,
opposite-signed zero subtraction, finite/infinite combinations, invalid
infinity-minus-infinity, and left/right quiet and signalling NaNs. It pins:

- raw FPCR directed-rounding order;
- IXC and OFC on inexact/overflow cases;
- IOC and default quiet NaN for invalid infinity subtraction;
- NaN payload propagation and sNaN quieting;
- exact operand order;
- distinct-source preservation and architectural replacement for all alias
  topologies;
- NZCV, FPCR, and seeded FPSR preservation;
- D0-D31 plus externally measured D8-D15/FP-state restoration;
- RW→RX permission transition and instruction-cache publication.

Accepted result:

```text
METRIC emitter_fsub_exact_words=32768
METRIC emitter_fsub_native_routes=576
METRIC emitter_fsub_alias_routes=256
```

## Closure decision

At this checkpoint the directly evidenced row was promoted:

- `emitter_api,FSUB_ddd` → **audited**.

No raw boundary, MIDFUNC, guest instruction family, Motorola-status path, or
generator row was promoted. `generator,i_FPP` remained **unreviewed**.

A later complete configured-root audit established that every AArch64
FSUB/FSSUB/FDSUB selector enters exact semantic service before `fsub_rr`, while
configured AArch64 FCMP uses `fcompare_result_rr` and no other caller exists.
The current inventory therefore classifies `fsub_rr`, `raw_fsub_rr`, and
`FSUB_ddd` as **unreachable**. This report remains direct encoding/host-semantic
evidence for the retained dead emitter definition; it does not override
configured reachability.
