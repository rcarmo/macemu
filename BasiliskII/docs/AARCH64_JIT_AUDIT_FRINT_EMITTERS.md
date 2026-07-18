# AArch64 generic FRINT scalar-rounding emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `2dda64d7`

## Scope

This checkpoint audits the complete reachable scalar-binary64 rounding cluster:

- `FRINTA_dd(Dd,Dn)`: round to integral, nearest with ties away from zero;
- `FRINTI_dd(Dd,Dn)`: round to integral using the raw AArch64 FPCR mode;
- `FRINTZ_dd(Dd,Dn)`: round to integral toward zero.

These are the non-`X` forms: finite inexact rounding does not request IXC. The
checkpoint does not promote raw boundaries, MIDFUNC wrappers, compound
remainder/integer-conversion behavior, Motorola status publication, or
`generator,i_FPP`.

## Configured source sites

Configured AArch64 source has exactly one `FRINTA_dd`, two `FRINTI_dd`, and two
`FRINTZ_dd` sites. They occur in:

- integer-destination rounding/classification and ordinary current-mode round;
- fixed-zero round and modulus truncation;
- remainder nearest-away quotient construction.

The exact 1/2/2 counts and authoritative source spellings are structural. A new
source site does not inherit this audit silently.

## Direct generic evidence

`jit-test/emitter-frint-conformance.cpp` includes production
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts all fields for all three APIs:

- **3,072** exact words.

Native execution exhausts all API, field, and raw FPCR-mode combinations:

- **12,288** routes: three APIs × 32 destinations × 32 sources × four modes;
- **384** in-place aliases.

The direct oracle distinguishes each instruction rather than deriving one from
another. It covers positive/negative half ties at 0.5, 1.5, and 2.5, positive
and negative minimum subnormals, signed zero, infinity, a large integral value,
and quiet/signalling NaNs. It pins:

- nearest-away behavior for `FRINTA_dd` independent of FPCR;
- raw AArch64 FPCR order for `FRINTI_dd` (nearest-even, +∞, −∞, zero);
- toward-zero behavior for `FRINTZ_dd` independent of FPCR;
- sign-preserving zero results;
- qNaN payload preservation and sNaN quieting with IOC;
- no added IXC for finite fractional values in these non-`X` forms;
- source preservation for distinct fields and exact replacement for aliases;
- NZCV, FPCR, and seeded FPSR preservation;
- D31, D0/result-field overlap, D30/LR-number symmetry, callee-saved fields,
  and externally measured D8-D15/FPCR/FPSR restoration.

The callable fixture preserves LR, its result pointer, D8-D15, X19-X30, and
saved FPCR/FPSR through stack slots so no tested D field doubles as hidden
fixture state.

Accepted result:

```text
METRIC emitter_frint_exact_words=3072
METRIC emitter_frint_native_routes=12288
METRIC emitter_frint_alias_routes=384
```

## Closure decision

The directly evidenced rows are promoted:

- `emitter_api,FRINTA_dd` → **audited**;
- `emitter_api,FRINTI_dd` → **audited**;
- `emitter_api,FRINTZ_dd` → **audited**.

No raw boundary, MIDFUNC, compound arithmetic path, Motorola-status path, or
generator row is promoted. `generator,i_FPP` remains **unreviewed**.

A later configured-root audit retired the definition-only `raw_frndint_rr` and
`raw_frndintz_rr` wrappers beneath already-unreachable MIDFUNCs. That does not
retire these emitter rows: `FRINTI_dd` retains its integer-destination rounding
site, and `FRINTZ_dd` retains its modulus-truncation site. Both remain audited
and reachable with the exact 2/2 configured-site counts pinned here.
