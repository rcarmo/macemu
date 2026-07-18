# AArch64 generic FDIV binary64/binary32 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `d21ffe10`

## Scope

This checkpoint audits the complete reachable scalar division pair:

- `FDIV_ddd(Dd,Dn,Dm)` for binary64;
- `FDIV_sss(Sd,Sn,Sm)` for binary32.

It closes generic encoding, rounding, exception, lane, alias, and state
semantics only. Guest FDIV/FSDIV/FDDIV/FSGLDIV service, raw/MIDFUNC wrappers,
conversion composition, Motorola status, and `generator,i_FPP` remain separate.

## Configured sites

Configured source contains three `FDIV_ddd` and one `FDIV_sss` sites. They
cover ordinary division, truncating/nearest remainder quotient construction,
and forced-single `FCVT_sd → FDIV_sss → FCVT_ds` composition. Exact 3/1 counts
and source spellings are structural.

## Direct evidence

Separate binary64 and binary32 probes avoid shared expected constants. Each
executes production words from RW→RX memory and provides:

- **32,768** exact encodings;
- **636** native semantic routes under all four FPCR modes;
- **292** alias routes plus every register field.

Combined evidence is **65,536 exact words + 1,272 native routes**.

Both oracles cover exact signed quotients, ±1/3 directed rounding, signed
overflow, signed half-minimum-subnormal underflow, finite/±zero with DZC and
signed infinity, zero/zero IOC, zero/negative and finite/infinity signed zero,
infinity/infinity IOC, and left/right quiet/signalling NaNs. Full D→X snapshots
prove binary32 lane clearing. Distinct-value Dn==Dm/Sn==Sm witnesses prove the
second load owns both aliased source fields.

The contract pins IXC/UFC/OFC/DZC/IOC, payload quieting, operand order, source
and alias semantics, NZCV/FPCR/FPSR preservation, all fields, external
D8-D15/FP-state restoration, and instruction-cache publication.

Accepted results:

```text
METRIC emitter_fdiv_exact_words=32768
METRIC emitter_fdiv_native_routes=636
METRIC emitter_fdiv_alias_routes=292
METRIC emitter_fdiv_s_exact_words=32768
METRIC emitter_fdiv_s_native_routes=636
METRIC emitter_fdiv_s_alias_routes=292
```

## Closure decision

Promoted rows:

- `emitter_api,FDIV_ddd` → **audited**;
- `emitter_api,FDIV_sss` → **audited**.

No raw, MIDFUNC, conversion, guest family, Motorola-status, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
