# AArch64 generic FMSUB fused binary64 emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `43233f32`

## Scope

This checkpoint audits the complete reachable `FMSUB_dddd(Dd,Dn,Dm,Da)` API,
whose scalar-binary64 result is fused `Da − Dn×Dm` with one final rounding.
It closes encoding, fused arithmetic, exception, four-field alias, and state
semantics only.

Remainder raw/MIDFUNC/guest behavior, Motorola quotient/status publication, and
`generator,i_FPP` remain separate.

## Configured sites

Configured source has exactly two sites in truncating and nearest remainder
helpers. Both use the original destination as accumulator while supplying a
rounded quotient and source divisor. Counts, operand order, and source spellings
are structural.

## Direct evidence

`jit-test/emitter-fmsub-conformance.cpp` executes production words from RW→RX
memory and provides:

- **1,048,576** exact words across every Dd/Dn/Dm/Da combination;
- **400** native semantic routes under all four FPCR modes;
- **208** destination and source-source alias routes.

The key fused discriminator computes
`1 − (1+2^-52)(1−2^-52) = 2^-104` exactly. A separate multiply then subtract
would produce zero. The oracle also covers directed midpoint rounding, signed
overflow and half-minimum-subnormal underflow, zero×infinity and infinity
cancellation invalid cases, and quiet/signalling NaNs in each of Dn, Dm, and
Da. Native execution pins the operand-position NaN sign contract: Dn NaNs
inherit the negated-product sign, while Dm and Da NaNs retain their sign.

Four distinct-value source-source alias witnesses prove preload order for
Dn==Dm, Dn==Da, Dm==Da, and all-equal fields. Additional routes cover each
destination alias and D31/high fields. The contract pins IXC/UFC/OFC/IOC,
payload quieting, source images, NZCV/FPCR/FPSR, external D8-D15/FP-state
restoration, and instruction-cache publication.

Accepted result:

```text
METRIC emitter_fmsub_exact_words=1048576
METRIC emitter_fmsub_native_routes=400
METRIC emitter_fmsub_alias_routes=208
```

## Closure decision

Promoted row:

- `emitter_api,FMSUB_dddd` → **audited**.

No raw, MIDFUNC, remainder guest family, Motorola-status, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
