# AArch64 JIT FPP multiply batch

## Scope

This bounded checkpoint covers `FMUL` (`0x23`) and forced-result
`FSMUL`/`FDMUL` (`0x63`/`0x67`). `FSGLMUL`, subtraction, remainder/scale,
control operations, and complete `i_FPP` closure remain separate.

## Repairs

AArch64 binary64-native lowering cannot preserve extended factors, forced
24-/53-bit result formats, architectural NaN metadata, or Motorola exception
status. The three selectors now service before native operand acquisition.

Ordinary FMUL now retains both extended operands and multiplies directly into a
separate FPCR-width MPFR result. FSMUL/FDMUL join the shared forced binary
publication boundary: target exponent range, overflow/underflow, common binary
NaN payload/sign ownership, and result condition codes are published once.

## Focused evidence

`bun jit-test/fpp-mul-service-matrix.ts` passes:

```text
FPP_MUL_MATRIX service_pass=30 strict_pass=3 fail=0 total=33
```

The matrix covers exact and low-bit extended products, FPCR/forced rounding,
signed zero and infinity, zero-times-infinity OPERR, forced range, NaN
quieting/destination precedence, FP7 replay, EA effects, accrued state, and
strict rejection.

Four one-sided operand-retention witnesses independently distinguish source and
destination pre-rounding. The exact target and counterfactual pre-rounded
results are:

```text
single destination: exact ccde6b; pre-destination ccde6c; pre-source ccde6b
single source:      exact dd28c1; pre-destination dd28c1; pre-source dd28c2
double destination: exact a604cf4925ec0000; pre-destination a604cf4925ebf800; pre-source exact
double source:      exact fa3736d18fc27800; pre-destination exact; pre-source fa3736d18fc27000
```

Each case enters natively at PC `0x1008`, then executes through semantic service;
FPSR is snapshotted before the result store clears current exception status.
The complete two-pass service profile is pinned as the initial destination load
at `f239@0x1000`, followed by two identical source/FMUL, FPSR-capture, and store
triples. Absolute-long source uses `f239@0x1008`, `f200@0x1010`, and
`f239@0x1014`; register, postincrement, and predecrement forms use their exact
`f200`/`f218`/`f220` source opcode at `0x1008`, then `f200@0x100c` and
`f239@0x1010`. This replaces a stale total-only exception for the
signalling-destination case; clean runtime records seven non-duplicative
boundaries with PCs derived from each source form's encoded length.

## Structural and review decision

The structural audit pins guarded pre-acquisition service, ordinary direct and
forced result paths, exact witness records, special/range/NaN classes, native
entry, and 30+3 counts. Independent review rejected earlier symmetric witnesses;
they were replaced by the four one-sided cases above, and re-review approved.

This guest-service checkpoint promotes no closure row. `i_FPP` remains
unreviewed. Later direct generic-emitter audits independently closed
`FMUL_ddd` and `FMUL_sss` encoding/value/alias/state semantics without
promoting this guest family; see `AARCH64_JIT_AUDIT_FMUL_D_EMITTER.md` and
`AARCH64_JIT_AUDIT_FMUL_S_EMITTER.md`.

A later configured-root reachability audit exhaustively retired the residual
binary64 native chain. Both configured AArch64 `fmul_rr` roots—the
FMUL/FSMUL/FDMUL selector block and separate FSGLMUL block—enter semantic
service before operand acquisition and before their retained calls; there is no
MIDFUNC caller. Therefore `fmul_rr`, `raw_fmul_rr`, and `FMUL_ddd` are
**unreachable**. Positive ordered control-flow for both roots, exact root/edge
counts, lower-chain shape, and future-caller checks are pinned in
`closure-inventory.ts` and `structural-audit.ts`.

This is retirement, not native acceptance. The earlier exhaustive direct
binary64 emitter probe remains historical evidence, while this 30+3 matrix and
the separate 22+1 FSGLMUL matrix own configured guest runtime fidelity.

A later complete FSGLMUL lower-chain audit proved that `fsglmul_rr` has no
configured caller and its retained `raw_fsglmul_rr` composition is
definition-only. Consequently the raw wrapper and sole-site `FMUL_sss` emitter
are also **unreachable**. The exhaustive direct binary32 emitter probe remains
historical evidence; shared conversion emitters stay reachable elsewhere.
