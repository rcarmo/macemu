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

## Structural and review decision

The structural audit pins guarded pre-acquisition service, ordinary direct and
forced result paths, exact witness records, special/range/NaN classes, native
entry, and 30+3 counts. Independent review rejected earlier symmetric witnesses;
they were replaced by the four one-sided cases above, and re-review approved.

This guest-service checkpoint promotes no closure row. `i_FPP` and `FMUL_sss`
remain unreviewed. A later direct generic-emitter audit independently closes
`FMUL_ddd` encoding/value/alias/state semantics without promoting this guest
family; see `AARCH64_JIT_AUDIT_FMUL_D_EMITTER.md`.
