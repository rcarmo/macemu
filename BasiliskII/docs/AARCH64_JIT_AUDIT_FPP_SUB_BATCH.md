# AArch64 JIT FPP subtract batch

## Scope

This bounded checkpoint covers ordinary `FSUB` (`0x28`) and forced-result
`FSSUB`/`FDSUB` (`0x68`/`0x6c`). It does not classify the complete `i_FPP`
lifecycle or any generic subtract emitter.

## Repairs

The AArch64 compiler previously acquired subtraction operands through binary64
native shadows. That cannot retain architectural extended low bits, forced
24-/53-bit result semantics, NaN metadata, or exact Motorola status. All three
selectors now enter configured MPFR service before operand acquisition.

Ordinary FSUB now retains both extended operands and computes destination minus
source directly into a separate FPCR-width result. FSSUB/FDSUB join the shared
forced binary publication boundary: the completed subtraction is rounded once
to the forced format, target exponent range and Motorola exception state are
published, exact cancellation is not misclassified as underflow, and common
binary NaN payload/sign ownership is applied.

## Focused runtime evidence

`bun jit-test/fpp-sub-service-matrix.ts` passes:

```text
FPP_SUB_MATRIX service_pass=40 strict_pass=3 fail=0 total=43
```

The matrix covers exact extended subtraction, ordinary FPCR precision and
rounding, forced single/double precision and rounding, signed exact
cancellation, signed zeros, forced finite overflow/underflow, infinity rules,
qNaN/SNaN quieting and destination precedence, FP7 alias/reseed, source EA
side effects, accrued FPSR, integer CCR preservation, and exact strict
rejection of all three selectors.

Six asymmetric operand-retention witnesses distinguish source and destination
pre-rounding. The forced-result exact and counterfactual target significands
are:

```text
single destination: exact a0a658; pre-destination a0a659; pre-source exact
single source:      exact 8aae9b; pre-destination exact; pre-source 8aae9a
double destination: exact f3e7a96e58bd2000; pre-destination f3e7a96e58bd1800; pre-source exact
double source:      exact a0139b5a747ab000; pre-destination exact; pre-source a0139b5a747aa800
```

The source-only single and destination-only double records are also executed
through ordinary FSUB at FPCR single/double precision. Every service case enters
a compiled block natively at PC `0x1008`, then requires the exact audited
fallback opcode for its addressing form (`f239`, `f218`, `f220`, or `f200`).

## Structural and review decision

The structural audit pins guarded pre-acquisition service, destination-minus-
source MPFR order, ordinary direct-result and forced publication membership,
cancellation-aware range handling, binary NaN ownership, the six complete
operand-retention records, special/range/alias/EA classes, native entry,
opcode-specific fallback attribution, strict rejection, and 40+3 accounting.

Independent review rejected the first symmetric extended-bit witnesses and the
initially narrow forced-special coverage. The matrix was replaced with the six
one-sided records and forced infinity/NaN cases above; re-review approved the
bounded checkpoint.

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending all
selector groups.
