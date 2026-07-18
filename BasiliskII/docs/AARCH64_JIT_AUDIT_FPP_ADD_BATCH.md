# AArch64 JIT FPP add batch

## Scope

This bounded `i_FPP` batch covers ordinary `FADD` (`0x22`) and forced-result
`FSADD`/`FDADD` (`0x62`/`0x66`). Its later configured-root closure addendum also
retires their residual AArch64 `fadd_rr` → `raw_fadd_rr` → `FADD_ddd` chain. It
does not classify multiply/subtract families, FREM/FSCALE, control operations,
or the complete `i_FPP` lifecycle.

## Authoritative semantics

The fixed matrix follows the *MC68881/MC68882 User's Manual* and exact binary
power-of-two or MPFR 4.2.2 calculations:

- both operands retain architectural extended significand and exponent range;
- ordinary FADD rounds the completed sum at FPCR precision and direction;
- FSADD/FDADD force 24-/53-bit result precision and matching exponent range,
  but do not pre-round either operand;
- exact cancellation produces signed zero according to rounding direction and
  does not report underflow or inexact;
- opposite-signed infinities produce NaN plus OPERR, while equal-signed
  infinities retain that infinity;
- an untrapped SNaN is quieted and reports SNAN, then common destination
  precedence applies if both operands are NaNs; and
- finite target-format overflow/underflow publishes the Motorola exception and
  accrued status.

## Defects found and repaired

The AArch64 compiler acquired addends through binary64 native shadows, which
cannot preserve extended low bits/exponent range, forced result semantics, NaN
metadata, or exact Motorola status. All three selectors now exit to MPFR service
before operand acquisition on AArch64.

Ordinary FADD previously loaded its source at FPCR single/double precision and
added in place. It now joins the extended-source/direct-result contract: both
operands remain extended, while `mpfr_add` writes directly into a separate
FPCR-width result to avoid source narrowing and double rounding.

FSADD/FDADD already loaded the source at extended precision and wrote a
forced-width result, but shared divide-only publication. The shared forced
binary result boundary now also covers addition:

- target exponent range is checked;
- finite overflow and inexact underflow are published;
- exact cancellation (`t == 0`) is not misclassified as underflow;
- common source/destination NaN payload/sign selection is applied; and
- the selected NaN sign is applied to both MPFR state and metadata.

## Focused runtime evidence

`bun jit-test/fpp-add-service-matrix.ts` passes:

```text
FPP_ADD_MATRIX service_pass=35 strict_pass=3 fail=0 total=38
```

The fixed matrix covers:

- exact extended addition and an ordinary low-bit discriminator;
- FPCR single/double result precision and directed rounding;
- forced single/double nearest and directed rounding;
- forced source values just above the 24-/53-bit half-ULP thresholds, which
  round upward only if the extended-only source bit survives operand loading;
- ordinary and forced exact cancellation, including round-minus negative zero
  and explicit absence of UNFL/INEX;
- signed-zero combinations;
- forced finite overflow and underflow;
- opposite/same-sign infinity rules;
- qNaN/SNaN payload, sign, quieting, and destination precedence;
- FP7 self-alias and non-idempotent destination reseeding;
- postincrement/predecrement EA effects;
- accrued FPSR and integer CCR preservation; and
- exact strict rejection of FADD, FSADD, and FDADD.

Every service case enters a compiled block natively at PC `0x1008` and executes
the add selector through configured MPFR service. FPSR is snapshotted into D0
before the following extended store clears operation-local exception status.
The destination-SNaN witness additionally pins its exact seven-boundary profile:
initial destination/source imports and add/store, followed by replay
source/add/store. This corrects an older stale six-marker count without changing
its already-correct bytes, FPSR, D0, A0, or CCR oracle.

## Structural contracts

The structural audit requires the three-selector AArch64 exit before operand
acquisition; ordinary direct-result membership; forced binary publication;
cancellation-aware range classification; binary NaN ownership; native-entry
and strict-rejection proof; and all 35+3 cases. High-risk witnesses are pinned
as complete selector/source/destination/output/FPSR records, not merely names.

Independent review first required forced extended-only-bit and forced exact
cancellation witnesses, then required exact structural bindings for those
vectors plus range and NaN cases. All were added; final re-review approved the
bounded tranche.

## Closure decision

No row is promoted to **audited**. `generator,i_FPP` remains **unreviewed**
pending all selector groups.

A later configured-root reachability audit corrected the original conservative
classification of the retained native addition chain. Every configured AArch64
FADD/FSADD/FDADD selector enters semantic service before operand acquisition and
before `fadd_rr`; there is no other configured root or MIDFUNC caller. Therefore
`fadd_rr`, `raw_fadd_rr`, and `FADD_ddd` are **unreachable**. Positive ordered
control-flow, exact root/graph-edge counts, lower-chain shape, and future-caller
checks are pinned in `closure-inventory.ts` and `structural-audit.ts`. This is
retirement, not native acceptance: the retained post-return code is not
executed, while the 35+3 semantic-service matrix remains its runtime-fidelity
proof.
