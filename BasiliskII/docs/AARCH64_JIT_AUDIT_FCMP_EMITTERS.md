# AArch64 generic FCMP emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `ff445dad`

## Scope

This checkpoint audits the complete reachable scalar-double compare emitter API
cluster:

- `FCMP_dd(Dn,Dm)`;
- `FCMP_d0(Dn)`.

It does not reclassify the FPP-local `fcompare_result_rr` wrapper, which is
intentionally outside the MIDFUNC/closure census, or `generator,i_FPP`.

## Reachable callers

Configured AArch64 source contains five `FCMP_dd` and three `FCMP_d0` call
sites:

1. two integer-conversion representability/OPERR comparisons;
2. two integer-conversion exactness/INEX comparisons;
3. the live FPP FCMP four-class result emitter;
4. the FPP FCMP signed-equality discriminator;
5. the extended-format store zero/special-case split; and
6. floating-result-to-integer-NZCV publication.

The caller count and each authoritative source spelling are pinned in the
structural gate. A new caller does not inherit this audit silently.

## Encoding and native contract

`jit-test/emitter-fcmp-conformance.cpp` compiles directly against
`codegen_arm64.h`, emits into a RW page, switches it to RX, clears the
instruction cache, and executes it on the AArch64 host.

Encoding evidence exhausts:

- every `Dn` × `Dm` field for `FCMP_dd`: **1,024 exact words**;
- every `Dn` field for `FCMP_d0`: **32 exact words**.

Native evidence covers **40 register-register + 32 register-zero vectors**:

- less, equal, greater, signed-zero equality, infinity, and subnormal classes;
- quiet and signalling NaN in either operand;
- D0/D1, D31/D30, callee-saved D8/D15, and self-alias routes;
- D0, D8, D15, and maximum D31 zero comparisons;
- exact NZCV classes: less `N`, equal `Z|C`, greater `C`, unordered `C|V`;
- no operand mutation;
- unchanged FPCR;
- preserved seeded FPSR condition state, with IOC added only for SNaN.

The callable fixture saves and restores AAPCS64 D8-D15 and the caller's
FPCR/FPSR. An external AArch64 assembly wrapper seeds all eight callee-saved
D-register low halves plus FPCR/FPSR, invokes the JIT function, snapshots and
checks post-return state, then restores the harness process's originals. This
proves the call boundary rather than merely inspecting pre-restore values. The
fixture uses W/X-safe result storage and transitions memory RW→RX rather than
retaining a writable executable page.

Accepted result:

```text
METRIC emitter_fcmp_exact_words=1056
METRIC emitter_fcmp_dd_native_vectors=40
METRIC emitter_fcmp_d0_native_vectors=32
METRIC emitter_fcmp_alias_vectors=10
METRIC emitter_fcmp_nan_classes=4
```

The already accepted guest-level FCMP matrix remains the composition proof:
**176/176** exact-native cases across eleven operand classes and all sixteen
68881 predicates, with full integer CCR and FPSR CCB preservation.

## Closure decision

The directly evidenced rows are promoted:

- `emitter_api,FCMP_dd` → **audited**;
- `emitter_api,FCMP_d0` → **audited**.

No adjacent conversion, arithmetic, raw, MIDFUNC, or generator row is promoted.
`generator,i_FPP` remains **unreviewed**.
