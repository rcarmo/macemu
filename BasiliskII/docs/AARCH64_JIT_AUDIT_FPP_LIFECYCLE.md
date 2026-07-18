# AArch64 JIT FPP generator lifecycle closure

Date: 2026-07-18
Branch: `jit-audit-next`

## Scope

This acceptance checkpoint closes the configured `USE_JIT_FPU` AArch64
`generator,i_FPP` lifecycle. It reconciles the already-published focused FPP
reports and maintained runtime matrices against the complete live dispatcher;
it does not reclassify unrelated generic emitter APIs or claim a `FULLMMU`
build.

The generator contract is one extension-word fetch followed by
`comp_fpp_opp(opcode, extra)`, with FPU ownership, `mayfail`, opcode byte-order
handling, and fail-closed behavior when `USE_JIT_FPU` is absent.

## Mechanical lifecycle census

`bun jit-test/fpp-lifecycle-census.ts` fails closed on the current source and
accepted evidence graph. It proves:

- all **8** top-level `((extra >> 13) & 7)` forms are present;
- all **61** implemented ordinary operation selector encodings are assigned
  exactly once to **22** semantic owners;
- **10** top-level FMOVE/FMOVEM/FMOVECR/control-transfer owners have maintained
  matrix and report pairs;
- duplicate selector ownership, missing source cases, missing matrices, missing
  reports, or loss of fail-closed matrix exits are fatal;
- selector values without an implementation continue to reach the dispatcher's
  `default: FAIL(1); return;` boundary rather than acquiring operands or
  emitting a partial operation.

Accepted census output:

```text
FPP_LIFECYCLE_CENSUS top_forms=8 operation_selectors=61 selector_owners=22 top_level_owners=10
FPP_LIFECYCLE_CENSUS integrated_pass=904 integrated_fail=0 regpressure_pass=31 strict_negative=1
```

## Runtime fidelity owners

The lifecycle is intentionally mixed native and exact MPFR service:

- ordinary integer/single/double FMOVE inputs and selected compare/test paths
  retain directly proved native execution;
- architectural extended-register copies, double/extended/packed destinations,
  explicit-precision moves, FMOVECR, static/dynamic FMOVEM, and control
  transfers use their accepted exact service boundaries where a binary64
  shadow cannot preserve architectural state;
- arithmetic, remainder/scale, square-root, transcendental, sign, and
  decomposition selector groups retain their published per-family matrices,
  including source/destination aliases, FPCR rounding/precision, FPSR
  condition/exception state, integer CCR preservation, EA ordering, and strict
  rejection where applicable.

This is composition evidence: it accepts `i_FPP` because every reachable
source branch now has a direct focused owner. It does not inherit that status
onto compound MIDFUNC/raw wrappers or generic encoders whose complete public
contracts remain separate.

## Integrated acceptance

The most recent clean FPP epoch passed the complete default campaign before and
after a clean configured AArch64 build:

```text
METRIC pass=904
METRIC fail=0
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC risky_total=904
METRIC score=100
REGPRESSURE_SUMMARY selected=31 pass=31 fail=0
METRIC strict_full_jit_negative_gate=1
```

Post-epoch FMOVE ownership and lower-chain retirement checkpoints preserve
maintained focused matrices and deterministic structural checks. This closure
checkpoint reruns the lifecycle census, structural audit, deterministic
inventory, and current integrated campaign before publication.

## Closure decision

Promote exactly:

- `generator,i_FPP`: **unreviewed -> audited**.

No MIDFUNC, raw-boundary, or generic emitter row is promoted by this report.
`generator,i_FScc` remains separate. BasiliskII `FULLMMU` implementation is out
of scope; NeXT MMU integration is owned independently by the Previous project.
