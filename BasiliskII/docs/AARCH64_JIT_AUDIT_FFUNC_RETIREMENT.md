# AArch64 JIT host-libm floating-chain retirement

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `6cfabf5b`

## Scope

This reachability checkpoint classifies the retained `ffunc_rr` MIDFUNC and its
sole lower caller `raw_ffunc_rr`. The ARM64 compatibility header still maps
FSIN, FETOX, FLOG2, and FCOS spellings to this binary64 host-libm chain, but the
configured `USE_JIT_FPU` compiler enters MPFR semantic service before operand
acquisition for all four selectors.

This is a two-row **unreachable** correction, not an audit of host `sin`, `exp`,
`log2`, or `cos`, and not a claim that binary64 libm implements Motorola
extended semantics.

## Positive control-flow proof

The four retained compatibility roots are:

```text
fsin_rr  -> ffunc_rr(sin,  ...)
fetox_rr -> ffunc_rr(exp,  ...)
flog2_rr -> ffunc_rr(log2, ...)
fcos_rr  -> ffunc_rr(cos,  ...)
```

For each matching ordinary FPP selector, configured AArch64 source contains an
unconditional `FAIL(1); return;` inside the architecture guard before
`get_fp_value()` and before the retained compatibility call. These are not
merely disabled by runtime preferences: the configured compiler cannot reach
the binary64 chain.

The retirement remains fail-closed:

- exactly four compatibility roots must exist;
- each named selector must retain its AArch64 service barrier before operand
  acquisition and the retained call;
- `ffunc_rr` must remain definition/end-marker only in the MIDFUNC source;
- `raw_ffunc_rr` must remain definition/end-marker only in codegen source;
- the retained bodies and their call-boundary shape must remain recognisable;
- any future configured caller makes inventory regeneration fail instead of
  silently preserving the unreachable classification.

## Runtime-fidelity reason for service ownership

The prior accepted FPP service batches establish why native reachability would
be wrong. The old chain acquired a binary64 shadow and invoked host libm, losing
Motorola extended source bits and range, FPCR target precision/rounding, and
exact FPSR status. The configured MPFR services evaluate from the extended
source directly into the requested target format and publish Motorola exception
state.

The existing accepted matrices cover 49 service + 4 strict cases for the
FSIN/FETOX/FTWOTOX/FLOG2 batch and 36 service + 3 strict cases for the
FCOSH/FACOS/FCOS batch. This checkpoint reruns a bounded attribution subset:

- FSIN, FETOX, FLOG2, and FCOS: one exact extended-source/double result each;
- the matching strict FP7 case for each selector;
- exact semantic-service fallback at PC `0x1000` for result cases;
- strict rejection before `NATEXEC` for strict cases;
- exact output/FPSR/CCR and isolated CoW cleanup inherited from those
  fail-closed matrices.

Focused result:

```text
FFUNC_RETIREMENT_FOCUSED service=4 strict=4 fail=0 total=8
```

## Closure decision

The following rows change from **unreviewed** to **unreachable**:

- `midfunc,ffunc_rr`;
- `raw_boundary,raw_ffunc_rr`.

No emitter API is promoted or retired: the raw boundary uses generic FMOV/call
primitives that have other independent reachability and classifications. No
production or generated source changes in this checkpoint. Whole-engine closure
is not claimed.

## Acceptance

- focused attribution subset: **4 exact MPFR service + 4 strict rejection**;
- structural audit: pass, including four ordered service barriers, four retained
  compatibility spellings, and exactly two definition-only retired rows;
- deterministic inventory: **998 rows**, exactly `ffunc_rr` and
  `raw_ffunc_rr` unreviewed -> unreachable; MIDFUNC totals become 279 audited /
  120 unreachable / 23 unreviewed, raw totals become 30 audited / 19
  unreachable / 34 unreviewed, and total unreviewed becomes **184**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `ab2240b76d9acc95bf14b62f6b390aa49b246a1589e7598c6fa4d4dcbf4c1d14`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `5a0fb08f333e434cb4df6aa7d2e891fc9c15363c0baeba544fb6a729c02a2522`;
- independent bounded reachability review: **APPROVE** for all four dominating
  barriers, exact configured roots, absent hidden MIDFUNC/raw callers, and
  exact two-row inventory scope;
- executable source is unchanged from canonical `6cfabf5b`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Bun transpilation, shell syntax, source hygiene, `git diff --check`, and scoped
CoW/HOME cleanup also pass. Acceptance logs are removed after publication.
