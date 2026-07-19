# AArch64 JIT FMOVECR zero/one wrapper retirement

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `25ef08e8`

## Scope

This reachability checkpoint classifies the retained zero/one floating-constant
wrappers:

- `fmov_d_ri_0` and `raw_fmov_d_ri_0`;
- `fmov_d_ri_1` and `raw_fmov_d_ri_1`.

The apparent architectural roots are FMOVECR selector 15 (zero) and selector 50
(`10^0`, one). In the configured AArch64 build, the entire FMOVECR selector
switch is dominated by the exact-MPFR service gate. The only other MIDFUNC
parent, `fmov_l_ri`, is already unreachable.

This is a four-row **unreachable** correction, not native acceptance of the
wrappers and not a promotion or retirement of their generic emitter primitives.

## Positive control-flow and caller proof

The configured FPP compiler enters `FAIL(1); return;` before
`switch (extra & 0x7f)`. Retained post-barrier source still contains:

```text
case 0x0f: fmov_0(reg) -> fmov_d_ri_0
case 0x32: fmov_1(reg) -> fmov_d_ri_1
```

The ARM64 MIDFUNC source has one additional parent spelling for each under
`fmov_l_ri` cases 0 and 1, but that parent has no configured root. Therefore:

- each constant MIDFUNC has only its definition markers plus the unreachable
  parent reference;
- each raw boundary has only `LOWFUNC`/`LENDFUNC` markers after its MIDFUNC is
  removed from the reachable graph;
- any future caller, selector-gate move, or token-cardinality drift fails the
  closure or structural check.

`raw_fmov_d_ri_0` uses `MOVI_di(r, 0)` and `raw_fmov_d_ri_1` uses the audited
`FMOV_di(r, 0b01110000)`. This checkpoint does not classify `MOVI_di` and does
not alter audited `FMOV_di`; both have other independent source sites or require
separate generic API review.

## Runtime evidence

The accepted full FMOVECR matrix already covers all 22 defined selectors,
representative undefined selectors, exact 80-bit values, FPCR precision and
rounding, FPSR, destination fields, **36 service cases**, and **3 strict
rejections**.

`bash jit-test/fmov-zero-one-retirement-matrix.sh` reruns the bounded attribution
subset:

- selector 15: exact extended positive zero and zero FPSR classification;
- selector 50: exact extended one;
- FP7 strict FMOVECR rejection before native execution;
- exact semantic-service fallback at PC `0x1000`, unchanged A0/SR, guarded
  output, and isolated CoW/HOME cleanup through the underlying matrix.

Focused result:

```text
FMOV_ZERO_ONE_RETIREMENT_FOCUSED service=2 strict=1 fail=0 total=3
```

## Closure decision

The following rows change from **unreviewed** to **unreachable**:

- `midfunc,fmov_d_ri_0`;
- `midfunc,fmov_d_ri_1`;
- `raw_boundary,raw_fmov_d_ri_0`;
- `raw_boundary,raw_fmov_d_ri_1`.

No production or generated source changes. No emitter API row changes.
Whole-engine closure is not claimed.

## Acceptance

- focused attribution subset: **2 exact MPFR service + 1 strict rejection**;
- structural audit: pass, including the common pre-selector service gate,
  selectors 15/50, the sole unreachable parent, two MIDFUNCs, two
  definition-only raw boundaries, and the focused wrapper contract;
- deterministic inventory: **998 rows**, exactly the four named rows
  unreviewed -> unreachable; MIDFUNC totals become 279 audited / 122
  unreachable / 21 unreviewed, raw totals become 30 audited / 21 unreachable /
  32 unreviewed, and total unreviewed becomes **180**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `c8e8e879ff6f8e16f1d0669cffbd1216d04398656df07c6f6d5320039c77d242`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `9898efd65fe3cb184ce2ca1a7992c529ae375ed5693797330855fba6a9ee0e84`;
- independent bounded review: **APPROVE** for configured dominance, exact roots,
  unreachable `fmov_l_ri`, absent hidden callers, exact four-row scope, and
  separate generic primitive classifications;
- executable source is unchanged from canonical `25ef08e8`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

`FMOV_di` remains audited and reachable; `MOVI_di` remains unreviewed and
reachable. Bun transpilation, shell syntax, source hygiene, `git diff --check`,
and scoped CoW/HOME cleanup also pass. Acceptance logs are removed after
publication.
