# AArch64 JIT unused double-load synonym retirement

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `9d17274a`

## Scope

This checkpoint classifies only `midfunc,fmov_d_rm`. The MIDFUNC is a retained
synonym for loading a host-memory binary64 value into a floating virtual
register, but it has no configured caller. Its sole external spelling is a
legacy `extern` declaration in `compemu_fpp.cpp`.

The live ordinary double-memory FMOVE path is deliberately **not** retired:

```text
get_fp_value(size=5) -> fmov_rm(FS1, temp_fp) -> raw_fmov_d_rm
```

Therefore `midfunc,fmov_rm` and `raw_boundary,raw_fmov_d_rm` remain reachable
and unreviewed pending their own complete ownership/load-boundary audit.

## Positive reachability proof

The configured-root census and structural audit require:

- `fmov_d_rm` occurs only as its `MIDFUNC`/`MENDFUNC` markers in ARM64 MIDFUNC
  source;
- its only FPP-source spelling is the exact legacy extern declaration;
- no generated, support, compatibility, or FPP call root exists;
- live `fmov_rm` still calls `raw_fmov_d_rm`;
- the shared raw body still loads the host pointer and performs the binary64
  load; and
- a strict exact-native double-memory FMOVE remains green.

Any future caller makes closure regeneration fail rather than silently keeping
the unreachable classification.

## Runtime evidence

The accepted ordinary FMOVE memory matrix covers five formats over `(An)`,
`(An)+`, and `-(An)`, A7 geometry, maximum FP/register fields, exact FPSR/CCR,
strict second-pass native execution, and CoW cleanup (**18/18**).

`bash jit-test/fmov-d-rm-retirement-matrix.sh` reruns the focused live-sibling
witness:

- FMOVE.D `(A0)` through `fmov_rm -> raw_fmov_d_rm`;
- exact binary64 `1.5`, unchanged A0 and `SR=0x271f`;
- strict native replay with no fallback;
- isolated CoW/HOME cleanup through the underlying matrix.

```text
FMOV_D_RM_RETIREMENT_FOCUSED live_double=1 fail=0 total=1
```

## Closure decision

`midfunc,fmov_d_rm` changes from **unreviewed** to **unreachable**. No other row
changes. In particular `fmov_rm` and `raw_fmov_d_rm` stay reachable/unreviewed.
No production or generated source changes. Whole-engine closure is not claimed.

## Acceptance

- focused live-sibling matrix: **1/1 strict exact-native**;
- structural audit: pass for declaration-only external census, definition-only
  synonym MIDFUNC, live `fmov_rm`, shared raw load body, and focused wrapper;
- deterministic inventory: **998 rows**, exactly `fmov_d_rm` unreviewed ->
  unreachable; MIDFUNC totals become 279 audited / 123 unreachable / 20
  unreviewed, all other layer statuses are unchanged, and total unreviewed
  becomes **179**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `260466556b7887f15d717ea952d275f4189a74008019fab82633b4f531db9435`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `db86880fca557b95d2254b56c88e4079fecce63c744af5ca79b52c2205e5817e`;
- independent review: **APPROVE** after source-attributed preprocessing,
  declaration-vs-call syntax, exact synonym names, and raw reference pruning
  were traced explicitly; the earlier bare BLOCK had no counterexample and is
  not treated as a substantive verdict;
- executable source is unchanged from canonical `9d17274a`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Shell/Bun syntax, source hygiene, `git diff --check`, and scoped CoW/HOME
cleanup pass. Acceptance logs are removed after publication.
