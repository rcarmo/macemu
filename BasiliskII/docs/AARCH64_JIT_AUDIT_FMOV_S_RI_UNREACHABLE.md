# AArch64 JIT FMOVECR binary32-constant wrapper retirement

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `deac1697`

## Scope

This checkpoint classifies only `midfunc,fmov_s_ri`. The ARM64 compatibility
header maps four historical FMOVECR constants—π, log10(2), log2(e), and ln(2)—
to this immediate-binary32 wrapper. All four roots are below the configured
AArch64 FMOVECR exact-MPFR service return, so none is control-flow reachable.

The lower `raw_fmov_s_rr` boundary is **not** retired. It remains live through
`fmov_s_rr` for ordinary single-precision register and memory sources.

## Positive control-flow and caller proof

The configured graph must retain exactly four macro-expanded `fmov_s_ri` roots
and zero MIDFUNC parents. Raw source must still show all four compatibility
mappings, while the FMOVECR service gate must return before selector dispatch.
The MIDFUNC itself must remain definition/end-marker only and retain its
immediate materialisation plus shared `raw_fmov_s_rr` call.

The shared raw boundary must still have the live `fmov_s_rr` caller and its
binary32-bit transfer followed by binary64 widening. A future caller or moved
service barrier fails closure/structural checks.

## Runtime evidence

`bash jit-test/fmov-s-ri-retirement-matrix.sh` runs three bounded cases:

- exact MPFR-serviced FMOVECR π;
- strict FP7 FMOVECR rejection before native execution;
- strict exact-native ordinary single `(A0)` through
  `fmov_s_rr -> raw_fmov_s_rr`.

The underlying matrices require exact value/FPSR/CCR, native or service
attribution, replay, and isolated CoW/HOME cleanup.

```text
FMOV_S_RI_RETIREMENT_FOCUSED service=1 strict=1 live_single=1 fail=0 total=3
```

The full accepted FMOVECR and ordinary-memory matrices remain **36+3** and
**18/18** respectively.

## Closure decision

`midfunc,fmov_s_ri` changes from **unreviewed** to **unreachable**. `fmov_s_rr`
and `raw_fmov_s_rr` remain reachable/unreviewed. No generic emitter row changes,
and no production/generated source changes. Whole-engine closure is not
claimed.

## Acceptance

- focused attribution: **1 exact service + 1 strict rejection + 1 live native
  single-source case**;
- structural audit: pass for four dead macro roots, definition-only MIDFUNC,
  live sibling/raw conversion, and focused wrapper;
- deterministic inventory: **998 rows**, exactly `fmov_s_ri` unreviewed ->
  unreachable; MIDFUNC totals become 280 audited / 124 unreachable / 18
  unreviewed, total unreviewed becomes **176**;
- live-helper reference counts correctly reduce when the dead MIDFUNC leaves
  the reachable graph: `compemu_raw_mov_l_ri` 9 -> 8 and `raw_fmov_s_rr` 4 ->
  3, with both statuses unchanged;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `704d2548336608582106dea5f0c5edc05c40c6848961ff14372061a347b1a4d9`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `b9282cf8b218424f392c8e50b8e68c6769399765f7390e2e52974a08b9a7273f`;
- independent review: **APPROVE** for exact roots/barrier, absent parents,
  retained shared raw chain, three runtime cases, cleanup, and one status row;
- executable source is unchanged from canonical `deac1697`; accepted artifact
  hashes and the carried **904/904** active, **33/33** allocator, strict-policy,
  and clean-build baselines remain unchanged.

Shell/Bun syntax, source hygiene, `git diff --check`, and scoped CoW/HOME
cleanup pass. Acceptance logs are removed after publication.
