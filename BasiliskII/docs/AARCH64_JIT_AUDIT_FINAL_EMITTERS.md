# AArch64 final generic emitter audit

Date: 2026-07-28
Base: `d9c3ca895647444652a1f26a2545718a8e810a01`

## Scope

This is the final **44-row** reachable `emitter_api` tranche in the 998-row
closure inventory. It consists of five source-coherent clusters:

1. literal/FP memory (6): `LDR_xPCi`, `LDR_dXi`, `LDR_dXx`, `LDR_sXi`,
   `STR_dXi`, `STR_dXx`;
2. shifts/rotate (10): `LSL_{wwi,www,xxi,xxx}`, `LSR_{wwi,www,xxi,xxx}`,
   `ROR_{wwi,www}`;
3. moves (13): `MOV_{wi,wish,ww,xi,xish,xx}`, `MOVI_di`,
   `MOVK_{wi,wish,xi,xish}`, `MOVN_{wi,xi}`;
4. system/FP state (7): `MRS_{NZCV,FPCR,FPSR}_x`,
   `MSR_{NZCV,FPCR,FPSR}_x`, `REV64_dd`;
5. multiply/divide (8): `MSUB_{wwww,xxxx}`, `SMULL_xww`, `UMULL_xww`,
   `SDIV_{www,xxx}`, `UDIV_{www,xxx}`.

The configured inventory reference total is **598**. The bounded raw four-source
root contains **778** calls; the difference is inactive/unreachable MIDFUNC
source removed by the configured closure graph.

## Focused exact/native contract

`jit-test/emitter-final-conformance.cpp` uses one executable-page harness with
cluster-specific failure labels and counters. It proves:

- **44/44** canonical representative words, exactly one per API;
- **496/496** native value/alias/lane/edge checks;
- **35/35** ordinary-instruction NZCV-preservation checks;
- `MOVI_di`: **256/256** architectural per-byte bitmask immediates;
- system state: **23/23** NZCV/FPCR/FPSR round trips with FP state restored;
- FP direct memory: **2/2** bit-31 `UXTW` guest-offset load/store cells;
- literal load from an embedded code-page constant;
- binary32/binary64 raw-lane loads and stores;
- all immediate shift counts (W 0..31, X 0..63), register count masking,
  width zero extension, and source/destination aliases;
- move-wide lane placement, MOVK preservation, MOVN complement semantics, and
  W/X width behavior;
- `REV64_dd` as the architectural D-lane `v.8b` byte reversal used by double
  host-memory swapping, not the unrelated Q-lane `v.16b` form;
- MSUB modulo-width semantics, signed/unsigned widening multiplication,
  signed/unsigned division, divide-by-zero result zero, and signed MIN/-1 wrap.

Focused result:

```text
METRIC emitter_final_apis=44
METRIC emitter_final_exact_words=44
METRIC emitter_final_native_vectors=496
METRIC emitter_final_nzcv_vectors=35
METRIC emitter_final_movi_vectors=256
METRIC emitter_final_system_vectors=23
METRIC emitter_final_fp_uxtw_highbit_vectors=2
```

## Findings during oracle construction

No production defect was reproduced. The independent oracle corrected four
incorrect test assumptions before acceptance:

- FP register-offset memory uses `[base_x, offset_w, UXTW]`, not X-offset LSL;
- `REV64_dd` is the low D-lane `v.8b` operation, not Q-lane `v.16b`;
- `MOVI_di` expands immediate bits to `0xff` byte lanes, not one repeated byte;
- generic NZCV cells must pass guest offset zero and natmem base in the encoded
  roles for UXTW memory forms.

These are test-harness corrections only. Production and generated source remain
unchanged.

## Closure candidate

Published predecessor:

- rows: **998**;
- emitter status: `147 audited / 103 unreachable / 44 unreviewed`;
- CSV hash: `85a99c8a3f81c791f61f83aae4ec049f1f1c3c4c9eae42eea4b9346b73ce17cd`;
- Markdown hash: `df08168879f71d302b181f06c368c548496def42140dc97abd7fbaaf74f6cd90`.

Acceptance must promote exactly 44 rows, yielding `191 audited / 103
unreachable / 0 unreviewed` emitter APIs and zero unreviewed rows in every
inventory layer. Final whole-engine gates remain separate after publication.

Candidate evidence:

- focused final-emitter probe: pass with all metrics above;
- complete integrated emitter/boundary phase: pass, `validation_complete=1`,
  `EMITTER_RC=0` (opcode vectors intentionally skipped by that phase);
- clean generated AArch64 JIT build: pass, `BUILD_RC=0`;
- complete active-risky corpus: **904/904**, zero failures, zero infrastructure
  failures, `validation_complete=1`, and `VECTOR_RC=0`;
- allocator-pressure corpus: **33/33**, zero failures, `REGPRESSURE_RC=0`;
- pending-state inventory remains canonical at `147 audited / 103 unreachable /
  44 unreviewed`, with hashes above;
- source hygiene and `git diff --check`: pass;
- production and generated source: unchanged.

Initial independent verdict: **reject** — the narrow judge raised no semantic,
encoding, ABI, scope, counter, or coverage objection, but refused finality
because the report and canonical rows were intentionally still pending. This is
retained as review history, not treated as approval.

The final independent readiness judge inspected the 44-row census, all
production definitions and configured/raw caller totals, hard-coded encoding
oracle, native semantic and preservation cells, integrated gate, clean build,
904-vector corpus, allocator-pressure corpus, and fail-closed structural
contract. It found no source, semantic, encoding, ABI, counter, coverage, or
scope defect beyond the expected pre-promotion pending marker.

Final promoted inventory:

- emitter status: `191 audited / 103 unreachable / 0 unreviewed`;
- no unreviewed row remains in any inventory layer;
- CSV hash: `8220e4e02341ac559a4af49a0bd163e86c0f11c5ffa94df57f304fb542313afd`;
- Markdown hash: `939fd2711ed9e42542caba28e413679b22060a1a57ad05f434fe9e8f7c00cde3`.

Final structural and deterministic regeneration gates: pass.

final re-review: **approve**.
