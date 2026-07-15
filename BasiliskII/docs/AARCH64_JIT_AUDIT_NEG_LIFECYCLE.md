# AArch64 JIT NEG lifecycle audit

## Scope

This tranche closes the reachable M68K `NEG.B`, `NEG.W`, and `NEG.L` generator lifecycle and the separately reachable generic AArch64 `NEG_ww` encoder API. It also corrects the identical effective-address ownership omission in memory-form `NEGX`.

The authoritative generator is `src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is regenerated output.

## Structural finding

Memory `NEG` and `NEGX` fetch an operand and retain its pre-write effective address while they:

1. allocate a private zero/result scratch;
2. execute shared `SUB`/`SUBX` lowering;
3. publish flags; and
4. write the result to the original address after any architectural postincrement or predecrement.

The fetched value remained allocator-owned, but the private effective address did not. A result allocation could therefore reuse the EA's host mapping before `genastore()`.

A pre-fix forced collision on `NEG.B (A0)+` (`S3` result toward `S1` EA) executed natively and produced:

- interpreter: stored/loaded `FF`, captured CCR `2719`, final SR `2718`;
- JIT: unchanged `01`, captured CCR `2719`, final SR `2710`;
- allocator witness: `REGPRESSURE_PIN_HIT scratch_vreg=22 pin_vreg=20`;
- exact entry: both `INTERPOP pc=00001000` and `NATEXEC pc=00001000`.

The same probe against `NEGX.B (A0)+` left `01` instead of `FE` and ended with SR `2710` instead of `2718`.

This was an ownership defect, not an arithmetic or encoder defect.

## Repair

For each memory destination, the generator now acquires `jit_value_lock(srca)` immediately after `genamode()` and releases it only after `genastore()`:

- `__negealock` for `NEG`;
- `__negxealock` for `NEGX`.

Regeneration produces 42 balanced lock/unlock pairs for `NEG` and 42 for `NEGX`: 21 writable memory handlers in each of the flag-live and no-flags tables. Register destinations acquire no EA lock.

The post-fix permanent pressure cells both report `REGPRESSURE_PIN_SKIP ... locked=1`, exact native entry, and interpreter/JIT register equality:

- `neg_b_postinc_result_ea_collision`;
- `negx_b_postinc_result_ea_collision`.

The earlier byte/word/long `NEGX` source/result collision cells remain active, so this correction extends rather than replaces the accepted source-value contract.

## M68K semantic matrix

`NEG` continues to use the shared `flag_sub` lowering with an explicit zero destination; the unreachable `jff_NEG_*` and `jnf_NEG_*` namesakes are not called.

The 24-vector exact-native matrix covers:

- byte, word, and long zero, one, signed minimum, and minus-one inputs;
- narrow Dn upper-lane preservation;
- Z, N, V, C, and X replacement, including signed-minimum overflow;
- flag-live and no-flags generated tables;
- `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and absolute-long writeback;
- normal and forced-special memory helpers;
- A7 byte postincrement/predecrement geometry;
- exact `pc=00001000` native replay on every vector.

Focused acceptance reports 24 pass, 0 fail, 0 infrastructure failure, and 24/24 opcode-native evidence.

## Generic `NEG_ww` encoder

M68K `NEG` itself lowers through shared SUB MIDFUNCs, so it does not prove the generic encoder API. `NEG_ww` has six textual call sites in the MIDFUNC source; two lie on reachable configured paths (the flag-live and no-flags signed-word division remainder correction), while four are in closure-unreachable namesakes/helpers.

`jit-test/emitter-neg-conformance.cpp` directly proves:

- one emitted instruction;
- exact word `0x4b0903ea` for `NEG W10,W9`;
- seven native 32-bit vectors, including zero, signed minimum, all ones, upper-64-bit masking, and an ordinary mixed-bit value;
- AArch64 W-register zero-extension of the result.

Metrics:

```text
METRIC emitter_neg_exact_words=1
METRIC emitter_neg_native_vectors=7
METRIC emitter_neg_width32=1
METRIC structural_neg_emitter_apis=1
METRIC structural_neg_emitter_callsites=6
```

`NEG_xx`, `NEGS_ww`, and `NEGS_xx` remain closure-unreachable and are not promoted by this report.

## Acceptance

The mandatory gates are:

```sh
./jit-test/emitter-neg-conformance.sh
bun jit-test/structural-audit.ts
B2_REGPRESSURE_CELLS=neg_b_postinc_result_ea_collision,negx_b_postinc_result_ea_collision ./jit-test/regalloc-pressure.sh
B2_TEST_NAMES=<24 NEG matrix names> ./jit-test/run.sh
bun jit-test/closure-inventory.ts
bash -n jit-test/run.sh jit-test/regalloc-pressure.sh jit-test/emitter-neg-conformance.sh
git diff --check
```

Accepted evidence:

- focused NEG matrix: **24/24**, zero semantic or infrastructure failures;
- complete active-risky inventory, partitioned into seven bounded fail-closed
  slices: **694/694** (`100+100+100+100+100+100+94`), every slice score 100;
- complete allocator-pressure suite: **16/16**, including both new EA cells;
- post-clean focused replay: **24/24** plus both EA cells with `skip=1`,
  `natexec=1`, and `interpop=1`;
- direct emitter: 1 exact word and 7/7 native results;
- clean AArch64 build after two byte-identical generator runs;
- deterministic generated hashes:
  - `compemu.cpp`: `4a7a7d01f2f2fb76e418ffdcd8bcad7e43bd0aa49ef33c25d7ff773a9c331e84`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure artifacts:
  - CSV: `2d045bc0d0d779858a242bbe747bf7306c91d703487f3c0e1273488046d0d423`;
  - Markdown: `9912665e1fe4ccb7cd828f8dede6578441cd896cc067942565678c7eb0abaaab`;
- shell syntax and `git diff --check`: clean.

The audit also found that `emit_failure_metrics()` and the top-level summary
previously returned success after infrastructure or semantic failures. Both
paths now exit nonzero. A missing-ROM negative gate reports `build_ok=0`,
`infra_fail=1`, `total=0`, and process status 1; structural enforcement emits
`METRIC structural_harness_fail_closed_status=1`.
