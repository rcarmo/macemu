# AArch64 generic conditional-select emitter audit

Date: 2026-07-28
Base: `aa031e83066f7907c373612e5ed25439633a8d62`

## Scope

This bounded audit covers the four mechanically selected reachable generic
conditional emitter APIs:

- `CSEL_wwwc`
- `CSEL_xxxc`
- `CSET_xc`
- `CSETM_wc`

The two `CSEL` forms share the A64 conditional-select encoding grammar. `CSET`
and `CSETM` are architectural aliases that select between zero and one/all-ones
by encoding the inverse predicate. Other conditional-compare/select aliases are
outside this tranche and remain classified independently.

## Source and caller census

The authoritative definitions remain in
`BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h`.

The raw production-source census, excluding the four definitions, is:

| API | Raw callers |
|---|---:|
| `CSEL_wwwc` | 9 |
| `CSEL_xxxc` | 29 |
| `CSET_xc` | 17 |
| `CSETM_wc` | 9 |
| **Total** | **64** |

Callers span `compemu_midfunc_arm64_2.cpp`, `codegen_arm64.cpp`, and
`compemu_legacy_arm64_compat.cpp`. The closure inventory's configured reachable
reference counts are narrower because it follows only reachable MIDFUNC graph
roots; they remain `9/11/15/9` respectively.

No configured `CSET_xc` or `CSETM_wc` caller passes `NATIVE_CC_AL` or a
nonexistent configured `NATIVE_CC_NV`. Dynamic alias predicates are bounded by
the explicit `jnf_SCC` mapping or `legacy_x86_cc_to_native()` abort path. This
matters because condition inversion is meaningful for the 14 ordinary
predicates, while AL/NV are degenerate alias inputs.

## Encoding and native oracle

`jit-test/emitter-conditional-conformance.cpp` checks eight representative
instruction words against canonical A64 encodings:

- `CSEL w9,w10,w11,EQ` -> `0x1a8b0149`
- `CSEL w30,w29,w28,NV` -> `0x1a9cf3be`
- `CSEL x12,x13,x14,MI` -> `0x9a8e41ac`
- `CSEL x30,x29,x28,AL` -> `0x9a9ce3be`
- `CSET x15,NE` -> `0x9a9f07ef`
- `CSET x30,LE` -> `0x9a9fc7fe`
- `CSETM w16,CS` -> `0x5a9f33f0`
- `CSETM w30,GT` -> `0x5a9fd3fe`

The native oracle sets NZCV explicitly and evaluates expected predicates in
independent C++ logic. It executes:

- `CSEL_wwwc`: all 16 condition encodings x all 16 NZCV nibbles = 256;
- `CSEL_xxxc`: all 16 condition encodings x all 16 NZCV nibbles = 256;
- `CSET_xc`: 14 ordinary predicates x all 16 NZCV nibbles = 224;
- `CSETM_wc`: 14 ordinary predicates x all 16 NZCV nibbles = 224.

Total: **960/960 native vectors** plus **8/8 exact words**. W-form tests use
host inputs with nonzero upper halves and require architectural zero-extension;
X-form tests require the complete 64-bit selected value.

## Finding

No production encoding or semantic defect was reproduced. The source macros
match canonical encodings, select the expected operand for every NZCV witness,
apply the alias inversion correctly, and preserve W/X width semantics. There is
therefore no production-source change in this tranche.

## Closure

Deterministic regeneration retains the authoritative **998-row** inventory and
promotes exactly four `emitter_api` rows from `unreviewed` to `audited` using
this report. The committed predecessor CSV hash is:

`7dee9ce2603c44f959ac1e59020106eaa640c1bc5aaf2a7fc3ca979d798fed44`

Expected emitter status movement is `121 audited / 70 unreviewed` to
`125 audited / 66 unreviewed`; every other layer and status is unchanged.

## Acceptance evidence

Focused evidence collected on the native AArch64 host:

```text
METRIC emitter_conditional_apis=4
METRIC emitter_conditional_exact_words=8
METRIC emitter_conditional_csel_w_vectors=256
METRIC emitter_conditional_csel_x_vectors=256
METRIC emitter_conditional_cset_x_vectors=224
METRIC emitter_conditional_csetm_w_vectors=224
METRIC emitter_conditional_native_vectors=960
METRIC emitter_conditional_all_conditions=1
METRIC emitter_conditional_width32_zero_extend=1
METRIC emitter_conditional_width64=1
```

The focused harness is integrated into the bounded emitter phase. Acceptance
runs on this exact candidate after the completed clean build were:

- focused conditional probe: **8/8 exact words**, **960/960 native vectors**;
- complete emitter/boundary phase: pass, including the integrated conditional probe;
  its emitter-only wrapper correctly reports `validation_complete=1` and
  `vectors_skipped=1`; the trailing opcode-vector aggregate is therefore
  `pass=0 / total=0`, not an emitter failure;
- complete active-risky corpus: **904/904**, zero failure and zero infrastructure failure;
- allocator pressure: **33/33**;
- clean full `BasiliskII` build: pass;
- pending-state deterministic regeneration: byte-identical published CSV
  `7dee9ce2603c44f959ac1e59020106eaa640c1bc5aaf2a7fc3ca979d798fed44`
  and canonical Markdown
  `e72f4ff1283c1cfcdd5d620e9d3c54106a7ff56d0ba8e70cf02c1ab6421f7324`;
  final promotion regeneration will record its own hashes;
- option-like output paths such as `--check` are now rejected before generation,
  preventing accidental canonical detail-path mutation;
- source hygiene and `git diff --check`: pass;
- production and generated source: unchanged.

An initial parallel broad run raced `make clean` and lost the executable; its
vector/allocator failures are rejected as invalid infrastructure evidence. The
sequential post-build reruns above are the acceptance evidence.

Review history:

1. initial independent verdict: **reject** — no semantic, encoding, ABI,
   census, or hash defect found; acceptance was rejected because this report
   remained pending, the inventory generator did not recognise the exact
   pending marker, structural therefore failed by design, and sequential logs
   were not recorded here;
2. correction: the inventory generator now rejects this exact pending marker,
   this report records the sequential evidence, and structural remains
   fail-closed until the next verdict is recorded.

Configured raw-caller total: **64**.

Final promoted inventory hashes:

- CSV: `fa880dd456f1ad6112b56a90ea15ede909e932f7d5d939c86096a03d467c477d`;
- Markdown: `00965376f073ef9cb138a49df21aec9008e686ddebc9e966b0a8e095b6d020ad`.

final re-review: **approve**.
