# AArch64 JIT FBcc lifecycle audit

## Scope

This tranche audits the configured `USE_JIT_FPU` native compiler path for
`i_FBcc`. It covers all sixteen 68881 predicates, word and long signed
displacements, taken and not-taken successors, exact native replay, integer
CCR preservation, and the MPFR/native-double boundary that supplies FPSR
condition state.

The existing compfpu-disabled semantic service remains independently covered;
this report promotes only the reachable native generator row `i_FBcc`.

## Defects found and repaired

1. `comp_fbcc_opp` inherited x87 parity condition IDs (`10` and `11`). The
   AArch64 branch emitter correctly rejected those unsupported integer IDs.
   FBcc now uses a distinct sixteen-value FP predicate namespace and explicit
   AArch64 `FCMP` predicate lowering.
2. `FCMP` NZCV was treated as architectural integer CCR at block finalisation.
   FBcc now saves integer CCR before predicate construction and tags the host
   NZCV as edge-only, so `XNZVC` is unchanged on both successors.
3. Mid-block side exits accepted only integer conditions and inverted them with
   `cc ^ 1`. They now accept FP edges and use the 68881 complement pairing
   `cc ^ 15`, without restoring integer NZCV over the live `FCMP` predicate.
4. Native FP shadows were declared as a block-boundary contract but were never
   synchronised. Fresh JIT entry therefore classified every architectural FPSR
   state as zero. Dispatcher entry now imports MPFR registers plus FPSR CCB into
   the lazy `FP_RESULT` shadow; all exits to C/interpreter export native FP
   registers and CCB while preserving FPSR quotient and exception fields.
5. FTST could self-alias its source with `FP_RESULT`. The result is now
   materialised through a distinct FP temporary before publication.

## Runtime evidence

`bun jit-test/fbcc-native-matrix.ts` is fail-closed and runs 160 strict cases:

- 16 integer FP predicates;
- positive, zero, negative, positive-NaN, and negative-NaN condition classes;
- word and long displacement forms;
- taken and not-taken outcomes;
- strict full-JIT with no fallback;
- exact second-pass native entry at the FBcc opcode;
- architectural successor selection;
- full integer `SR=0x271f` preservation.

Accepted focused result:

```text
FBCC_NATIVE_MATRIX pass=160 fail=0 total=160
```

## Structural contracts

- FP pseudo-condition IDs are disjoint from integer ARM condition IDs.
- Every condition is emitted through `compemu_raw_jcc_l_oponly` with explicit
  ordered/unordered semantics.
- Integer CCR is saved before target-address arithmetic and `FCMP`.
- Final and mid-block edges do not publish `FCMP` NZCV as guest CCR.
- FP edge complementation uses the architectural predicate pairing.
- JIT entry/exit synchronises the architectural FPU register file and FPSR CCB.
- `jitfpu false` still routes FBcc through the existing semantic service.

## Acceptance gates

Post-clean acceptance is:

- focused strict exact-native matrix: **160/160**, zero failures;
- complete active-risky corpus: **904/904**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure matrix: **31/31**, zero failures;
- strict full-JIT negative contract: ordinary allocation fallback plus expected
  aborts for allocation, optlev-0, opcode fallback, and verifier-reference paths;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after two
  explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic closure regeneration retains **997 rows**; generated hashes are:
  - CSV: `43451f85d7173d6f29bc38f41c6508db352c6fe5ee73104096788e8d012b2a8c`;
  - Markdown: `8e67e0b1dad0a2420899a6f1339fab8fe2418464cee9faa6cf9a9aa87f1c6db4`;
- shell syntax, structural checks, source hygiene, and `git diff --check` pass.

## Closure decision

`generator,i_FBcc` is **audited** for the configured native-FPU build. No other
FPU generator, MIDFUNC, emitter, or runtime-boundary row is promoted by this
tranche. The deterministic inventory next selects `FPP`; whole-engine closure
is not claimed.
