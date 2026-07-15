# AArch64 JIT generic branch-emitter audit

Date: 2026-07-15

## Scope

This tranche closes the complete reachable generic AArch64 branch-encoding cluster rather than inferring encoder correctness from M68K opcode equivalence. The configured source graph has 21 reachable APIs and 237 references:

- `B_i`, `BR_x`, and `CC_B_i`;
- `BEQ_i`, `BNE_i`, `BCS_i`, `BCC_i`, `BMI_i`, `BVS_i`, `BVC_i`, `BGE_i`, `BGT_i`, `BLE_i`, and `BLS_i`;
- `CBZ_wi`, `CBZ_xi`, `CBNZ_wi`, and `CBNZ_xi`;
- `TBZ_wii`, `TBZ_xii`, and `TBNZ_wii`.

`BHI_i`, `BLT_i`, `BPL_i`, and `TBNZ_xii` have no configured callers and remain closure-unreachable. Their shared encoders are nevertheless exercised by the direct probe. `BL_i` and `BLR_x` are separate unreachable call/link APIs and are not promoted by this report.

## Defects found

### Signed TBZ/TBNZ immediate encoding

All four `TBZ`/`TBNZ` macros encoded their signed 14-bit instruction displacement with `% 0x3fff` rather than an imm14 mask. This had two independent defects:

- displacement `0x3fff` encoded as zero instead of all immediate bits set;
- negative displacements left-shifted a negative C++ value, which is undefined behaviour.

The pre-fix direct probe failed closed under UBSan:

```text
emitter-branch-conformance.cpp:106:29: runtime error: left shift of negative value -8192
```

The macros now use `(i & 0x3fff) << 5`, matching the existing signed-mask contracts for `B`, `B.cond`, and `CBZ`/`CBNZ`.

The final adversarial pass found a second UB path in the X forms: when production supplied bit 32–63 as a signed `int`, the width selector formed signed `1 << 31`. The X-form macros now form it as `((bit & 0x20u) << 26)`, and the UBSan probe deliberately accepts its bit argument as signed `int` so that this production call shape cannot regress unnoticed.

### Runtime branch patch discrimination

`write_jmp_target()` identified both `TBZ`/`TBNZ` and `CBZ`/`CBNZ` with the same `0x7c000000` mask and patched every member as imm14. That silently truncated a valid CB displacement outside ±32KB even though CB has a signed imm19 ±1MB range.

The TB patch mask was also `0xfffc001f`, which clears only 13 immediate bits and can retain stale imm14 bit 13 when repatching a nonzero instruction. Out-of-range offsets merely logged a warning and still installed a truncated branch. Unknown instruction words fell into the B.cond patch path.

The repaired patch boundary now:

1. rejects unaligned targets;
2. distinguishes `B`, `TBZ`/`TBNZ`, `CBZ`/`CBNZ`, and `B.cond` by their architectural opcode masks;
3. applies signed imm26, imm14, imm19, and imm19 limits respectively;
4. clears the complete immediate field (`0xfff8001f` for TB);
5. aborts before opening the executable write window on range or opcode violations;
6. writes and flushes exactly one instruction only after validation.

This converts a possible wrong-target native branch into a fail-closed compiler error.

## Direct encoding and native execution proof

`jit-test/emitter-branch-conformance.cpp` compiles against the production macros and runs under native AArch64 with UBSan enabled. It proves:

- 56 independent exact instruction words;
- signed minimum and maximum displacement fields for imm26, imm19, and imm14;
- all 16 raw condition fields and all 14 named B.cond wrappers;
- BR register fields;
- CB W/X register width and zero/nonzero routes;
- TB W/X bit 0, 31, 32, and 63 fields and routes;
- all 16 NZCV combinations for each of the 14 named AArch64 conditions;
- a native negative-displacement BNE loop;
- a native forward/backward unconditional branch path;
- a native register-indirect branch to a local executable target.

Accepted direct output:

```text
METRIC emitter_branch_exact_words=56
METRIC emitter_branch_native_vectors=251
METRIC emitter_branch_patch_exact_words=8
METRIC emitter_branch_patch_rejections=10
METRIC emitter_branch_patch_native_vectors=4
METRIC emitter_branch_condition_vectors=224
METRIC emitter_branch_signed_range_edges=8
METRIC emitter_branch_width32=1
METRIC emitter_branch_width64=1
```

The probe is mandatory in `jit-test/run.sh`, bounded by `timeout -k 5s 60s`, and returns nonzero on any encoding, native-route, count, sanitizer, or infrastructure failure.

## Required gates

```sh
timeout -k 5s 60s ./jit-test/emitter-branch-conformance.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
bash -n jit-test/run.sh jit-test/emitter-branch-conformance.sh
git diff --check
```

Before publication this tranche also requires the complete allocator-pressure suite, clean BasiliskII build, deterministic closure regeneration, and the complete active-risky exact-native campaign in bounded slices.

## Final acceptance

After the signed X-bit-selector correction, all evidence was regenerated against the final production source:

- direct UBSan/native conformance: 56/56 exact words, 251/251 native emitter vectors, 8/8 exact patch words, 10/10 required patch rejections, and 4/4 natively executed patched routes;
- strict fallback/abort matrix: 5/5;
- allocator pressure: 16/16 cells;
- active-risky exact-native replay: 694/694 in seven bounded fail-closed slices (`100+100+100+100+100+100+94`), with zero semantic or infrastructure failures;
- clean AArch64 `uae_cpu_2026` build, structural audit, shell syntax, and diff hygiene: pass;
- generated `compemu.cpp`: byte-stable across three observations at SHA-256 `4a7a7d01f2f2fb76e418ffdcd8bcad7e43bd0aa49ef33c25d7ff773a9c331e84`;
- synchronized closure regeneration: 997/997 rows, promoting 21 branch APIs to audited and leaving emitter totals at 27 audited, 91 unreachable, and 176 unreviewed.

At this report's publication the next mechanically selected semantic family was `ADD`; it is subsequently closed by `AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md`. This branch-emitter report does not supply that later semantic evidence.
