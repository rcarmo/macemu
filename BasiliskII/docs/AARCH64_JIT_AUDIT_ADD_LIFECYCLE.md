# AArch64 JIT ADD lifecycle audit

## Scope

This tranche closes the reachable M68K `ADD.B`, `ADD.W`, and `ADD.L` lifecycle: flag-live and no-flags compiler tables, register and immediate lowering, all readable source EAs, all writable destinations, aliases, special-memory routing, EA writeback, and allocator ownership.

`ADDA`, `ADDX`, and generic AArch64 `ADD_*` emitter APIs are separate families and are not promoted by this report. The authoritative generator is `src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is regenerated output.

## Structural inventory

The reachable generator route is `i_ADD`. It emits 208 handlers: 104 flag-live and 104 no-flags. Of these, 126 have writable memory destinations (63 per table).

Arithmetic is shared by six register-source MIDFUNC routes:

- `jff_ADD_b`, `jff_ADD_w`, and `jff_ADD_l`;
- `jnf_ADD_b`, `jnf_ADD_w`, and `jnf_ADD_l`.

Each route acquires both operands through its width-specific `INIT_REGS_b/w/l(d, s)` contract and releases them through `EXIT_REGS(d, s)`. Constant sources route to the corresponding six reachable immediate helpers. The older `jnf_ADD_im8` definition has no configured caller and remains closure-unreachable. Narrow register destinations merge only the low byte/word; long destinations replace the full 32-bit lane. Flag-live lowering derives NZVC from width-correct AArch64 `ADDS` operations and publishes X from carry. No-flags lowering changes data without publishing guest CCR state.

The generated forms cover:

- Dn and immediate sources;
- `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, absolute-long, `(d16,PC)`, and indexed-PC readable sources;
- Dn, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and absolute-long destinations;
- byte A7 postincrement/predecrement geometry; and
- normal and forced-special memory paths.

## Allocator finding

Memory-destination `ADD` retains a private pre-write effective address while the shared arithmetic MIDFUNC allocates operands and, on the flag-live path, publishes X before `genastore()` performs the ordered write. Postincrement or predecrement may already have changed the architectural address register, so that private EA cannot be reconstructed from the architectural base.

Before repair, `add_b_postinc_x_ea_collision` forced FLAGX toward the live pre-write EA for `ADD.B D0,(A0)+`. It executed both interpreter and native JIT at the audited PC but failed equivalence:

```text
status=FAIL pin=2 skip=0 natexec=1 interpop=1
```

This is an EA-ownership defect, not an arithmetic failure. The generator now pins `dsta` immediately after destination acquisition and releases it only after `genastore()`. Regeneration creates 126 balanced `__adddstealock` lock/unlock pairs, one for every memory handler, and none for Dn destinations.

The repaired witness rejects both attempted collisions while retaining exact native execution:

```text
add_b_postinc_x_ea_collision status=PASS pin=0 skip=2 natexec=1 interpop=1
```

A second pressure cell forces architectural D0 toward the fetched private source for `ADD.B (A0)+,D0`:

```text
add_b_postinc_source_dreg_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
```

Counterfactual builds established that an extra generator source lock and a multiset rewrite of `jit_value_lock()` were unnecessary: the MIDFUNC `INIT_REGS`/`EXIT_REGS` lifecycle already owns both arithmetic operands. Those broader changes were removed. The accepted production repair is therefore limited to the witnessed pre-write EA pin.

## Exact-native semantic matrix

The 34-vector matrix begins each replay at the audited opcode and requires native execution at `pc=00001000`. It covers:

- byte, word, and long zero, signed overflow, unsigned carry, ordinary, and self-alias results;
- narrow upper-lane preservation and full long replacement;
- register and constant/immediate paths, including large and negative long immediates;
- Z, N, V, C, and X replacement;
- three flag-dead register routes and one flag-dead memory route;
- every readable memory-source EA and writable memory-destination EA listed above;
- postincrement, predecrement, indexed, PC-relative, absolute, and A7 byte geometry;
- special-memory helper routing; and
- stored-data reloads plus captured SR snapshots after memory RMW operations.

Focused acceptance reports 34 pass, 0 fail, 0 infrastructure failure, with exact-native assertion on all 34 vectors.

## Acceptance gates

```sh
B2_TEST_NAMES=<34 ADD matrix names> bash jit-test/run.sh
bash jit-test/regalloc-pressure.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
bash -n jit-test/run.sh jit-test/regalloc-pressure.sh
make -C BasiliskII/src/Unix clean
make -C BasiliskII/src/Unix -j12
B2_TEST_NAMES=add_core_b_postinc_dest_native bash jit-test/run.sh
B2_REGPRESSURE_CELLS=add_b_postinc_source_dreg_collision,add_b_postinc_x_ea_collision bash jit-test/regalloc-pressure.sh
git diff --check
```

Accepted evidence:

- focused exact-native matrix: **34/34**, zero semantic or infrastructure failures;
- complete active-risky replay: **695/695**, zero semantic or infrastructure failures, score 100;
- complete allocator-pressure suite: **18/18**, including both ADD cells;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build, followed by **1/1** promoted exact-native replay and both ADD pressure witnesses (`skip=1` / `skip=2`);
- generated output is byte-reproducible across two runs:
  - `compemu.cpp`: `07a4be8b0d94300d8290c9b63110815856e7f03d54a97053f5a8691a8b5e1f82`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- structural contracts require 208 generated handlers, six shared operand lifecycles, zero redundant generator source locks, 126 balanced memory-EA pins, all 34 exact-native vectors, and both pressure witnesses;
- deterministic 997-row closure inventory:
  - generator `audited=48`, `serviced=44`, `unreviewed=38`;
  - MIDFUNC `audited=210`, `unreachable=118`, `unreviewed=94`;
  - CSV: `590cb438aafe9c3caf0e24956982e4129af25951aa34444f12676e6b0ac43821`;
  - Markdown: `51055f29b17ac7a7d62c9aeb552b617c6682bac377e50cf5912d5fe60153ca6b`;
- shell syntax, structural audit, source hygiene, and diff hygiene are clean.
