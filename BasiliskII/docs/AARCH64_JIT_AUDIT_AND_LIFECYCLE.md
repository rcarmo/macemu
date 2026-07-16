# AArch64 JIT AND lifecycle audit

## Scope

This tranche closes the reachable M68K `AND.B`, `AND.W`, and `AND.L` lifecycle: flag-live and no-flags compiler tables, register and immediate lowering, all readable source EAs, all writable destinations, aliases, special-memory routing, EA writeback, and allocator ownership.

`ANDSR` was accepted with the immediate-CCR tranche. Generic AArch64 `AND_*` and `ANDS_*` emitter APIs remain separate encoder families and are not promoted by this report. In particular, the legacy `AND_ww1f` API remains closure-unreachable. The authoritative opcode generator is `src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is deterministic generated output.

## Structural inventory

The reachable generator route is `i_AND`. It emits 156 handlers: 78 flag-live and 78 no-flags. Of these, 84 have writable memory destinations, 42 per table.

Logical lowering uses twelve reachable MIDFUNC routes:

- `jff_AND_b`, `jff_AND_w`, and `jff_AND_l`;
- `jnf_AND_b`, `jnf_AND_w`, and `jnf_AND_l`;
- the corresponding six `_imm` forms.

Register-source routes acquire source and destination through width-specific `INIT_REGS_b/w/l(d, s)` and release them through `EXIT_REGS(d, s)`. Constant register sources route to the immediate forms. Byte and word destinations retain their untouched upper lane; long destinations replace the full 32-bit lane. Flag-live lowering uses width-correct AArch64 `ANDS`, publishes N/Z, clears V/C, preserves X, and records non-inverted host carry state. No-flags lowering uses `AND` and does not change guest flags or carry metadata. Immediate byte/word paths sign-extend both operands for flag calculation and merge only the audited low lane; long immediates are materialised with `LOAD_U32`.

The generated forms cover:

- Dn and immediate sources;
- `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, absolute-long, `(d16,PC)`, and indexed-PC readable sources;
- Dn, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and absolute-long destinations;
- byte A7 postincrement/predecrement geometry; and
- normal and forced-special memory paths.

## Allocator finding and repair

Writable logical destinations fetch through a private pre-write effective address. Postincrement or predecrement may then change the architectural address register before the shared MIDFUNC allocates source/destination temporaries and `genastore()` performs the ordered write. The generated EA value was live in C++ but was not locked in the JIT allocator.

A forced S2-to-S1 collision made this deterministic for `AND.B D0,(A0)+` before repair:

```text
and_b_postinc_ea_source_collision status=FAIL pin=1 skip=2 natexec=1 interpop=1
interpreter: D0=a5a5000f D2=22222710 A0=0000a001 SR=2710
JIT:         D0=a5a500ff D2=22222718 A0=0000a001 SR=2718
```

The interpreter stored and reloaded `0x0f`; native JIT execution reloaded stale `0xff` and published the corresponding wrong N flag. This is an EA-ownership defect, not an AND arithmetic defect.

The shared OR/AND/EOR generator now locks `dsta` immediately after writable-memory destination acquisition and unlocks it only after `genastore()`. Regeneration creates 84 balanced `__logicdstealock` pairs in each family, 252 total, and none in register-destination handlers. The repaired collision rejects the attempted reuse and preserves exact native execution:

```text
and_b_postinc_ea_source_collision status=PASS pin=0 skip=3 natexec=1 interpop=1
```

A separate source-first witness forces architectural D0 toward the fetched source for `AND.B (A0)+,D0` and passes with one rejected allocation:

```text
and_b_postinc_source_dreg_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
```

The MIDFUNC operand lifecycle already owns arithmetic inputs, so no extra generator source lock was added. Exact-native `OR.B D0,(A0)+` and `EOR.B D0,(A0)+` regressions pass, including a forced-special OR route. Those two witnesses validate the shared repair but do not promote the complete OR or EOR semantic families.

## Exact-native semantic matrix

The 34-vector AND matrix begins every replay at the audited opcode and requires native execution at `pc=00001000`. It covers:

- byte, word, and long zero, negative, positive, ordinary, and self-alias results;
- narrow upper-lane preservation and full long replacement;
- register and constant/immediate routes, including zero, patterned, and high-bit immediates;
- N/Z replacement, mandatory V/C clear, and X preservation;
- three flag-dead register routes and one flag-dead memory route;
- all nine readable memory-source and seven writable memory-destination EA classes;
- postincrement, predecrement, indexed, PC-relative, absolute, and A7 byte geometry;
- six forced-special memory routes; and
- stored-data reloads plus captured SR snapshots after memory RMW operations.

Two adjacent exact-native vectors exercise the repaired OR/EOR writable-EA generator path. Focused clean-build acceptance reports 36 pass, 0 fail, and 0 infrastructure failure: 34 complete AND vectors plus those two shared-path regressions.

## Acceptance gates

```sh
B2_TEST_NAMES=<34 AND names plus 2 OR/EOR EA regressions> bash jit-test/run.sh
bash jit-test/run.sh
bash jit-test/regalloc-pressure.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
bash -n jit-test/run.sh jit-test/regalloc-pressure.sh
make -C BasiliskII/src/Unix clean
make -C BasiliskII/src/Unix -j12
sha256sum BasiliskII/src/Unix/{compemu.cpp,compstbl.cpp,comptbl.h}
git diff --check
```

Accepted evidence:

- focused exact-native AND matrix: **34/34**, zero semantic or infrastructure failures;
- adjacent shared-generator OR/EOR replay: **2/2**, zero semantic or infrastructure failures;
- combined replay from the clean binary: **36/36**;
- complete active-risky replay: **698/698**, zero semantic or infrastructure failures, score 100;
- complete allocator-pressure suite: **20/20**, including both AND cells;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build;
- generated output is byte-reproducible across clean and explicit regeneration:
  - `compemu.cpp`: `3476e73b1d78da29814d529c8493909bf00f85e7928a0e0afa0cb3e3a8f459b5`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- structural contracts require 156 generated AND handlers, twelve reachable MIDFUNC routes, all 34 exact-native vectors, 84 balanced AND memory-EA pins, 252 balanced shared logical-family pins, two adjacent exact-native regressions, and both pressure witnesses;
- deterministic 997-row closure inventory:
  - generator `audited=49`, `serviced=44`, `unreviewed=37`;
  - MIDFUNC `audited=222`, `unreachable=118`, `unreviewed=82`;
  - CSV: `11f80c0ad17985e01ce54e1722b0ad40fa59fac92245593b37d25890b1d89568`;
  - Markdown: `353db52f5922e270fb26346cd6e4fa1caa977a2dee0fbc9a794b453ce01d0e5f`;
- shell syntax, structural audit, source hygiene, and diff hygiene are clean.

The inventory next selects reachable generic emitter `AND_ww3f`; `AND_www` and `AND_xxx` follow at the same deterministic risk score.
