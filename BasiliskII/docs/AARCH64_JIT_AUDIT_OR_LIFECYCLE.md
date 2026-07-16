# AArch64 JIT OR lifecycle audit

## Scope

This tranche closes the reachable M68K `OR.B`, `OR.W`, and `OR.L` lifecycle:
flag-live and no-flags compiler tables, Dn, immediate, and readable-memory
sources, register and writable-memory destinations, aliases, special-memory
routing, EA writeback, exact native execution, and allocator ownership.

`ORSR` was accepted with the immediate-CCR tranche. Generic AArch64 `ORR_*`
and `immOP_ORR` emitter APIs remain separate encoder families and are not
promoted by this report. The authoritative opcode generator is
`src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is deterministic
generated output.

## Structural inventory

The reachable generator route is `i_OR`. It emits 156 handlers: 78 flag-live
and 78 no-flags. The generated surface reaches all twelve width-specific
logical MIDFUNC routes:

- `jff_OR_b`, `jff_OR_w`, and `jff_OR_l`;
- `jnf_OR_b`, `jnf_OR_w`, and `jnf_OR_l`;
- the corresponding six `_imm` forms.

Register-source routes acquire source and writable destination together through
width-specific `INIT_REGS_b/w/l(d, s)` and release both through
`EXIT_REGS(d, s)`. Constant sources route to the immediate forms. Byte and word
register destinations retain their untouched upper lane; long destinations
replace all 32 bits. Flag-live lowering sign-extends narrow operands, performs
OR, and uses width-correct `TST` to publish N/Z while clearing V/C. X is never
acquired or changed. No-flags lowering performs only the result operation and
does not publish guest flags or change carry-polarity metadata. Its immediate
forms preserve narrow upper lanes and retain deterministic constant folding.

The generated forms cover nine readable source EA classes and seven writable
destination EA classes:

- Dn and instruction-stream immediate sources;
- `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word,
  absolute-long, `(d16,PC)`, and indexed-PC readable sources;
- Dn, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and
  absolute-long destinations;
- byte A7 postincrement and predecrement geometry; and
- normal and forced-special memory paths.

## Writable-EA and allocator ownership

OR shares the OR/AND/EOR generator lifecycle repaired in commit `8198f939`.
A writable memory destination is fetched through a private pre-write effective
address; architectural postincrement/predecrement may occur before the MIDFUNC
consumes the fetched value and before `genastore()` performs the final ordered
write. The generator locks `dsta` after fetch and releases it only after
storage. Deterministic generation contains 84 balanced OR lock pairs, none in
register-destination handlers.

This tranche does not infer OR ownership from the accepted AND or EOR audits.
Two OR-specific pressure cells cover `OR.B (A0)+,D0` and
`OR.B D6,(A0)+`, and require exact native entry:

```text
or_b_postinc_source_dreg_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
or_b_postinc_ea_source_collision   status=PASS pin=0 skip=3 natexec=1 interpop=1
```

The first forces architectural D0 toward the already-fetched private S1 source
and proves source-before-destination acquisition. The second forces fetched RMW
value S2 toward private pre-write EA S1 and proves destination-address ownership
through flag publication and the ordered store. Both interpreter and native JIT
runs produce D0=`0xa5a500ff`, A0=`0x0000a001`, and SR=`0x2718`.

No new production correction was required: the accepted shared writable-EA
repair and existing OR MIDFUNC ownership satisfy the complete source-led
contract. One initial matrix failure was a fail-closed harness setup defect:
the predecrement source address had been placed in A0 rather than A1. Correcting
the explicit `INIT_REGS` field made both interpreter and JIT execute the
intended `OR.L -(A1),D0` case; no emulator source was changed.

## Exact-native semantic matrix

The 37-vector OR matrix begins every replay at the audited opcode at
`pc=00001000` and requires native execution. It covers:

- byte, word, and long zero, negative, and positive results;
- byte/word upper-lane preservation and full long replacement;
- all source/destination self-alias forms;
- Dn and immediate routes, including patterned and high-bit immediates;
- all six flag-live and all six no-flags MIDFUNC routes;
- N/Z replacement, mandatory V/C clear, and X preservation;
- all nine readable source and all seven writable destination EA classes;
- postincrement, predecrement, indexed, PC-relative, absolute, and A7 byte
  geometry;
- ORI and dynamic OR memory destinations;
- six forced-special memory routes; and
- stored-data reloads plus captured SR snapshots after memory operations.

The focused matrix passes 37/37 with zero semantic or infrastructure failure.

## Acceptance gates

```sh
B2_TEST_NAMES=<37 OR names> bash jit-test/run.sh
B2_REGPRESSURE_CELLS=or_b_postinc_source_dreg_collision,or_b_postinc_ea_source_collision \
  bash jit-test/regalloc-pressure.sh
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

- focused exact-native OR matrix before and after the clean build: **37/37**,
  zero semantic or infrastructure failures;
- complete active-risky replay: **761/761**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **24/24**, including both OR witnesses;
- focused OR allocator pressure: **2/2**, with one and three forced allocation
  rejections respectively;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- structural contracts require 156 generated OR handlers split 78/78 across
  flag-live/no-flags tables, twelve reachable MIDFUNC routes, all 37 exact
  vectors, nine readable and seven writable EA classes, 21 memory vectors, 84
  balanced writable-EA pins, six forced-special routes, seven explicit
  no-flags vectors, and both OR pressure witnesses;
- generated output is byte-reproducible before clean, after clean, and after
  two explicit regenerations:
  - `compemu.cpp`: `3476e73b1d78da29814d529c8493909bf00f85e7928a0e0afa0cb3e3a8f459b5`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory:
  - generator `audited=51`, `serviced=44`, `unreviewed=35`;
  - MIDFUNC `audited=246`, `unreachable=118`, `unreviewed=58`;
  - emitter API remains `audited=42`, `unreachable=91`, `unreviewed=161`;
  - CSV: `4ea824575572eb7ada3dda64e90b0df22ace33f5be52dacc04b61fb7431414e9`;
  - Markdown: `e73a7005c417176972a8dc3b3194c106489d6fa8a32ffb8313be11cc1de8780b`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects reachable `SUB` lifecycle rows. Generic `ORR_*`
emitters remain separate. Whole-engine closure is not claimed.
