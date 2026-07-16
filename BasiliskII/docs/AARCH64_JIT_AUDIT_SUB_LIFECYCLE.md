# AArch64 JIT SUB lifecycle audit

## Scope

This tranche closes the reachable M68K `SUB.B`, `SUB.W`, and `SUB.L`
lifecycle: flag-live and no-flags compiler tables, register and immediate
lowering, all readable source EAs, all writable destinations, aliases,
special-memory routing, EA writeback, exact native execution, borrow/X
publication, and allocator ownership.

`SUBA`, `SUBX`, and generic AArch64 `SUB_*` / `SUBS_*` emitter APIs are
separate families and are not promoted by this report. `SUBX` was accepted with
the ADDX/SUBX and immediate-CCR tranche. The authoritative opcode generator is
`src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is deterministic
generated output.

## Structural inventory

The reachable generator route is `i_SUB`. It emits 208 handlers: 104 flag-live
and 104 no-flags. Of these, 126 have writable memory destinations, split 63/63
between the two compiler tables. The generated surface reaches twelve
width-specific arithmetic routes:

- `jff_SUB_b`, `jff_SUB_w`, and `jff_SUB_l`;
- `jnf_SUB_b`, `jnf_SUB_w`, and `jnf_SUB_l`;
- the corresponding six `_imm` forms.

Register-source routes acquire source and writable destination together through
width-specific `INIT_REGS_b/w/l(d, s)` and release both through
`EXIT_REGS(d, s)`. Constants route to the immediate forms, whose no-flags paths
retain deterministic constant folding. Byte and word destinations retain their
untouched upper lane; long destinations replace all 32 bits. Flag-live lowering
uses width-correct AArch64 `SUBS`, marks physical C as inverted relative to the
M68K borrow convention, and publishes X through `DUPLICACTE_CARRY`. No-flags
lowering changes only data and publishes no NZVCX state or carry-polarity
metadata.

The generated forms cover nine readable source EA classes and seven writable
destination EA classes:

- Dn and instruction-stream immediate sources;
- `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word,
  absolute-long, `(d16,PC)`, and indexed-PC readable sources;
- Dn, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and
  absolute-long destinations;
- byte A7 postincrement and predecrement geometry; and
- normal and forced-special memory paths.

## Reproduced destination-EA lifetime defect

A writable-memory SUB fetches the destination through a private pre-write
effective address. Architectural postincrement or predecrement may update the
address register before the arithmetic MIDFUNC allocates operands, publishes X,
and returns to `genastore()`. That private EA cannot then be reconstructed from
the architectural base.

Before repair, the generated 208-handler SUB surface contained no destination
EA pins. The exact-native pressure cell `sub_b_postinc_x_ea_collision` forced
FLAGX toward the unowned pre-write EA for `SUB.B D0,(A0)+`. Both paths entered
the audited opcode natively, but the JIT reloaded stale data and published the
wrong CCR:

```text
sub_b_postinc_x_ea_collision status=FAIL pin=2 skip=0 natexec=1 interpop=1
INTERP D0=a5a500ff A0=0000a001 SR=2718
JIT    D0=a5a50000 A0=0000a001 SR=2714
```

The source-first control `sub_b_postinc_source_dreg_collision` passed before the
repair with `skip=1`, isolating the defect to writable destination-EA ownership
rather than source handling.

The generator now pins `dsta` immediately after destination acquisition and
releases it only after `genastore()`. Regeneration creates 126 balanced
`__subdstealock` lock/unlock pairs, one for every memory-destination handler,
and none for Dn destinations. It adds no redundant source lock: MIDFUNC
`INIT_REGS` / `EXIT_REGS` already owns the arithmetic operands.

After rebuilding generated opcode objects, both focused pressure witnesses pass
with exact native entry:

```text
sub_b_postinc_source_dreg_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
sub_b_postinc_x_ea_collision        status=PASS pin=0 skip=2 natexec=1 interpop=1
```

The repaired collision produces D0=`0xa5a500ff`, A0=`0x0000a001`, and
SR=`0x2718` in both interpreter and JIT.

## Exact-native semantic matrix

The 37-vector SUB matrix begins every replay at the audited opcode at
`pc=00001000` and requires native execution. It covers:

- byte, word, and long zero, negative, signed-overflow, unsigned-borrow, and
  ordinary results;
- byte/word upper-lane preservation and full long replacement;
- all source/destination self-alias forms;
- Dn and immediate routes, including patterned, large, high-bit, and negative
  immediates;
- all six flag-live and all six no-flags MIDFUNC routes;
- N/Z/V/C replacement and width-correct X/borrow publication;
- all nine readable source and all seven writable destination EA classes;
- postincrement, predecrement, indexed, PC-relative, absolute, and A7 byte
  geometry;
- SUBI and dynamic SUB memory destinations;
- six forced-special memory routes; and
- stored-data reloads plus captured SR snapshots after memory operations.

The focused matrix passes 37/37 with zero semantic or infrastructure failure.

## Acceptance gates

```sh
B2_TEST_NAMES=<37 SUB names> bash jit-test/run.sh
B2_REGPRESSURE_CELLS=sub_b_postinc_source_dreg_collision,sub_b_postinc_x_ea_collision \
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

- focused exact-native SUB matrix: **37/37**, zero semantic or infrastructure
  failures;
- complete active-risky replay: **798/798**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **26/26**, including both SUB witnesses;
- focused SUB allocator pressure: **2/2**, with one and two forced allocation
  rejections respectively;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- structural contracts require 208 generated SUB handlers split 104/104 across
  flag-live/no-flags tables, twelve reachable MIDFUNC routes, all 37 exact
  vectors, nine readable and seven writable EA classes, 21 memory vectors, 126
  balanced writable-EA pins, zero redundant generator source pins, six
  forced-special routes, seven explicit no-flags vectors, and both SUB pressure
  witnesses;
- generated output is byte-reproducible before clean, after clean, and after
  two explicit regenerations:
  - `compemu.cpp`: `17e9d3510ceb4e479d6e64520b90433278f6a15cfcf1c7d5daf1d3f36a4d12e0`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly `i_SUB` and the
  twelve directly evidenced SUB MIDFUNC rows:
  - generator `audited=52`, `serviced=44`, `unreviewed=34`;
  - MIDFUNC `audited=258`, `unreachable=118`, `unreviewed=46`;
  - emitter API remains `audited=42`, `unreachable=91`, `unreviewed=161`;
  - CSV: `51aab7025ad6eedba68eaa5d1a6620d34b392e6f63bea2951c95e07ef239487c`;
  - Markdown: `d1b01f1a3cd2292b756a224371ae006a153a6b77a344ef7b3d36b4b557612be3`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects reachable generic `SUB_wwi`. Generic `SUB_*` and
`SUBS_*` emitters remain separate. Whole-engine closure is not claimed.
