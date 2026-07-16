# AArch64 JIT EOR lifecycle audit

## Scope

This tranche closes the reachable M68K `EOR.B`, `EOR.W`, and `EOR.L`
lifecycle: flag-live and no-flags compiler tables, Dn and immediate sources,
register and writable-memory destinations, aliases, special-memory routing, EA
writeback, exact native execution, and allocator ownership.

`EORSR` was accepted with the immediate-CCR tranche. Generic AArch64 `EOR_*`
and `immOP_EOR` emitter APIs remain separate encoder families and are not
promoted by this report. In particular, `EOR_www`, `EOR_wwwLSLi`, `EOR_xxbit`,
`EOR_xxCflag`, and `immOP_EOR` remain unreviewed, while the source-unreachable
`EOR_xxx` and `EOR_xxxLSLi` remain unreachable. The authoritative opcode
generator is `src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is
deterministic generated output.

## Structural inventory

The reachable generator route is `i_EOR`. It emits 96 handlers: 48 flag-live
and 48 no-flags. Of these, 84 have writable memory destinations, 42 per table;
the remaining twelve are register destinations. Every generated handler has
one width-specific logical route. Narrow no-flags handlers may select either
`xor_b`/`xor_w` or a mutually exclusive `kill_rodent()` `xor_l` optimisation;
long handlers use `xor_l`.

Logical lowering uses twelve reachable MIDFUNC routes:

- `jff_EOR_b`, `jff_EOR_w`, and `jff_EOR_l`;
- `jnf_EOR_b`, `jnf_EOR_w`, and `jnf_EOR_l`;
- the corresponding six `_imm` forms.

Register-source routes acquire source before the writable destination through
width-specific `INIT_REGS_b/w/l(d, s)` and release both through
`EXIT_REGS(d, s)`. Constant Dn sources route to the immediate forms. Byte and
word register destinations retain their untouched upper lane; long
destinations replace all 32 bits. Flag-live lowering sign-extends narrow
operands, performs EOR, and uses width-correct `TST` to publish N/Z while
clearing V/C. X is never acquired or changed. No-flags lowering performs only
the result operation and does not change guest flags or carry-polarity
metadata. Long no-flags immediates retain deterministic constant folding.

The generated forms cover:

- Dn and instruction-stream immediate sources;
- Dn, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, and
  absolute-long destinations;
- byte A7 postincrement and predecrement geometry; and
- normal and forced-special memory paths.

No readable-memory source class is missing: classic M68K EOR permits only Dn or
immediate sources. EORI uses the same destination set as the dynamic family.

## Writable-EA and allocator ownership

EOR shares the OR/AND/EOR generator lifecycle repaired in commit `8198f939`.
A writable memory destination is fetched through a private pre-write effective
address; architectural postincrement/predecrement may occur before the
MIDFUNC consumes the fetched value and before `genastore()` performs the final
ordered write. The generator locks `dsta` after fetch and releases it only
after storage. Deterministic regeneration contains 84 balanced EOR lock pairs,
none in register-destination handlers.

This tranche does not infer EOR ownership from the earlier AND acceptance. Two
EOR-specific pressure cells use `EOR.B D6,(A0)+` and require exact native entry:

```text
eor_b_postinc_source_dest_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
eor_b_postinc_ea_dest_collision     status=PASS pin=0 skip=3 natexec=1 interpop=1
```

The first forces fetched S2 toward the still-live D6 source and proves
source-before-RMW acquisition. The second forces S2 toward private pre-write S1
and proves EA ownership through flag publication and the ordered store. Both
interpreter and native JIT runs produce byte `0xf0`, A0=`0x0000a001`, and
SR=`0x2718`.

No new production correction was required: the accepted shared EA repair and
existing EOR MIDFUNC ownership satisfy the complete source-led contract.

## Exact-native semantic matrix

The 28-vector EOR matrix begins every replay at the audited opcode at
`pc=00001000` and requires native execution. It covers:

- byte, word, and long zero, negative, and positive results;
- byte/word upper-lane preservation and full long replacement;
- all source/destination self-alias forms;
- Dn and immediate routes, including patterned and high-bit immediates;
- all six flag-live and all six no-flags MIDFUNC routes;
- N/Z replacement, mandatory V/C clear, and X preservation;
- all seven writable memory-destination EA classes;
- postincrement, predecrement, indexed, absolute, and A7 byte geometry;
- EORI to memory and dynamic EOR to memory;
- three forced-special memory routes; and
- stored-data reloads plus captured SR snapshots after memory RMW operations.

The focused matrix passes 28/28 with zero semantic or infrastructure failure.
An adjacent OR postincrement vector remains independently active for the
shared generator path, but is not part of the EOR closure count and does not
promote OR.

## Acceptance gates

```sh
B2_TEST_NAMES=<28 EOR names> bash jit-test/run.sh
B2_REGPRESSURE_CELLS=eor_b_postinc_source_dest_collision,eor_b_postinc_ea_dest_collision \
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

- focused exact-native EOR matrix before and after the clean build: **28/28**,
  zero semantic or infrastructure failures;
- complete active-risky replay: **725/725**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **22/22**, including both EOR witnesses;
- focused EOR allocator pressure: **2/2**, with one and three forced allocation
  rejections respectively;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after
  explicit regeneration:
  - `compemu.cpp`: `3476e73b1d78da29814d529c8493909bf00f85e7928a0e0afa0cb3e3a8f459b5`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- structural contracts require 96 generated EOR handlers split 48/48 across
  flag-live/no-flags tables, twelve reachable MIDFUNC routes, all 28 exact
  vectors, seven writable EA classes, twelve memory vectors, 84 balanced EOR
  EA pins, three forced-special routes, seven explicit no-flags vectors, and
  both EOR pressure witnesses;
- deterministic 997-row closure inventory:
  - generator `audited=50`, `serviced=44`, `unreviewed=36`;
  - MIDFUNC `audited=234`, `unreachable=118`, `unreviewed=70`;
  - emitter API remains `audited=37`, `unreachable=91`, `unreviewed=166`;
  - CSV: `130c573401bbfc07a9da279de4b28a497cc520ad5606a1a307d3f443fad2e0ba`;
  - Markdown: `c08cb9c5e08994638845b7db8afde6baf530654f66a4ab63e517a6cea8a863d2`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects reachable generic emitter `EOR_www`; the adjacent
EOR emitter APIs remain separate. Whole-engine closure is not claimed.
