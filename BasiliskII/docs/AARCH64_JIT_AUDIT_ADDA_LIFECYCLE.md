# AArch64 JIT ADDA lifecycle audit

## Scope

This tranche closes the reachable M68K `ADDA.W` and `ADDA.L` lifecycle:
generator `i_ADDA`, dynamic MIDFUNCs `jnf_ADDA_w` / `jnf_ADDA_l`, immediate
MIDFUNCs `jnf_ADDA_w_imm` / `jnf_ADDA_l_imm`, word sign extension, long-width
arithmetic, 32-bit address-register wrap, constant folding, dynamic sources,
all readable source EAs, address writeback, aliases, XNZVC preservation, exact
native execution, special-memory routing, and allocator ownership.

`ADD`, `ADDX`, and generic AArch64 `ADD_*` emitter APIs are separate accepted
families and are not promoted by this report. The authoritative opcode
generator is `src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is
deterministic generated output.

## Structural inventory

The reachable `i_ADDA` generator emits 52 handlers, split 26/26 between the
flag-live and no-flags compiler tables. Both tables deliberately reach the same
no-flags implementation because ADDA never changes XNZVC. The generated
surface contains 26 calls to `jnf_ADDA_w` and 26 calls to `jnf_ADDA_l`.

The four reachable MIDFUNC routes are:

- `jnf_ADDA_w` and `jnf_ADDA_w_imm`;
- `jnf_ADDA_l` and `jnf_ADDA_l_imm`.

`ADDA.W` sign-extends bit 15 before adding to the complete 32-bit destination.
Its dynamic form uses `ADD_wwwEX(..., EX_SXTH)`; its immediate form first
converts through `uae_s16` and selects positive immediate ADD, negative
immediate SUB, or an explicit signed-16 materialisation. `ADDA.L` consumes and
replaces the complete 32-bit guest lane. Both constant paths use `set_const()`
so results are masked to the architectural 32-bit address-register width.
Neither dynamic nor immediate lowering emits flag-producing arithmetic,
carry/X publication, or carry-polarity metadata.

The generated forms cover Dn, An, instruction-stream immediate, `(An)`,
`(An)+`, `-(An)`, `(d16,An)`, indexed, absolute-word, absolute-long,
`(d16,PC)`, and indexed-PC sources. The destination is always An. Normal and
forced-special memory reads are directly exercised.

## Reproduced source/writeback lifetime defect

`ADDA.W/L (An)+,An` has two ordered ownership boundaries. The memory value is
fetched before the architectural postincrement, and arithmetic then consumes
that fetched value while acquiring the already-updated An as an RMW
destination. Under forced allocator collision, the destination writeback could
reuse the fetched source's host lane before either width consumed it.

Before repair, the focused pressure witnesses entered the audited instruction
natively but produced the increment-derived value instead of the fetched
operand:

```text
adda_w_postinc_source_dst_collision status=FAIL pin=1 skip=1 natexec=1 interpop=1
INTERP A0=0000a003
JIT    A0=00000006

adda_l_postinc_source_dst_collision status=FAIL pin=1 skip=1 natexec=1 interpop=1
INTERP A0=0000a005
JIT    A0=0000000a
```

The generator now requests an ADDA-only short source pin inside `genamode()`
for aliased postincrement. That pin begins after the read and ends after An
writeback. A second dynamic-source pin begins after `genamode()` and remains
live through the width-specific ADDA MIDFUNC. The two pins are sequential, not
nested. Immediate/constant sources bypass the second pin through public
`is_const()` so immediate dispatch and full constant folding remain intact.

Regeneration creates four balanced `__adda_writebacksrclock` pairs—the word and
long aliased-postincrement routes in both compiler tables—and 52 balanced,
constant-preserving `__addasrclock` pairs around the shared MIDFUNC calls.
After rebuilding generated opcode objects, both forced collisions reject both
unsafe reuse attempts and match the interpreter:

```text
adda_w_postinc_source_dst_collision status=PASS pin=0 skip=2 natexec=1 interpop=1
adda_l_postinc_source_dst_collision status=PASS pin=0 skip=2 natexec=1 interpop=1
```

The repaired results are A0=`0x0000a003` for the word case and
A0=`0x0000a005` for the long case, with SR=`0x271f` preserved in both paths.

## Constant-fold width repair

`jnf_ADDA_w_imm` previously mutated `live.state[d].val` directly. That bypassed
the AArch64 guest-register masking enforced by `set_const()` and allowed a
folded address-register result to retain host-pointer-width carry above bit 31.
The repaired route sign-extends the 16-bit source, performs the addition, and
publishes the result through `set_const(d, (uae_u32)...)`. Focused word and long
constant-destination vectors both prove `0xffffffff + 1 == 0x00000000` in the
guest lane. Because these two cases are fully folded, they are strict JIT versus
interpreter equivalence vectors rather than false exact-native-entry claims.

## Exact-native semantic matrix

The 29-vector ADDA matrix contains 27 exact-native vectors beginning at ADDA at
`pc=00001000` and two constant-fold equivalence vectors. It covers:

- positive, negative, high-bit, large, small, and wrapping word/long operands;
- exact ADDA.W sign extension and complete ADDA.L arithmetic;
- constant and dynamic source/destination combinations;
- Dn, An, immediate, and maximum register fields;
- source/destination aliasing plus word/long postincrement and predecrement
  aliases;
- all nine readable memory EA classes, including PC-relative and indexed forms;
- normal and forced-special memory reads;
- nominal flag-live and no-flags table selection; and
- complete XNZVC preservation observed through both SR and `MOVE SR,D3`.

The focused matrix passes 29/29 with zero semantic or infrastructure failure.

## Acceptance gates

```sh
B2_TEST_NAMES=<29 ADDA names> bash jit-test/run.sh
B2_REGPRESSURE_CELLS=adda_w_postinc_source_dst_collision,adda_l_postinc_source_dst_collision \
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

Accepted evidence recorded by this tranche:

- focused ADDA matrix: **29/29**, comprising 27 exact-native and two
  constant-fold equivalence vectors, with zero semantic or infrastructure
  failures;
- focused ADDA allocator pressure: **2/2**, each with two forced allocation
  rejections and exact native/interpreter parity;
- complete active-risky replay: **827/827**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **28/28**, including both ADDA witnesses;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- structural contracts require four reachable MIDFUNC routes, 52 generated
  handlers split 26/26 across compiler tables, 26 calls per width, 52 balanced
  constant-preserving source pins, four balanced aliased-postincrement pins,
  all 29 vectors, nine readable EA classes, eleven memory vectors, two
  forced-special routes, two explicit no-flags vectors, and both pressure
  witnesses;
- generated output is byte-reproducible before clean, after clean, and after
  two explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly `i_ADDA` and the
  four directly evidenced ADDA MIDFUNC rows:
  - generator `audited=53`, `serviced=44`, `unreviewed=33`;
  - MIDFUNC `audited=262`, `unreachable=118`, `unreviewed=42`;
  - emitter API remains `audited=49`, `unreachable=91`, `unreviewed=154`;
  - CSV: `02ff05fa878e1edf569d68b845d681bc8aa15a3a913b3d03993ef0085ec15bbd`;
  - Markdown: `5de3d42ec0e709ee877ce64047d2a1b0a22f2d97d5ee60da8537f96b6c6989f4`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects `Bcc`. Whole-engine closure is not claimed.
