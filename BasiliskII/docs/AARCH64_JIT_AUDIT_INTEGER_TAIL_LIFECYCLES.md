# AArch64 JIT integer-tail lifecycle audit

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `21084803`

## Scope

This bounded checkpoint closes the final six configured, reachable, unreviewed
ordinary integer generator rows:

- `i_MULS` and `i_MULU`;
- `i_NOT`;
- `i_SUBA`;
- `i_SWAP`;
- `i_TST`.

It also closes the eight directly connected reachable MIDFUNC rows:
`jnf_MULS`, `jnf_MULU`, and `jff_TST_{b,w,l}[_imm]`.

The namesake NOT, SUBA, and SWAP MIDFUNC implementations are not selected by
the configured generator. They remain unreachable. Generic EOR, SUB, rotate,
multiply, TST, memory, and allocator primitives retain their independently
derived status.

## Configured provider surface

The deterministic generated source contains the following complete provider
counts, evenly divided between flag-live and no-flags compiler tables:

| Family | Total | ff | nf |
|---|---:|---:|---:|
| MULS | 22 | 11 | 11 |
| MULU | 22 | 11 | 11 |
| NOT | 48 | 24 | 24 |
| SUBA | 52 | 26 | 26 |
| SWAP | 2 | 1 | 1 |
| TST | 70 | 35 | 35 |

MULS/MULU use their no-flags word MIDFUNC for exact signed/unsigned 16-by-16
multiplication, then publish long logical flags through the shared generator
path. TST reaches its six flag-setting dynamic/immediate MIDFUNCs through the
configured `test_{b,w,l}_rr` compatibility mapping. No-flags TST providers
retain EA reads and address-register writeback but emit no flag operation.
NOT, SUBA, and SWAP are composed directly by the generator and do not call
their retained namesake MIDFUNCs.

## Reproduced lifetime defects

Two forced allocator collisions reproduced source bugs before repair.

### NOT pre-write effective address

Memory NOT computed a private effective address, then allocated a private
result and published flags without retaining that address. For
`NOT.B d16(A0)`, forced S3-to-S1 reuse stole the EA mapping: memory remained
unchanged and the wrong result/flags escaped.

The generator now locks every non-Dn NOT `srca` after fetch and releases it only
after `genastore`. Regeneration produces 42 balanced lock/unlock pairs: 21
memory forms in each compiler table.

### SUBA widened source

SUBA widens its source into a private scratch before acquiring the address
register destination. For `SUBA.W (A0)+,A0`, forced destination reuse could
steal that widened source after architectural postincrement and reduce the
subtraction to a clobbered value.

The generator now locks `tmp` after widening and releases it only after
`sub_l(dst,tmp)`. Regeneration produces 52 balanced lock/unlock pairs, one in
every configured SUBA provider.

Permanent allocator cells prove the repaired ownership:

```text
REGPRESSURE cell=not_b_d16_result_ea_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
REGPRESSURE cell=suba_w_postinc_source_dst_collision status=PASS pin=0 skip=2 natexec=1 interpop=1
REGPRESSURE_SUMMARY selected=2 pass=2 fail=0
```

## Exact-native semantic matrix

`bun jit-test/integer-tail-native-matrix.ts` runs 32 interpreter/JIT pairs.
Every JIT case uses strict full-JIT, forced RAM L2, two-pass replay, exact native
entry at `pc=00001000`, and fail-closed native/summary checks. Memory-mutating
cases reset replay bytes before the second pass.

The matrix covers:

- signed MULS and unsigned MULU, zero, extrema, same-register aliases, and
  displacement memory operands;
- NOT byte/word/long lane semantics, explicit negative and zero results, D7
  maximum field, postincrement memory, computed EA, logical N/Z/V/C, X
  preservation, and the forced EA collision;
- SUBA.W sign extension, SUBA.L wrap, Dn/immediate operands, word/long
  `(An)+,An` aliases, CCR preservation, and the forced widened-source collision;
- SWAP halves, maximum D7, explicit negative/positive/zero logical flags, and
  no-flags table execution;
- TST byte/word/long dynamic and immediate routes, register/memory operands,
  N/Z/V/C with X preservation, register no-flags execution, and a no-flags
  postincrement-memory witness that proves the read and An writeback remain.

Accepted focused result:

```text
INTEGER_TAIL_NATIVE_MATRIX pass=32 fail=0 total=32
```

## Closure decision

Promote exactly fourteen rows from **unreviewed** to **audited**:

- generators: `i_MULS`, `i_MULU`, `i_NOT`, `i_SUBA`, `i_SWAP`, `i_TST`;
- MIDFUNCs: `jnf_MULS`, `jnf_MULU`, `jff_TST_b`, `jff_TST_w`, `jff_TST_l`,
  `jff_TST_b_imm`, `jff_TST_w_imm`, `jff_TST_l_imm`.

No emitter API, raw boundary, runtime boundary, or unreachable namesake MIDFUNC
is promoted. Whole-engine closure is not claimed.

## Acceptance gates

Required pre-publication gates:

```sh
bun jit-test/integer-tail-native-matrix.ts
bash jit-test/regalloc-pressure.sh --cells not_b_d16_result_ea_collision,suba_w_postinc_source_dst_collision
bash jit-test/run.sh
bash jit-test/regalloc-pressure.sh
bash jit-test/strict-full-jit.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
make -C BasiliskII/src/Unix clean
make -C BasiliskII/src/Unix -j12
sha256sum BasiliskII/src/Unix/{compemu.cpp,compstbl.cpp,comptbl.h}
bash -n jit-test/*.sh
git diff --check
```

Accepted evidence:

- focused strict-native matrix: **32/32**, both before and after the clean build;
- focused allocator witnesses: **2/2**, with `skip=1` for NOT and `skip=2` for
  SUBA plus exact native/interpreter parity;
- complete active-risky replay: **904/904**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, score 100;
- complete allocator-pressure regression: **33/33**;
- strict policy gate: ordinary allocation fallback plus expected aborts for
  allocation, optlev-0, opcode fallback, and verifier-reference paths;
- clean configured AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced an
  AArch64 ELF;
- generated outputs are byte-identical across clean build and two explicit
  serial regeneration passes:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic closure regeneration remains **998 rows** and changes exactly
  the fourteen listed rows:
  - generator: 75 audited / 44 serviced / 11 unreachable / **0 unreviewed**;
  - MIDFUNC: 275 audited / 119 unreachable / 28 unreviewed;
  - emitter API unchanged at 64 audited / 103 unreachable / 127 unreviewed;
  - raw boundary unchanged at 30 audited / 18 unreachable / 35 unreviewed;
  - runtime boundary unchanged at 40 serviced / 29 unreachable;
  - CSV: `23d856159dd42e407385a5797b5a7f8756dd2f8a975e6cd03b63e2d7ecebb43e`;
  - Markdown: `79b7a5bc521d56cfacebb93f46d0ec88a88c52ca8231ce2baf000ea3636808ba`;
- structural audit, shell syntax, Bun transpilation, source hygiene, and
  `git diff --check` pass;
- initial independent review found three evidence gaps; all were repaired with
  explicit NOT/SWAP zero cases, no-flags TST postincrement coverage, and twelve
  fail-closed namesake negatives. Final adjudication returned **APPROVE**.

The next closure batch is selected mechanically from the remaining 190
unreviewed lower-layer rows. Whole-engine closure is not claimed.
