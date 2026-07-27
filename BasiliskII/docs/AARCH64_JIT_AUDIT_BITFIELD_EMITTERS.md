# AArch64 JIT unsigned bitfield emitter audit

Date: 2026-07-27

Base: `742e6e6a` (`master`, published ASR emitter closure)

## Scope

This tranche audits the eight reachable unsigned insert/extract encoders
selected by `BFI_wwii`:

- `BFI_wwii`, `BFI_xxii`;
- `BFXIL_wwii`, `BFXIL_xxii`;
- `UBFIZ_wwii`, `UBFIZ_xxii`;
- `UBFX_wwii`, `UBFX_xxii`.

The signed `SBFIZ_wwii`, `SBFIZ_xxii`, `SBFX_wwii`, and `SBFX_xxii` definitions
remain configured-unreachable. No production repair is required.

## Configured and raw census

| API | Configured references | Raw calls |
|---|---:|---:|
| `BFI_wwii` | 135 | 167 |
| `BFI_xxii` | 24 | 65 |
| `BFXIL_wwii` | 1 | 5 |
| `BFXIL_xxii` | 26 | 29 |
| `UBFIZ_wwii` | 3 | 3 |
| `UBFIZ_xxii` | 26 | 26 |
| `UBFX_wwii` | 11 | 44 |
| `UBFX_xxii` | 25 | 38 |
| **Total** | **251** | **377** |

The larger raw surface comes from retained but configured-unreachable MIDFUNC
and compatibility bodies. Inventory promotion follows configured preprocessed
roots; structural acceptance locks both per-API lists independently.

## Encoding algebra

All eight APIs use UBFM/BFM encoding aliases with legal field domain:

```text
1 <= width <= bits - lsb
0 <= lsb < bits
bits in {32,64}
```

Insert-at-zero forms (`BFI`, `UBFIZ`) encode:

```text
immr = (-lsb) mod bits
imms = width - 1
```

Extract-low forms (`BFXIL`, `UBFX`) encode:

```text
immr = lsb
imms = lsb + width - 1
```

BFI/BFXIL preserve destination bits outside the selected field. UBFIZ/UBFX
zero all result bits outside the field. W forms truncate/zero-extend at 32 bits;
X forms retain full 64-bit width. None changes NZCV.

## Exhaustive direct conformance

`jit-test/emitter-bitfield-conformance.cpp` includes the production header and
generates one six-instruction native function for every legal field tuple:

- 528 legal W tuples per API;
- 2,080 legal X tuples per API;
- four API families;
- **10,432 exhaustive legal encodings**.

Every emitted word is compared against an independently constructed opcode and
field expression before execution. All functions are placed in one shared RW
mapping, switched once to RX, instruction-cache flushed, then executed with
distinct destination/source operands. The result is checked against an
independent insert/extract oracle and hostile NZCV must be preserved.

An additional 24 same-register alias functions cover field positions
`(0,1)`, `(bits/2,bits/2)`, and `(bits-1,1)` for each API/width. Sixteen exact
assembler anchors cover ordinary/max-register and last-bit fields:

```text
BFI W/X     33010149 b3410149
BFXIL W/X   331f7d49 b37ffd49
UBFIZ W/X   53010149 d3410149
UBFX W/X    531f7d49 d37ffd49
```

Each class also has a register-31 companion anchor.

Result:

```text
METRIC emitter_bitfield_apis=8
METRIC emitter_bitfield_anchor_words=16
METRIC emitter_bitfield_exhaustive_encodings=10432
METRIC emitter_bitfield_native_vectors=10456
METRIC emitter_bitfield_alias_vectors=24
METRIC emitter_bitfield_preserves_nzcv=1
```

The complete emitter phase passes with this bounded exhaustive suite installed
after ASR and before previously accepted semantic-family suites.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- loss of any reachable W/X definition;
- configured per-API census drift from the eight-entry 251-reference list;
- raw per-API drift from the eight-entry 377-call list;
- loss of independent encoding/result/mask formulas;
- loss of the complete legal `(lsb,width)` loops;
- loss of 16 assembler anchors, 10,432 exhaustive encodings, 10,456 native
  executions, 24 aliases, or NZCV preservation;
- omission of the bounded suite from the complete emitter phase;
- unexpected reachability of any SBFIZ/SBFX form.

## Acceptance results

The accepted clean-source epoch passes:

- direct bitfield conformance: **16 anchors + 10,432 exhaustive legal encodings
  + 10,456 native executions**;
- complete emitter phase: all 29 bounded suites pass;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated inventory/source hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: **APPROVE**.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
80a868bd76aa917fb081df9915bcf8ab5ab8bc3e8c1ec454fe6c0c83301e1378  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
46b14af21b26f1ea33e5a585163be42c3694046bfefbf42992417f90805f5fe7  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly the eight listed unsigned APIs from
`unreviewed` to `audited`. The four signed forms remain unreachable.

After this tranche, **107 emitter APIs and 17 raw boundaries remain
unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-bitfield-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
