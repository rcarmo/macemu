# AArch64 JIT fixed-register entry-prologue boundary audit

Date: 2026-07-28

Base: `f142b6b8` (`master`, published disabled opcode-counter retirement)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_init_r_regstruct`. The boundary publishes the two fixed registers
used by every native block:

- `R_REGSTRUCT` / X28 receives the exact 64-bit address of `regs`;
- `R_MEMSTART` / X27 receives the current 64-bit value stored in
  `NATMEM_OFFSET`.

The generic `MOV_xi` and `LDR_xXi` emitters remain independently classified.

## Entry contract

The sole caller is in the shared dispatcher-entry stub. It executes after the
callee-saved register frame is established and, when configured, after the FPU
architectural state is imported into its native shadow. It executes before
`compemu_raw_jmp_pc_tag()` dispatches to a compiled block.

The raw boundary must:

1. materialise the complete host pointer `&regs` into X28;
2. materialise the complete absolute address of `NATMEM_OFFSET` into X27;
3. load the current 64-bit value from that address into X27; and
4. preserve NZCV.

Using an offset from `regs` is deliberately forbidden: the unsigned immediate
form can encode only an aligned 32,760-byte range and previously corrupted X27
when the global lay farther away.

## Native proof

`jit-test/raw-init-regstruct-conformance.sh` exact-extracts both the production
`LOAD_U64` helper and raw boundary into a native AArch64 probe. The wrapper
saves/restores callee-saved X27/X28, executes the production body, captures both
published registers and NZCV, and tests five `NATMEM_OFFSET` classes:

- zero;
- low positive 31-bit;
- exactly 4 GiB;
- arbitrary full-width payload; and
- high canonical-pattern payload.

The extracted production body emits seven words for the current process. All
five native vectors require X28 to equal the exact synthetic `regs` address,
X27 to equal the current full-width offset, and NZCV to retain alternating
hostile patterns.

## Structural acceptance

The structural gate pins the production helper/body extraction, full-width
loads, terminal `LDR X27,[X27]`, forbidden regstruct-relative materialisation,
sole caller, entry ordering around save/FPU sync/PC-tag dispatch, exact probe
metrics, bounded main-runner integration, one-row closure promotion, and
continued independent classification of `MOV_xi` and `LDR_xXi`.

## Acceptance results

Final acceptance:

- exact-extracted production body: **7/7 words**;
- native fixed-register matrix: **5/5**;
- pointer width: **64-bit** for both X28 publication and X27 value;
- NZCV preservation: **5/5** hostile patterns;
- shared-entry configured whole-root references: **3** (LOWFUNC, LENDFUNC,
  sole call), with entry ordering structurally pinned;
- complete emitter/boundary phase: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  leaving **70 emitter APIs** and **6 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `6dc4188cb85f9faf44e75d51c7ea477ef898e2f304fa903c8abe08e3e5b88452`,
  Markdown
  `4eb3fa0b297015cb2302da0efc3aa7fc6d1df79220761472bfcb224e7cce10b7`,
  and unchanged generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial reject because the probe allowed a
  five-to-nine-word range while reporting seven and the sole-caller assertion
  was file-local; corrected to require exactly seven words and the configured
  whole-root reference count of three; final re-review: **approve**.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_init_r_regstruct`
from **unreviewed** to **audited**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-init-regstruct-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
