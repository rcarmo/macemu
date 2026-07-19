# AArch64 JIT configured MMU generator reachability audit

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `637d85df`

## Scope and decision

This graph-only checkpoint classifies eleven generator switch labels that have no provider in the configured BasiliskII Unix AArch64 build:

- `i_MMUOP030`;
- `i_PFLUSHN`, `i_PFLUSH`, `i_PFLUSHAN`, `i_PFLUSHA`;
- `i_PLPAR`, `i_PLPAW`, `i_PTESTR`, `i_PTESTW`;
- `i_LPSTOP`;
- `i_MMUOP`.

All eleven move from **unreviewed** to **unreachable**. This is not a semantic audit and does not implement or defer a reachable runtime path.

## Configured-root proof

The ten UAE 68030/68040 labels are inside inactive `#ifdef UAE` source in `uae_cpu_2026/compiler/gencomp.c`. The configured Unix translation unit does not contain those labels.

`i_MMUOP` remains visible under the historical `WINUAE_ARANYM` generator branch, but the configured BasiliskII `cpudefs.cpp` has no opcode definition for that mnemonic. Consequently generation produces no `MMUOP` compiler function or `compstbl.cpp` registration slot.

Fail-closed tooling requires all of the following for every classified row:

- the raw authoritative generator label still exists, so disappearance or renaming is detected;
- no configured `compemu.cpp` provider names the mnemonic;
- no configured `compstbl.cpp` slot names the mnemonic;
- no configured `cpudefs.cpp` definition names the mnemonic;
- the ten UAE-only labels remain absent from the preprocessed configured generator source;
- `i_MMUOP` remains present in configured generator source but cannot become reachable without gaining a configured opcode/provider, which fails the inventory gate.

The stale `uae_cpu_2026/compiler/compstbl_arm.cpp` mirror is not a configured provider and is deliberately excluded, as established by the control/address lifecycle audit.

## Build boundary

The active BasiliskII build uses direct addressing and does not define `FULLMMU` or `UAE`. Implementing FULLMMU/MMU behavior is explicitly outside this audit. NeXT MMU integration remains owned by the Previous project.

## Closure boundary

This report promotes no generator to audited or serviced and no MIDFUNC,
emitter, raw, or runtime row. If any configured opcode definition, generated
body, or table slot appears later, deterministic inventory generation fails
until the new live path receives its own semantic classification.

Accepted evidence:

- exact classification delta: **11/11** generator rows, unreviewed ->
  unreachable;
- deterministic inventory remains **998 rows** and now reports generator
  `audited=69`, `serviced=44`, `unreachable=11`, `unreviewed=6`;
- closure hashes are:
  - CSV: `892a7a28cc0f4ad91b5a0c2e2b09a6a48fb14b8dc52c1a789841f855012a1f1b`;
  - Markdown: `4d7a34a24ecfc5c061579ac1900d134ffb95a85a3c82d86719e2e43b525c4db8`;
- structural audit, Bun transpilation, shell syntax, and `git diff --check`
  pass;
- clean configured AArch64 build passes and executable generated sources remain
  byte-identical to the published runtime checkpoint:
  - `compemu.cpp`: `1bff4ac587e70e6d9054c86bbdf411012b38607ca6b2588418095eec24b66380`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- the unchanged published runtime baseline is focused control/address **15/15**,
  complete corpus **904/904**, allocator pressure **31/31**, and strict policy
  pass; no runtime campaign is duplicated for this non-executable accounting
  change;
- bounded independent review returns **APPROVE**, confirming that live adjacent
  cache services remain distinct and no FULLMMU implementation is implied.

Whole-engine closure is not claimed.
