# AArch64 JIT control/address generator lifecycle audit

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `ffc845e3`

## Scope

This tranche audits nine configured native generator rows that share effective-address construction, stack mutation, dynamic PC publication, block exits, and integer-CCR preservation:

- `i_NOP`;
- `i_RTD`;
- `i_LINK` and `i_UNLK`;
- `i_RTR`;
- `i_JSR` and `i_JMP`;
- `i_LEA` and `i_PEA`.

It does not promote `i_RTS` or `i_BSR`, which remain owned by their registered semantic-service contracts. It also does not promote `get_n_addr_jmp`, generic memory primitives, allocator APIs, branch emitters, or retained compatibility helpers.

The authoritative configured providers are `BasiliskII/src/Unix/compemu.cpp` and `compstbl.cpp`, generated from the current Unix `cpudefs.cpp`/`readcpu` epoch. The source-tree mirror `uae_cpu_2026/compiler/compstbl_arm.cpp` is not the active registration table and is not used as reachability evidence. The retained `jit_op_rtr` compatibility helper has no configured caller.

## Defects found and repaired

1. `LINK A7,#disp` used `SP_REG` as both the predecremented stack address and pushed frame value. Under native lowering, `writelong_clobber(SP_REG,src,...)` could therefore consume an aliased address/data virtual register and corrupt the frame. The generator now copies the architecturally selected post-predecrement value into a distinct scratch before the store.
2. `UNLK A7` read the popped longword into `SP_REG`, then added four to that same aliased register before the final An store. The JIT produced `0x0000a004` where the interpreter produced the architecturally ordered final value `0x0000a000`. The popped value now has a distinct scratch; SP postincrement occurs before the final An write, so the restored value wins the alias.
3. `JSR (A7)` left its target as the live A7 virtual register while pushing the return address. Native execution then resolved the target from the already-decremented SP, corrupting control flow and flags. Every JSR addressing form now snapshots and locks the computed target before stack mutation, and unlocks it after `regs.pc`, `PC_P`, and `pc_oldp` publication.

The pre-fix exact-native witnesses reproduced all three failures. No source change was needed for NOP, RTD, RTR, JMP, LEA, or PEA.

## Runtime evidence

`bun jit-test/control-address-native-matrix.ts` is fail-closed and runs fifteen interpreter/JIT pairs. Every JIT case uses forced RAM L2, strict full-JIT, two replay passes, and exact `NATEXEC pc=00001000` attribution.

The matrix covers:

- NOP with full `XNZVC` preservation;
- LEA `(A0)` and PC-indexed forms, including A5 destination and maximum D7 index field;
- PEA A7 source snapshot and exact stack restoration;
- LINK.W/L A7 alias ordering, signed displacement, pushed value, and final frame SP;
- UNLK A7 and ordinary A5 forms, popped value, postincrement, and alias winner;
- RTD positive and negative signed stack deltas with dynamic return PC;
- RTR stacked CCR plus dynamic PC and exact high-SR preservation;
- JSR `(A7)` and `d16(A7)` target snapshots, return push/pop, dynamic target execution, and CCR preservation;
- JMP `(A7)` and PC-indexed target forms with unchanged address register and CCR.

Accepted focused result:

```text
CONTROL_ADDRESS_NATIVE_MATRIX pass=15 fail=0 total=15
```

## Structural contracts

The generated configured provider census is exact and evenly split between flag-live and no-flags tables:

| Family | Total | ff | nf |
|---|---:|---:|---:|
| NOP | 2 | 1 | 1 |
| RTD | 2 | 1 | 1 |
| LINK.W/L | 4 | 2 | 2 |
| UNLK | 2 | 1 | 1 |
| RTR | 2 | 1 | 1 |
| JSR (seven legal EAs) | 14 | 7 | 7 |
| JMP (seven legal EAs) | 14 | 7 | 7 |
| LEA (seven legal EAs) | 14 | 7 | 7 |
| PEA (seven legal EAs) | 14 | 7 | 7 |

The structural gate pins:

- LINK address/data separation before `writelong_clobber`;
- UNLK popped-value separation and postincrement-before-final-write ordering;
- JSR target copy/lock before SP decrement and unlock only after PC publication;
- dynamic control instructions as block exits;
- `preserve_flags_before_nzcv_clobber()` on JSR/JMP;
- exact generated provider counts and the complete fifteen-case strict-native matrix inventory.

## Closure decision

Promote exactly these generator rows from **unreviewed** to **audited**:

- `i_NOP`, `i_RTD`, `i_LINK`, `i_UNLK`, `i_RTR`;
- `i_JSR`, `i_JMP`, `i_LEA`, `i_PEA`.

No MIDFUNC, emitter API, raw boundary, or runtime boundary row is promoted by this report. Whole-engine closure is not claimed.

## Acceptance gates

Accepted pre-publication evidence:

- focused lifecycle matrix: **15/15 exact-native** after the clean build;
- complete active-risky corpus: **904/904**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, score 100;
- complete allocator-pressure regression matrix: **31/31**. This is an
  integration gate; direct LINK/UNLK/JSR alias ownership is proved by the
  focused failing-then-passing witnesses rather than an invented generic cell;
- strict full-JIT policy: ordinary allocation fallback plus expected aborts for
  allocation, optlev-0, opcode-fallback, and verifier-reference paths;
- clean configured AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced an
  AArch64 ELF, and generated outputs were byte-identical across the clean epoch:
  - `compemu.cpp`: `1bff4ac587e70e6d9054c86bbdf411012b38607ca6b2588418095eec24b66380`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic closure regeneration retained **998 rows** and changed exactly
  the nine generator rows listed above. Two serial post-clean generations were
  byte-identical:
  - CSV: `69713819f90d85553267d91a4de117d59f350efb61cd2f78d44376d65031257c`;
  - Markdown: `e385ab90e599dcb17467a6d0509983a5742341b4efc8c59c198837865404c75e`;
- structural audit reports nine generators and fifteen exact-native vectors;
- shell syntax, Bun transpilation, source hygiene, and `git diff --check` pass;
- bounded independent review returned **APPROVE** with no blocker. Its one
  accepted tightening explicitly pins JSR's `isjump` block-edge contract;
  indexed-JSR and stronger NATEXEC-count suggestions remain nonblocking because
  all seven generated EAs share one pinned source lifecycle and exact provider
  census.
