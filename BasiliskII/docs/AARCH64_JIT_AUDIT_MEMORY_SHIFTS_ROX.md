# AArch64 JIT fixed-count memory shift and memory ROX audit

Date: 2026-07-14

Branch: `structural-audit`

Base: `3db1965c` (register-count `ROL`/`ROR` family accepted)

## Scope

This closure tranche audits the residual word-memory forms of the shift/rotate
family rather than another register-count subset:

- fixed-count memory `ASLW`, `ASRW`, `LSLW`, and `LSRW`;
- flag-live and no-flags generated wrappers for every legal memory EA;
- N/Z/V/C/X publication and memory read/modify/write ordering;
- memory `ROXLW` and `ROXRW` ownership of the architectural X register;
- fixed-displacement carry publication in the adjacent register `ROXR` helpers;
- exact-PC native replay, replayed memory state, and allocator pressure; and
- authoritative `gencomp.c` to generated `compemu.cpp` consistency.

No workload PC, ROM patch, encounter-order exception, or interpreter escape is
part of the repair.

## Confirmed structural defects

### Memory shifts ignored no-flags generation

The authoritative generator always entered `start_needflags()`, called the
`jff_*` helper, and published live flags for all four fixed-count memory shifts.
This occurred in both generated variants, even when later instructions made the
complete CCR dead.

`gencomp.c` now selects `jff_ASLW/ASRW/LSLW/LSRW` only when flags are live and
selects the matching `jnf_*` helper otherwise. The effective-address fetch and
memory writeback order is unchanged. Deterministic regeneration updates all
seven legal memory-EA handlers for each operation: 28 no-flags wrappers in
all.

### Carry and ASL overflow depended on emitted instruction length

The flag-live word helpers used numeric `TBZ` skips over NZCV updates. Their
correctness therefore depended on the number of AArch64 instructions emitted
inside the skipped sequence.

All four helpers now publish carry by extracting the source bit and inserting
it into NZCV without control flow. `ASLW` publishes C and V together from the
old bits 15 and 14 after the size-correct N/Z test. The structural gate rejects
any reintroduced fixed non-zero branch in this family. The same branchless
carry contract replaces the remaining three register `ROXR` carry skips.

### Memory ROX wrote through a read-only X binding

`jff_ROXLW` and `jff_ROXRW` acquired `FLAGX` with `readreg()`, wrote the new X
value through that read-only binding, then called `DUPLICACTE_CARRY`, which
reacquired and released X before the original binding was released again. This
violated allocator ownership even when a favourable register assignment
produced the expected architectural result.

Each helper now acquires X once with `rmw(FLAGX)`, consumes the old X, writes the
new X in place, derives C from that same value, and performs one `unlock2(x)`.
There is no second X acquisition and no duplicate unlock.

## Dynamic coverage

Ten new exact-native vectors cover:

- flag-live and no-flags forms of all four fixed-count memory shifts; and
- memory `ROXLW` and `ROXRW` with explicit incoming-X and replayed word state.

Every vector restores the word at guest `0xA000` before native replay, asserts
entry at opcode PC `0x1000`, requires two `NATEXEC` observations, compares the
complete interpreter/JIT register dump, and fails closed unless the strict
summary reports `opt0=0`, `fallback=0`, and `exec_nostats=0`.

The no-flags streams overwrite the complete CCR after the shift. Their final
`MOVE.W` observation legitimately recomputes N/Z/V/C while preserving X; the
explicit expected SR values encode that architectural ordering rather than
mistaking the observation instruction for shift output.

## Allocator-pressure proof

`jit-test/regalloc-pressure.sh` now retains the historical MULU control and adds
`roxrw_mem_x_live_all`:

- D1-D7 and A0-A6 are source-live across `ROXR.W (A0)`;
- A0 is forcibly aliased with the S2 scratch allocation;
- the collision must occur (`pin > 0`);
- `MOVE` instructions retain X until `ADDX.L D5,D6` consumes the newly written
  value, distinguishing new X=0 from stale incoming X=1;
- a bounded DBF loop makes the audited block hot; and
- exact native entry at `0x100A` is mandatory.

Accepted output reports `pin=2`, `natexec=32`, and `interpop=2`. Interpreter and
JIT register dumps are byte-identical. This is both an ownership-pressure and
an architectural stale-X discriminator, not merely a registration test.

## Structural guards

`jit-test/structural-audit.ts` requires:

- one destination RMW lifecycle in each `jff` and `jnf` memory shift helper;
- no flag publication from the `jnf` helpers;
- branchless C publication and branchless ASL C/V insertion;
- generated `jff`/`jnf` selection and unchanged memory writeback in all four
  representative `(An)` handlers;
- one `rmw(FLAGX)` and exactly one X unlock in each memory ROX helper;
- no `readreg(FLAGX)`, `DUPLICACTE_CARRY`, or fixed carry skip in those helpers;
- branchless carry publication in register `ROXR.B/W/L`;
- exact replay metadata and active-risk membership for all ten vectors; and
- a native, pinned, X-consuming allocator-pressure witness.

## Acceptance evidence

- focused family and adjacent-risk gate: **17/17**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, score 100;
- complete active-risky corpus: **657/657**, with zero semantic and
  infrastructure failures;
- post-clean exact-native smoke: **12/12**, with zero failures;
- allocator pressure: both cells pass; ROXR reports `pin=2`, `natexec=32`,
  `interpop=2`, with byte-identical interpreter/JIT state;
- clean AArch64 build: pass; binary SHA-256
  `464a2b780b46479bf49080be83004f82bf84f606d10da9a12769fdfdbbf540dc`;
- generated `compemu.cpp`: byte-reproducible across two forced regenerations,
  SHA-256
  `243f2498665e64de77c116ce9c191902cf2c87e30185c08911e03c11488320e9`;
- deterministic ordinary and strict Finder schedules each reached 24,120,000
  retirements, retained 16,777,216 PCs, reached 21 `DiskStatus 43` events, and
  had no host fault. Their execution windows remain byte-identical at SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`;
  strict reports `opt0=0 fallback=0 exec_nostats=0`;
- shell syntax, structural audit, deterministic generation, and
  `git diff --check`: pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
