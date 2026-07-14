# AArch64 JIT MOVE / MOVEA / MOVE16 lifecycle audit

Date: 2026-07-14
Branch: `structural-audit`
Host: host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`), 12-core
AArch64, 16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root

## Scope

This tranche closes the risk-94 transfer cluster without conflating three
architecturally different operations:

- `MOVE.B/W/L <ea>,<ea>`: source-value ownership, narrow Dn lane retention,
  NZVC publication with X preservation, all readable and writable EAs,
  update-mode ordering, source/destination aliases, and special memory;
- `MOVEA.W/L <ea>,An`: word sign extension, long replacement, no CCR change,
  source-EA writeback, and destination/base aliases;
- `MOVE16`: all five encodings, 16-byte alignment, four ordered longword
  transfers, direct and special-memory routes, and postincrement publication.

`gencomp.c` remains authoritative. `src/Unix/compemu.cpp` was regenerated from
it and is not independently edited.

## Live-path topology

### MOVE

The generated family contains 562 compiler functions across flag-live and
nominal no-flags tables. Every function now performs one balanced
`jit_value_lock(src)` / `jit_value_unlock()` lifetime around destination
allocation, flag generation, and final storage.

Byte/word shared MIDFUNCs remain reachable through the compatibility wrappers:

- `jff_MOVE_b`, `jff_MOVE_w`, and their immediate forms when a wrapper is
  entered inside `start_needflags()`;
- `jnf_MOVE_b`, `jnf_MOVE_w`, and their immediate forms for internal moves
  outside that native-flag interval.

Their audited contracts are:

- dynamic sources are acquired before destination RMW allocation;
- byte/word writes use BFI and preserve the untouched upper 24/16 Dn bits;
- flag-live paths sign-extend the selected lane before TST, so N and Z are
  width-correct while V/C clear;
- X remains outside the NZCV result;
- same-register forms do not destroy their input before flag sampling.

`jff_MOVE_l`, `jnf_MOVE_l`, and `jff_MOVE_l_imm` remain unreachable from the
configured generated/support/FPU roots. Long generated MOVE uses the primitive
`mov_l_*` / OR / TEST lowering directly; unreachable names are not promoted.

### MOVEA

`i_MOVEA` lowers directly in `gencomp.c`:

- word sources use `sign_extend_16_rr(dstreg + 8, src)`;
- long sources use `mov_l_rr(dstreg + 8, src)`;
- no `genflags`, `jff_MOVEA`, or `jnf_MOVEA` path is selected.

The generated family has 48 flag-live/nominal-no-flags compiler functions.
`jnf_MOVEA_w`, `jnf_MOVEA_l`, and `jnf_MOVEA_w_imm` remain unreachable. For
`(An)+,An` and `-(An),An`, the source EA side effect occurs while fetching the
operand, then the destination assignment deliberately wins, matching the
interpreter contract.

### MOVE16

`i_MOVE16` selects `genmov16`, not legacy `jnf_MOVE16`. The direct generator:

1. snapshots source and destination addresses;
2. masks both transfer addresses with `~15`;
3. publishes only the selected architectural +16 updates (once when both
   postincrement operands name the same An);
4. uses four ordered `readlong` / `writelong_clobber` pairs under special
   memory, or four ordered direct longword load/store pairs otherwise.

All ten generated flag-live/nominal-no-flags compiler functions use this route.
The similarly named `jnf_MOVE16` MIDFUNC remains unreachable and is not
promoted.

## Structural defect found and repaired

The earlier source-value repair covered only MOVE **to memory**. Register
MOVE destinations still fetched a memory operand into a scratch virtual
register and then performed destination flag/lane lowering without pinning
that source.

A forced inverse collision made the gap deterministic for
`MOVE.B (A1),D0`:

```text
pre-fix pressure event: pin=1
interpreter: D0=a5a50010, snapshotted SR=2710
JIT:         D0=00000000, snapshotted SR=2714
```

The destination's low-byte RMW accepted the host register still carrying the
fetched S1 source. It therefore destroyed both the source byte and D0's upper
lane before OR/flag publication.

The repair is family-level: `i_MOVE` now fetches and pins its source before
switching on destination mode, and releases it only after flags and storage.
It covers register and memory destinations, all widths, immediates, memory
sources, base/index aliases, and normal/special-memory lowering through one
ownership rule.

The allocator diagnostic was correspondingly generalised so an explicit
architectural write/RMW target may be forced toward any integer virtual source,
including a scratch source. Historical scratch-destination pressure semantics
remain unchanged. The repaired witness is:

```text
REGPRESSURE cell=move_b_mem_source_dst_collision status=PASS
            pin=0 skip=2 natexec=1 interpop=1
```

The complete nine-cell pressure suite also retains the accepted MULL,
memory-ROX, MOVEM, NEGX, and TAS witnesses.

## Exact-native matrix

The new matrix contains 48 exact-PC vectors, all with strict native-entry
proof:

- **31 MOVE vectors**: byte/word/long negative and zero classes, immediate and
  dynamic sources, same-Dn aliases, upper-lane retention, all readable source
  EAs, all writable destination EAs, normal/special memory, memory-to-memory
  update aliases, source/base aliases, CCR snapshots, and A7 byte stride;
- **10 MOVEA vectors**: word sign extension, long replacement, immediate,
  register, indirect, indexed, PC-relative, postincrement/predecrement
  destination aliases, A7 update, special memory, and unchanged full CCR;
- **7 MOVE16 vectors**: all five encodings, distinct/same postincrement
  registers, unaligned architectural addresses with aligned transfers, direct
  and forced-special paths, four-longword data verification, and unchanged CCR.

The test glue now accepts `B2_TEST_MEMORY_BYTES` address/byte fixtures before
the first pass. Unless `B2_TEST_REPLAY_BYTES` explicitly overrides them, the
same fixture is restored before every exact-PC replay. This prevents a trace
pass's memory writes from becoming the native pass's oracle.

Focused result:

```text
METRIC pass=48
METRIC fail=0
METRIC total=48
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

Complete active-risky result after adding one durable sentinel for each
subfamily:

```text
METRIC pass=687
METRIC fail=0
METRIC total=687
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

A clean AArch64 rebuild followed by the complete focused matrix again passes
48/48. The post-clean nine-cell allocator suite also passes. Two independent
runs of the authoritative generator reproduce `src/Unix/compemu.cpp`
byte-for-byte at:

```text
SHA-256 0a5d0e583262c000e3063604f46ada3bc44eba5471771fe809343e48898798a6
```

The regenerated closure inventory remains 997 rows. Generator totals become
`audited=37, serviced=44, unreviewed=49`; MIDFUNC totals become `audited=161,
unreachable=119, unreviewed=142`.

## Closure classification

Promoted to `audited`:

- generators: `i_MOVE`, `i_MOVEA`, `i_MOVE16`;
- reachable MIDFUNCs: `jff_MOVE_b`, `jff_MOVE_w`, `jff_MOVE_b_imm`,
  `jff_MOVE_w_imm`, `jnf_MOVE_b`, `jnf_MOVE_w`, `jnf_MOVE_b_imm`, and
  `jnf_MOVE_w_imm`.

Unreachable MOVE/MOVEA/MOVE16 MIDFUNCs retain that classification. This report
does not turn a dead namesake into accepted live code.

## Structural gates

`jit-test/structural-audit.ts` locks:

- one balanced source lifetime in every generated MOVE compiler function;
- byte/word lane, signed-NZ, same-register, and carry-state MIDFUNC contracts;
- direct MOVEA extension/no-flags routing;
- MOVE16 aligned address masking, four helper pairs, four direct pairs, and
  update aliasing;
- exact-native matrix cardinalities and forced-special sentinels;
- initial/replay memory fixture restoration;
- inverse scratch-source/architectural-destination allocator pressure.

This tranche closes only the MOVE ownership cluster. It does not claim that the
whole AArch64 JIT audit is complete.
