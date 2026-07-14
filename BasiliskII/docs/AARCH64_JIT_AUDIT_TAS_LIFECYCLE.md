# AArch64 JIT TAS lifecycle audit

Date: 2026-07-14

Branch: `structural-audit`

Base: `64ddfd649d05e6ee4708d59e92da1493452b09d4` (accepted NEGX closure)

## Scope

This report closes the live AArch64 `i_TAS` family as one mandatory-flag,
byte read/modify/write, effective-address, memory-routing, and allocator
ownership contract:

- D-register direct with upper 24-bit preservation;
- original byte values zero, positive, and negative;
- N/Z publication from the byte before bit 7 is set;
- unconditional V/C clear and X preservation;
- `(An)`, `(An)+`, `-(An)`, `d16(An)`, brief indexed, absolute-word, and
  absolute-long memory forms;
- A7 byte postincrement and predecrement through its architectural two-byte
  stride;
- normal and forced special-memory reads and writes;
- exact-PC native entry and forced EA/value allocator collision.

The audit follows configured generated code and final registration, not stale
alternate tables, dead helper names, or raw textual occurrence.

## Reachability finding

The executable path is:

1. authoritative `src/uae_cpu_2026/compiler/gencomp.c` handles `i_TAS`;
2. `genamode(..., GENA_GETV_FETCH, GENA_MOVEM_DO_INC)` obtains the original
   byte and performs any architectural address-register update;
3. both generated `comp_ff` and nominal `comp_nf` handlers call `jff_TAS`;
4. `jff_TAS` publishes the mandatory CCR result and sets bit 7 in place;
5. `genastore()` writes the modified byte to Dn or the original memory EA.

`jnf_TAS` is unreachable: the generator unconditionally surrounds `jff_TAS`
with `start_needflags()` / `live_flags()` / `end_needflags()`, because TAS
architecturally defines N/Z/V/C even when local liveness would otherwise select
a no-flags compiler table. The old `jit_op_tas` runtime helper is also
unreachable; it has no generated or post-registration caller. Neither dead
implementation was promoted or modified.

`src/Unix/compstbl.cpp` is the active generated registration table and contains
the TAS compiler entries. The stale alternate `compstbl_arm.cpp` NULL entries
are not the configured table and are not reachability evidence.

## Original-byte flag lifecycle

The reachable `jff_TAS` MIDFUNC has one ordered sequence:

1. acquire the byte operand through `rmw(d)`;
2. sign-extend the original low byte into a temporary;
3. execute `TST_ww` on that temporary, setting byte-correct N/Z and clearing
   V/C;
4. OR `0x80` into the destination without changing NZCV;
5. mark physical carry as non-inverted and release the destination.

This order is essential. Testing after the OR would make every positive input
look negative; testing the unnormalised 32-bit container would make Dn upper
bits contaminate N/Z. Register writeback uses `mov_b_rr`, retaining Dn's upper
24 bits. TAS does not publish carry to X, so the separate architectural X state
is preserved.

No semantic defect was found in this sequence. Closure is based on positive
source and native-runtime proof, not on an opcode-local rewrite.

## Memory RMW and effective-address lifecycle

Every generated memory form retains one EA value across
`readbyte -> jit_value_lock(srca) -> jff_TAS -> writebyte -> jit_value_unlock`.
Postincrement saves the original EA before updating An; predecrement updates An
before the read and then retains that updated EA for the write. Both byte update
modes use `areg_byteinc[]`, which selects a two-byte step for A7 and one byte for
A0-A6.

The same generic read/write primitives route ordinary RAM directly and forced
special memory through the bank helpers. The previously audited byte-write
boundary preserves guest NZCV around address guards, so the post-TAS store
cannot replace the flags just computed by `jff_TAS`. This matches the
single-CPU interpreter contract: an ordered byte read followed by byte write;
no stronger host-atomic primitive is required by the emulator.

## Exact-native evidence

The 13-vector exact-PC matrix contains:

- four D0 vectors covering zero with X clear/set, positive with X set, negative
  with X clear, stale incoming N/Z/V/C removal, and upper-lane preservation;
- seven vectors covering every legal memory EA class;
- two additional A7 postincrement/predecrement vectors;
- three memory vectors forced through special-memory helpers.

The positive `0x01 -> 0x81` absolute-word vector is a direct discriminator for
flags-before-bit-set: TAS must report N clear even though the stored result has
bit 7 set. Memory vectors execute `MOVE SR,D2` immediately after TAS and only
then load the modified byte for verification. D2 therefore records TAS flags,
while the final SR correctly reflects the verification MOVE. Replay memory is
restored before each exact-PC pass.

All vectors require strict interpreter/JIT byte equivalence, one deterministic
register dump, forced RAM L2 promotion, and `NATEXEC` at `0x1000`:

```text
METRIC pass=13
METRIC fail=0
METRIC total=13
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC risky_pass=13
METRIC risky_fail=0
METRIC score=100
```

## Allocator ownership

The original pressure hook covered write-only allocation during `readbyte`, but
could not target the later private `rmw(src)`. Extending the diagnostic hook to
explicit private RMW targets exposed a residual post-read lifetime defect:

```text
pre-repair: status=FAIL pin=1 skip=2 natexec=1 interpop=1
interpreter D0=a5a50080 SR=2718
JIT         D0=a5a50000 SR=2714
```

After `readbyte` released its transient address lock, the forced S1 byte RMW
could take A0's still-needed host mapping and redirect the final store. The
generator now explicitly locks every memory `srca` after the read and releases
it only after `genastore`. The strengthened witness is:

```text
post-repair: status=PASS pin=0 skip=3 natexec=1 interpop=1
interpreter D0=a5a50080 SR=2718
JIT         D0=a5a50080 SR=2718
```

Generated source contains 14 matched TAS EA locks/unlocks: seven memory forms in
each nominal compiler table. This correction was found during the later classic
bit-operation audit; it supersedes the weaker `pin=0 skip=2` evidence recorded
at the initial TAS publication.

## Acceptance evidence

At initial publication, the complete active-risky campaign passed **684/684**,
the focused matrix passed 13/13, and the then-current eight allocator cells
passed. After the strengthened private-RMW hook exposed and repaired the
post-read EA gap, a clean rebuild passed the combined TAS/classic-bit focused
matrix 42/42, the expanded active corpus 691/691, and all 12 allocator cells.
All runs had zero semantic, infrastructure, timeout, emulator-exit,
missing-dump, multiple-dump, sentinel, or native-evidence failures.

Two independent runs of the authoritative generator reproduced
`src/Unix/compemu.cpp` byte-for-byte and left it clean:

```text
SHA-256 14efd5a008fb6ca20065a56991f8e1a3ef8a574348127b0207fcea071a25a6dd
```

The regenerated closure census remains 997 rows. TAS promotion changes only
`generator:i_TAS` and reachable `midfunc:jff_TAS`; generator totals become
`audited=34, serviced=44, unreviewed=52`, and MIDFUNC totals become
`audited=153, unreachable=119, unreviewed=150`.

## Structural gates

`jit-test/structural-audit.ts` fails closed on:

- authoritative mandatory `i_TAS -> jff_TAS` routing;
- all eight generated flag-live and eight nominal no-flags handlers selecting
  `jff_TAS`, with no caller of `jnf_TAS`;
- sign-extension and TST of the original byte before ORing bit 7;
- non-inverted C publication, Dn byte-only writeback, and A7 geometry;
- read/EA-lock/RMW/write/EA-unlock order for all seven generated memory EA classes;
- all 13 exact-native vectors, three special-memory routes, active-risky
  sentinel, and the EA/value collision witness.

Expected metrics are:

```text
METRIC structural_tas_mandatory_flag_live=1
METRIC structural_tas_original_byte_flags=1
METRIC structural_tas_exact_native_vectors=13
METRIC structural_tas_memory_ea_classes=9
METRIC structural_tas_allocator_pressure=1
```

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.

## Closure boundary

This report promotes only live `generator:i_TAS` and `midfunc:jff_TAS`.
`midfunc:jnf_TAS` and `runtime_boundary:jit_op_tas` remain unreachable. It does
not classify MOVE, MOVEA, MOVE16, Scc/DBcc, bit operations, or lower emitter and
runtime boundaries merely exercised through already accepted shared services.
