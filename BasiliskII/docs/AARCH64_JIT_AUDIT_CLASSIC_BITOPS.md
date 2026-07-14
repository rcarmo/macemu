# AArch64 JIT classic bit-operation lifecycle audit

Date: 2026-07-14
Branch: `structural-audit`

## Scope

This tranche audits `BTST`, `BCHG`, `BCLR`, and `BSET` as one complete
condition/data/EA family:

- dynamic Dn and immediate bit numbers;
- modulo-8 byte-memory and modulo-32 long-Dn counts;
- original-bit Z publication with X/N/V/C preservation;
- flag-live and flag-dead lowering;
- source/destination aliasing;
- register destination versus byte read/modify/write memory;
- all configured memory EAs, including PC-relative generated forms;
- An and A7 writeback geometry;
- special-memory routing;
- effective-address/value allocator ownership;
- constant-folded bit 31.

The authoritative generator remains
`src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is generated.

## Reachability

The configured AArch64 path directly calls:

- eight BCHG MIDFUNCs: jff/jnf, byte/long, dynamic/immediate;
- eight BCLR MIDFUNCs with the same cross-product;
- eight BSET MIDFUNCs with the same cross-product;
- four flag-producing BTST MIDFUNCs: byte/long, dynamic/immediate.

BTST has no no-flags MIDFUNC because a flag-dead BTST has no data mutation;
the generator still performs its source and destination fetches, preserving
memory access/fault semantics, then emits no Boolean work. The generated legacy
`bt/btc/btr/bts` text is inside the inactive non-AArch64 preprocessor branch;
the configured path uses only the 28 direct MIDFUNC routes above.

Generated call counts are:

```text
jff BCHG/BCLR/BSET byte  18 each
jnf BCHG/BCLR/BSET byte  18 each
jff BCHG/BCLR/BSET long   2 each
jnf BCHG/BCLR/BSET long   2 each
jff BTST byte             20
jff BTST long              2
```

## Demonstrated defects

### Memory RMW lost its pre-write effective address

Modifying byte bit operations fetched the destination and retained `dsta` for
the later store, but did not explicitly own that private EA while condition
sampling and the destination RMW allocated registers. A forced S2-to-S1
postincrement witness made the byte destination take the EA's host mapping:

```text
REGPRESSURE cell=bitop_b_ea_value_collision status=FAIL pin=1 skip=2 natexec=1 interpop=1
interpreter D0=00000001 SR=2710
JIT         D0=00000000 SR=2714
```

The write was redirected away from the original `(A0)` byte. The generator now
locks `dsta` for every memory BCHG/BCLR/BSET after the read and releases it only
after `genastore`. BTST remains read-only and needs no post-read EA ownership.
The repaired witness is:

```text
REGPRESSURE cell=bitop_b_ea_value_collision status=PASS pin=0 skip=3 natexec=1 interpop=1
interpreter D0=00000001 SR=2710
JIT         D0=00000001 SR=2710
```

The diagnostic RMW pressure hook now accepts explicitly selected private as
well as architectural virtual-register targets, allowing this lifetime to be
proved rather than inferred.

### The strengthened pressure hook exposed the same residual TAS gap

TAS had previously passed a weaker write-allocation pressure check, but its
post-read private byte RMW could not be selected directly. The strengthened
hook forced that RMW toward the fetched byte's still-needed S1 EA and reproduced
the same redirected-store class:

```text
pre-repair: status=FAIL pin=1 skip=2 natexec=1 interpop=1
interpreter D0=a5a50080 SR=2718
JIT         D0=a5a50000 SR=2714
```

The TAS generator now locks every memory `srca` after `readbyte` and releases it
after `genastore`. The generated source contains 14 matched locks/unlocks, seven
memory forms in each nominal compiler table. The strengthened witness passes
with `pin=0 skip=3`; the TAS lifecycle report records this superseding evidence.

### BCLR.L bit-31 constant folding used signed shift UB

The flag-dead immediate BCLR.L constant path used `1 << (s & 31)`. For bit 31,
left-shifting signed `int` into the sign bit is undefined C++. It now forms the
mask as `uae_u32(1) << (s & 31)`. An exact-native test uses a compile-time
`MOVE.L #$80000000,D0`, clears bit 31 through the no-flags route, and overwrites
flags afterwards so the constant-folded data result is the only dependency.

## Proved contracts

### Count and width

- Byte-memory operations reduce dynamic counts to three bits and immediate
  counts with `& 7`.
- Long-Dn operations reduce dynamic counts to five bits and immediate counts
  with `& 31`.
- The matrix exercises 31, 32, and 63 boundaries.
- Dynamic long aliases sample the bit number from the original register before
  modifying that same register.

### Flags

Flag-producing paths save NZCV, derive Z from the original selected bit, replace
only NZCV bit 30, and restore the result. The physical carry representation and
its `flags_carry_inverted` bookkeeping remain unchanged, so architectural C is
preserved in either representation; X is a separate value and is untouched.

- Dynamic forms TST the original destination before mutation.
- Immediate BCHG toggles first and publishes the new bit, which is exactly the
  inverse of the original bit and therefore equals architectural Z.
- Immediate BCLR/BSET/BTST use a fixed one-instruction TBNZ skip around Z set.
- No-flags BCHG/BCLR/BSET use only non-flag-setting data instructions.
- BTST never mutates its destination.

### Memory ordering

The 108 generated modifying-memory entries have exactly 108 EA locks and 108
post-store unlocks. This covers both configured compiler tables, all three
modifying operations, both dynamic/immediate sources, and every generated byte
EA. Aipi/Apdi update the architectural An in normal genamode order while the
saved pre-write EA remains pinned. A7 byte modes retain their two-byte stride.
Special addresses continue through canonical `readbyte`/`writebyte` helpers.

## Exact-native matrix

The focused matrix contains 29 vectors:

- ten long-Dn vectors for all four operations, dynamic/immediate counts,
  original zero/set states, 31/32/63 reduction, aliases, and no-flags folding;
- thirteen ordinary memory vectors covering `(An)`, `(An)+`, `-(An)`, d16,
  indexed, absolute word/long, A7 postincrement/predecrement, special memory,
  read-only BTST, and a no-flags RMW;
- two modifying PC-relative vectors (d16 and indexed);
- two read-only BTST PC-relative vectors;
- two immediate-destination BTST vectors.

Every vector starts native replay at the opcode PC and requires two exact native
entries. Memory forms restore deterministic bytes before replay and snapshot SR
before verification loads.

Focused result:

```text
METRIC pass=29
METRIC fail=0
METRIC total=29
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

## Acceptance gates

After a clean rebuild, the 29 classic-bit vectors plus the 13 TAS vectors passed
as one exact-native focused set:

```text
METRIC pass=42
METRIC fail=0
METRIC total=42
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

The complete active risky corpus passed 691/691 with zero semantic,
infrastructure, or equivalence failures. All 12 allocator-pressure cells passed,
including the strengthened TAS and classic-bit witnesses at `pin=0 skip=3`.
Strict allocation fallback/abort, optlev0, opcode fallback, verifier reference,
and full-JIT negative gates all remained live. The structural audit, shell syntax
checks, `git diff --check`, and clean build passed.

Two independent authoritative generations produced identical `compemu.cpp`:

```text
785fc377f3c68e8a20409bcfef6e4504e77670ce201bf7af0b87f14c1c85e955
```

## Closure classification

The 997-row inventory changed only in source line coordinates and these intended
promotions. Promote as audited:

- generators `i_BTST`, `i_BCHG`, `i_BCLR`, and `i_BSET`;
- all 28 reachable jff/jnf classic-bit MIDFUNC definitions.

No similarly named configured MIDFUNC is deferred or unreachable. Whole-engine
completion is not claimed by this tranche.
