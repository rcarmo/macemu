# AArch64 JIT integer `forget_about` lifecycle audit

Date: 2026-07-26
Base: `d18e1532`

## Scope

This checkpoint audits exactly `midfunc,forget_about`, the integer allocator's
discard primitive. It does not promote the operations that call it, generic
memory MIDFUNCs, emitter APIs, raw boundaries, floating `f_forget_about`, or
runtime dispatch boundaries.

`forget_about(r)` means that the current virtual value is dead. It must remove
any physical association without writing the discarded value to its backing
slot, clear constant knowledge, and leave the vreg `UNDEF`. Safety therefore
depends on both the primitive and every configured caller.

## Primitive contract

If `r` is resident, `forget_about()` calls `disassociate()`. That first marks the
value `CLEAN`, then calls `evict()`: `tomem()` emits no store for a clean value,
and the physical hold is removed. The MIDFUNC then clears `live.state[r].val`
and sets status `UNDEF`. Already non-resident and constant values follow the
same final invalidation. A still-locked sole physical hold aborts in `evict()`;
locks are not silently cleared.

This is deliberately not an architectural writeback operation. Passing a live
Dn, An, `PC_P`, `FLAGX`, or `FLAGTMP` would be a caller defect.

## Configured caller census

The authoritative generated source retains **299 calls**, partitioned by
operand:

| Operand | Calls | Configured status | Ownership |
|---|---:|---|---|
| `src` | 84 | active | fetched/copied private source, consumed before discard |
| `scratchie` | 175 | dormant | private lane helper behind configured-false `kill_rodent()` |
| `tmp` | 40 | active | private MOVE16 transfer word, stored before discard |

The AArch64 compatibility implementation of `kill_rodent(int)` is exactly
`(void)r; return 0;`. Thus **124** generated calls are active and **175** are
retained in unreachable anti-stall branches. The dormant calls are still
classified because a later backend-policy change could make them reachable;
they remain safe private vregs, but current runtime tests cannot attribute
their execution.

The exact retained generated-family split is:

| Family | Calls |
|---|---:|
| MOVEA | 40 |
| ADDA | 40 |
| ADDAQ | 4 |
| MOVE16 | 40 |
| OR | 52 |
| AND | 52 |
| EOR | 32 |
| MOVE | 23 |
| NOT | 16 |

The remaining four source calls are in allocator/support code:

1. retained API `release_scratch(i)` rejects non-scratch IDs and double release,
   then discards only the allocated `S1..S5` vreg; it has no configured caller
   in this tree and is dormant;
2. active opcode-boundary `freescratch()` discards the complete
   `S1..VREGS-1` private range and resets the scratch-use bitmap;
3. active `writeword_clobber(address, source)` discards `source` only after the
   normal or special guest store has consumed it;
4. active `writelong_clobber(address, source)` has the same post-consumption
   contract.

Together with the MIDFUNC definition, these are the inventory's **304 source
references**: 127 active calls, 176 dormant calls, and one definition. No caller operand denotes an architectural integer vreg. The
active/dormant partition, generated family and operand totals are fail-closed in
the structural audit; a new caller, family, spelling, or active
`kill_rodent()` policy blocks regeneration.

## Exact-native controls

`jit-test/forget-about-lifecycle-matrix.sh` composes maintained strict-native
controls for all caller classes rather than inventing duplicate opcode tests:

- MOVEA fetched-source discard;
- ADDA/ADDAQ fetched-source discard;
- MOVE16 repeated transfer-word discard and reuse;
- one AND no-flags control confirming the configured `kill_rodent()` branch
  remains dormant while the surrounding opcode is strict-native (it is not
  claimed as execution of `forget_about`);
- 36 integer FMOVE destination cases whose word/long stores consume S2 through
  the clobber helpers across Dn and memory destinations, integer widths,
  writeback modes, FPCR rounding/range cases, exact native attribution, and
  replay isolation.

Accepted focused result:

```text
FORGET_ABOUT_LIFECYCLE_MATRIX active=39 dormant_control=1 pass=40 fail=0 total=40
```

Direct attribution remains structural: runtime equality cannot distinguish a
correct discard from an unnecessary scratch spill when both preserve guest
state.

## Closure decision

Promote exactly `midfunc,forget_about` from **unreviewed** to **audited**.
Whole-engine closure is not claimed. The remaining MIDFUNC, emitter, and raw
rows remain mechanically selected and independently classified.

## Acceptance

- source reference census: **304**, comprising 299 generated calls, four
  support calls, and the MIDFUNC definition;
- complete call-site partition: **127 active / 176 dormant**; generated calls
  are 124 active / 175 behind hard-false `kill_rodent()`, while support calls
  are three active / one definition-only retained API;
- caller proof: exactly nine generated families and three private operand
  spellings; zero architectural operand class;
- focused strict exact-native controls: **39 active + 1 dormant-policy**;
- structural audit: pass for clean-before-evict, `UNDEF`, locked-hold abort,
  generated family/operand counts, support caller ownership, and focused
  wrapper contents;
- deterministic closure regeneration promotes exactly one row;
- executable/generated source is unchanged from `d18e1532`;
- shell syntax and `git diff --check`: pass.
