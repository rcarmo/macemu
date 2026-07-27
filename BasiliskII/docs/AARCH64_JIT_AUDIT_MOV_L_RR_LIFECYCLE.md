# AArch64 JIT `mov_l_rr` and raw register-copy audit

Date: 2026-07-27  
Base: `93e79c0a`

## Scope

This checkpoint audits:

- `midfunc,mov_l_rr`, the generic integer/pointer virtual-register copy; and
- `raw_boundary,compemu_raw_mov_l_rr`, its full-width host-register copy.

It does not promote the generic `MOV_xx` emitter API, allocator policy, MOVE
family semantics, or pointer arithmetic.

## Configured reachability

The inventory records 2,359 references to `mov_l_rr`. Configured preprocessing
reproduces that total exactly:

- 2,342 generated `compemu.cpp` calls;
- 14 active FPU compiler calls;
- 2 calls from lower MIDFUNC wrappers in `compemu_midfunc_arm64_2.cpp`;
- 1 support call in indexed-EA construction.

Raw source has more generated/FPU spellings in inactive preprocessor branches;
they are not used as evidence.

Configured generated calls occupy 45 syntactic source/destination forms. The
largest classes are address-register copies into `srca`/`dsta`, result
publication into architectural registers, MOVE/MOVEA source transfers, MOVEM
cursor snapshots, count copies, and six `mov_l_rr(PC_P,src)` control-flow
BRA providers. Configured AArch64 preprocessing removes the legacy non-AArch64 FBcc
`mov_l_rr(S2,PC_P)` / conditional-move implementation, so no live route copies a
host PC pointer into an ordinary guest vreg.

## MIDFUNC state contract

`mov_l_rr(d,s)` has three reachable states:

1. **Self copy** (`d == s`): return without allocator, flags, or emission.
2. **Constant source**: route through the audited `mov_l_ri(d,val)` constant
   boundary. Non-`PC_P` destinations remain 32-bit; `PC_P` retains full pointer
   width. The six generated `PC_P <- src` providers reach this path after typed
   host-pointer construction.
3. **Materialised source**: acquire and lock `s` with `readreg` before allocating
   `d` with `writereg`; emit a real copy; unlock destination and source. The
   explicit copy avoids shared-host-register lock conflicts.

The operation emits no NZCV/X mutation, memory access, fault, or PC publication
on its own. Architectural meaning belongs to its caller.

## Raw boundary

`compemu_raw_mov_l_rr` emits one `MOV_xx(d,s)`, deliberately using X-register
width. Four production callers plus LOWFUNC/LENDFUNC make its six inventory
references:

- the `mov_l_rr` materialised branch;
- allocator host-register relocation (`mov_nregs`);
- allocator exclusivity split (`make_exclusive`);
- fallback ABI setup (`REG_PAR2 <- R_REGSTRUCT`).

X width is mandatory for `PC_P`, pointer-capable private scratch state, and the
R_REGSTRUCT ABI pointer. Guest values are safe because their producers already
zero the upper half through W-register operations. The raw boundary does not
own that producer invariant.

## Exact evidence

`jit-test/mov-l-rr-conformance.sh` checks four exact register-field encodings and
executes seven native vectors:

- six distinct-register copies covering zero, 32-bit high-bit/all-ones, and
  full-width 64-bit patterns;
- one same-register alias.

`jit-test/mov-l-rr-lifecycle-matrix.sh` composes that with eight strict runtime
controls:

- self-copy no-op with flags;
- constant-source MOVEA.L;
- materialised Dn-to-Dn MOVE.L;
- long-displacement BRA's constant `PC_P <- src` publication;
- zero copy, dynamic MOVEA.L, and two long MOVE update/alias controls.

Result:

```text
MOV_L_RR_LIFECYCLE conformance=7 focused=4 controls=4 fail=0 total=15
```

## Closure decision

`midfunc,mov_l_rr` and `raw_boundary,compemu_raw_mov_l_rr` move from
**unreviewed** to **audited**. No production/generated source change is needed.
Whole-engine closure is not claimed.

## Acceptance

- exact/native raw conformance: **4 words, 7 vectors**;
- strict runtime controls: **8/8**;
- total focused evidence: **15/15**;
- configured census: **2,342 + 14 + 2 + 1 = 2,359**;
- raw census: **four callers + two markers = 6**;
- exact two-row closure delta; deterministic 998-row regeneration:
  - CSV: `8cfb7e22d7d83a0b1b774b62ee5e168faa26554f874620446080f02aa7a9e61f`;
  - Markdown: `a325d592b8d2acf3e95b91aa978eed144a135e823f49ba2e3bd4395f697f11bc`;
- independent bounded review: **APPROVE** for configured census, pointer
  direction, four raw callers, X-width safety, evidence, and exact scope;
- production/generated hashes unchanged from `93e79c0a`:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `gencomp.c`: `7ff6be9dc85916f77e31e2b426460c23d7aaf449c1be1800a21ebb40a21a741a`;
  - MIDFUNC source: `495296a9400c5c54bd21e928217a9228534afb720f38b9af96222274f5652ae2`;
  - raw source: `ca7997484b3c0a40d25b90f4ae48e538b4978e01816e014e75ac63399906bc24`;
- structural audit, shell/C++ warnings-as-errors, `git diff --check`, and source
  hygiene: pass.
