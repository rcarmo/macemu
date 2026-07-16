# AArch64 JIT EXG lifecycle audit

Date: 2026-07-16

## Scope

This report closes the reachable integer `i_EXG` generator lifecycle across all
three legal long-width forms:

- `EXG Dn,Dn`;
- `EXG An,An`;
- `EXG Dn,An`.

It covers simultaneous exchange semantics, same-class self aliases, maximum
register fields, roundtrips, full XNZVC preservation, exact native entry,
no-flags table execution, and allocator ownership. EXG has no namesake MIDFUNC;
the complete live implementation is emitted directly by `gencomp.c`.

## Generator contract

The generator fetches both full-width operands, allocates one private temporary,
and emits the exchange in three ordered steps:

1. copy the original source into `tmp`;
2. write the original destination into the source architectural register;
3. write `tmp` into the destination architectural register.

The temporary is essential: neither architectural write may destroy the value
needed by the other. Same-register Dn/Dn and An/An encodings are legal no-ops;
the An/An generated route uses private copies when both decoded operands name
the same architectural register. Dn/An cannot alias because the register files
are distinct.

No EXG handler materialises, discards, or publishes flags. There are no memory
accesses and no explicit generator JIT-value pins; ordinary `mov_l_rr` source
ownership must retain the private temporary across both writes.

Configured generation contains six handlers: three encoding classes in the
flag-live table and the same three in the no-flags table. Every handler allocates
one temporary and saves the source before either architectural write.

## Exact-native runtime matrix

The focused matrix contains 12 exact-native vectors:

- one distinct-register exchange for each of Dn/Dn, An/An, and Dn/An;
- same-register no-op forms for Dn/Dn and An/An;
- maximum field coverage for each encoding class;
- two-EXG roundtrips for each encoding class;
- a Dn/An no-flags-table vector whose following MOVEQ determines the observed
  SR, proving EXG itself does not publish flags.

Every vector starts directly at EXG and uses two-pass exact-native replay. Exact
register and SR assertions prove simultaneous exchange and complete XNZVC
preservation. Focused result: **12/12**, zero semantic or infrastructure
failures, score 100.

## Allocator pressure

The pressure witness forces EXG D0,D1's private temporary toward D0's live host
mapping. `mov_l_rr(tmp,src)` rejects that alias (`skip=1`), retains original D0
through the first write, and completes the exchange with exact register/SR
replay at native entry.

## Structural result

The fail-closed structural audit locks:

- one live generator case and exact save/first-write/second-write order;
- no flags, memory, or explicit generator lock calls;
- six generated handlers split 3/3 across compiler tables;
- one temporary source save per handler and exact Dn/An write route counts;
- both same-class alias routes;
- all 12 encodings, expected register/SR states, initial states, exact-native
  replay, risky tags, active-corpus entries, and pressure witness.

## Acceptance evidence

- focused exact-native matrix: **12/12**, zero semantic or infrastructure
  failures, score 100;
- complete active-risky replay: **888/888**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **30/30**, including the EXG temporary/
  source witness with `skip=1` and exact register/SR native replay;
- strict full-JIT negative gate passes, including the expected allocation abort;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after two
  explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly generator `i_EXG`:
  - generator `audited=56`, `serviced=44`, `unreviewed=30`;
  - MIDFUNC remains `audited=262`, `unreachable=118`, `unreviewed=42`;
  - emitter API remains `audited=49`, `unreachable=91`, `unreviewed=154`;
  - raw boundary remains `audited=24`, `unreviewed=58`;
  - CSV: `929100eaa777a00cddf6abbe27e46cea2d26a0ecf7dda9f14ec48a1329aafdb6`;
  - Markdown: `c8d83351d8e18e5680d9259855aca0b4d17a7b50d683290b93d524c334cbb06f`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects `EXT`. Whole-engine closure is not claimed.
