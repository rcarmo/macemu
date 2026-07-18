# AArch64 JIT legacy FScc raw-chain retirement

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `a613336a`

## Scope

This bounded graph checkpoint covers the legacy AArch64 `fp_fscc_ri` MIDFUNC,
its `raw_fp_fscc_ri` lower boundary, and the now-unreachable `CLEAR_LOW8_xx`
and `SET_LOW8_xx` macros.

It does **not** close the configured `i_FScc` generator lifecycle. Live
`compfpu` FScc uses the separate `comp_fscc_opp` CMOV route and remains
**unreviewed**, as do the broadly shared `CSETM_wc` and `BFXIL_xxii` emitter
APIs.

## Source graph

Configured AArch64 source has no caller of `fp_fscc_ri`. The retained MIDFUNC
contains only its definition and the edge to `raw_fp_fscc_ri`; the raw boundary
likewise has only its `LOWFUNC`/`LENDFUNC` definition tokens.

The dead raw switch contains 15 explicit native-condition cases. Its exact
lowering inventory is:

- 11 `CLEAR_LOW8_xx` sites inside the dead FScc raw boundary;
- 10 `SET_LOW8_xx` sites inside the dead FScc raw boundary;
- four `CSETM_wc` plus four `BFXIL_xxii` sites;
- ten ordered/unordered `BVS_i` guards and ten local `B_i` joins.

`SET_LOW8_xx` has no other source site. `CLEAR_LOW8_xx` has two additional
sites, one each in the already-unreachable `jnf_CLR_b` and `jff_CLR_b`
namesake MIDFUNCs. Thus the complete source partition is **13/10** clear/set:
11/10 in dead FScc plus 2/0 in dead CLR, with no reachable configured caller.
Both macros expand directly to logical-immediate words and have no nested
emitter dependency. `CSETM_wc` and `BFXIL_xxii` remain live through separate
integer MIDFUNC and compatibility callers.

The live `comp_fscc_opp` route is structurally distinct: it imports floating
flags, switches on `extra & 0x0f`, composes predicates with `cmov_l_rr`, and
publishes the low byte with `mov_b_rr`. It contains no legacy
`fp_fscc_ri`/`raw_fp_fscc_ri` edge.

## Evidence and closure

The maintained integrated opcode harness passes the configured
`fscc_false_byte` vector. This is a live-route smoke check only; it is not
complete predicate, EA, exception, or allocator evidence for `i_FScc`.

The structural audit fails closed on:

- any new `fp_fscc_ri` or `raw_fp_fscc_ri` caller;
- loss or reshaping of any of the 15 condition cases;
- changes to the exact 11/10 dead-FScc plus 2/0 dead-CLR low-byte partition;
- accidental reuse of the legacy path by `comp_fscc_opp`; or
- changes to the current live shared-emitter site ownership.

The authoritative inventory changes exactly three rows:

- `raw_boundary,raw_fp_fscc_ri`: **unreviewed -> unreachable**;
- `emitter_api,CLEAR_LOW8_xx`: **unreviewed -> unreachable**;
- `emitter_api,SET_LOW8_xx`: **unreviewed -> unreachable**.

`generator,i_FScc`, `emitter_api,CSETM_wc`, and `emitter_api,BFXIL_xxii` remain
**unreviewed**. `generator,i_FPP` is unrelated and remains **unreviewed**.
