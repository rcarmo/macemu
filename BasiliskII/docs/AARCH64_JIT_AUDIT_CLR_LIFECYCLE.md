# AArch64 JIT CLR lifecycle audit

Date: 2026-07-16

## Scope

This report closes the reachable integer `i_CLR` generator lifecycle across
byte, word, and long register and writable-memory forms. It covers upper-lane
preservation, fixed logical flags, every writable EA class, address-register
writeback, A7 byte geometry, special-memory routing, store/flag ordering, exact
native replay, no-flags table execution, and allocator pressure.

The six namesake `jff_CLR_{b,w,l}` / `jnf_CLR_{b,w,l}` MIDFUNCs are not called
from configured generated/support/FPU roots and remain explicitly unreachable.
No MIDFUNC row is promoted by this report.

## Generator contract

The live generator does not read the previous destination value. It:

1. calculates the aligned writable EA or architectural Dn destination;
2. allocates a private zero value and emits `mov_l_ri(dst,0)`;
3. stores the zero through the normal width-specific register/memory path;
4. only then publishes logical flags by testing that zero.

The order is significant on AArch64. Memory-store helpers can use host NZCV for
address/special-memory decisions. Publishing CLR's fixed result after storage
ensures those internal flags cannot escape as architectural state. The final
M68K contract is X preserved, N=V=C=0, and Z=1.

Configured generation contains 48 handlers: 24 flag-live and 24 no-flags. Each
table contains eight legal writable forms per width (Dn, (An), (An)+, -(An),
(d16,An), indexed, absolute word, and absolute long). Across both tables there
are 14 byte, 14 word, and 14 long memory stores; Dn byte/word writes preserve the
upper lane. The 24 flag-live handlers contain eight tests per width, while all
24 no-flags handlers omit flag materialisation.

## Exact-native runtime matrix

The focused matrix contains 15 exact-native vectors:

- Dn byte/word/long, including exact upper-lane preservation;
- (An), (An)+, -(An), (d16,An), indexed, absolute word, and absolute long;
- A7 byte postincrement and predecrement geometry;
- three forced special-memory routes;
- a memory CLR followed by BNE, proving fixed flags are published after storage;
- one register and one memory no-flags-table vector, where a later MOVEQ sets the
  observed SR and proves CLR did not re-materialise flags.

All memory vectors assert the exact stored zero bytes and replay them at the
CLR opcode PC. Focused result: **15/15**, zero semantic or infrastructure
failures, score 100.

## Allocator pressure

`CLR.B (A0)+` retains the private preincrement EA while allocating the zero
scratch and committing A0 writeback. The pressure witness forces the zero
scratch toward the EA's host mapping. The allocator rejects that collision
(`skip=1`), executes the exact opcode natively, stores zero at the old address,
advances A0, and leaves SR=$2714.

## Structural result

The fail-closed structural audit locks:

- one live generator case and no namesake MIDFUNC calls;
- zero-before-store and store-before-flags ordering;
- 48 generated handlers split 24/24 across compiler tables;
- 48 zero sources, 42 memory stores, and 24 width-correct flag tests;
- no flags in no-flags handlers;
- all 15 test encodings, expected register/SR states, memory bytes, replay state,
  special-memory routes, active-corpus entries, and pressure witness;
- all six namesake MIDFUNC rows retained as unreachable.

## Acceptance evidence

- focused exact-native matrix: **15/15**, zero semantic or infrastructure
  failures, score 100;
- complete active-risky replay: **876/876**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **29/29**, including the CLR EA/zero
  witness with `skip=1`, exact native execution, and exact memory/SR replay;
- strict full-JIT negative gate passes, including the expected allocation abort;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after two
  explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly generator `i_CLR`:
  - generator `audited=55`, `serviced=44`, `unreviewed=31`;
  - MIDFUNC remains `audited=262`, `unreachable=118`, `unreviewed=42`;
  - emitter API remains `audited=49`, `unreachable=91`, `unreviewed=154`;
  - raw boundary remains `audited=24`, `unreviewed=58`;
  - CSV: `7c3248e0ee68f3b463ecf242d3bc023c07648ba122736bc030be9051246dab6f`;
  - Markdown: `116420b191f094f65404b8b696256858f83182341393f8750683a6576cc96519`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects `EXG`. Whole-engine closure is not claimed.
