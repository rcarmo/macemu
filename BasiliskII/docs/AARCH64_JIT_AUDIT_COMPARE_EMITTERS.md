# AArch64 generic compare emitter audit

Date: 2026-07-14
Branch: `structural-audit`

## Scope

This audit covers the complete configured generic CMP encoder cluster selected
by the closure inventory:

- `CMP_wi(Wn, i12)` and `CMP_xi(Xn, i12)`;
- `CMP_ww(Wn, Wm)` and `CMP_xx(Xn, Xm)`;
- `CMP_wwLSLi(Wn, Wm, shift)`.

These are AArch64 backend APIs, not M68K compare semantics. Their consumers span
shift/rotate overflow construction, BCD and extend arithmetic, CHK, division,
MULL overflow detection, special-memory routing, block-PC comparison, FPU
classification, and the live M68K CMP/CMPA/CMPM MIDFUNCs. Passing the semantic
compare matrix therefore did not by itself close this layer.

`CMP_wwEX` and `CMP_xxLSLi` have no path from the configured AArch64 roots and
remain unreachable rather than being promoted by similarity.

## Encoding contracts

All five live APIs encode the architectural CMP aliases of flag-setting SUBS
with destination register 31:

- immediate forms select 32- or 64-bit `sf`, set `S`, clear the optional
  immediate shift, place an unsigned 12-bit immediate in bits 21:10, and encode
  `Rd=31`;
- register forms select 32- or 64-bit `sf`, set `S`, use an unextended unshifted
  second register, and encode `Rd=31`;
- `CMP_wwLSLi` selects the 32-bit shifted-register form and places a legal
  five-bit LSL count in bits 14:10;
- `_W` truncates the final expression to `uae_u32` before emission, preventing
  signed intermediate values from widening into host-sized output.

The direct probe checks independently assembled words with nonzero source
register fields:

```text
CMP w9,  #0          7100013f
CMP x11, #4095       f13ffd7f
CMP w9,  w10         6b0a013f
CMP x11, x12         eb0c017f
CMP w9,  w10,LSL#31  6b0a7d3f
```

## Configured caller audit

The configured source census contains 86 call sites:

```text
CMP_wi       49
CMP_xi        2
CMP_ww       23
CMP_xx        6
CMP_wwLSLi    6
```

Every fixed immediate is in `0..4095`. The only nonliteral immediate is `i` in
the three immediate ASL width helpers; all three are reached from
constant-folded register counts masked with `& 0x3f`, so they remain inside the
imm12 domain. The two live shifted-register counts are 16 and 24. The direct
probe additionally exercises legal boundary counts 0 and 31.

The macros deliberately encode an imm12/five-bit field rather than accepting an
arbitrary integer. Current callers satisfy that contract; structural census and
argument checks fail closed if a future configured caller exceeds it.

## Direct native conformance

`jit-test/emitter-compare-conformance.cpp` includes the production header,
captures each emitted word, places short sequences in executable memory, flushes
the instruction cache, executes them on the AArch64 host, and reads NZCV. The
expected oracle independently computes width-bounded subtraction flags.

Twenty native vectors cover:

- 32- and 64-bit equal, borrow, carry/no-borrow, and signed-overflow states;
- W-register upper-half truncation versus true X-register 64-bit behavior;
- immediate zero, one, and the `0xfff` imm12 boundary;
- shifted-register counts 0, 1, 16, and 31;
- nonzero `Rn`/`Rm` fields and exact word encoding.

The probe is compiled with `-Wall -Wextra -Werror`, runs under a bounded timeout,
and is part of every `jit-test/run.sh` acceptance invocation. Current result:

```text
METRIC emitter_compare_exact_words=5
METRIC emitter_compare_native_vectors=20
METRIC emitter_compare_width32=1
METRIC emitter_compare_width64=1
```

No encoder defect was found. This is a source-led clean audit, not a claim based
only on existing opcode equivalence.

## Acceptance gates

Post-clean acceptance is:

```text
exact independent encodings       5/5
native NZCV vectors              20/20
integrated focused exact-native    1/1
complete active-risky            693/693
allocator-pressure                14/14
strict fail-closed contracts        6/6
closure inventory                997 rows
```

The integrated structural gate also reports exactly five APIs, 86 configured
call sites, and 20 native vectors. Shell syntax, warning-as-error probe
compilation, structural contracts, closure regeneration, `git diff --check`,
and a clean build pass. Pre-clean, clean-build, and explicit post-build
regeneration outputs match byte-for-byte at generated `compemu.cpp` SHA-256
`dff217a685f0fe8727ad98630750d1ea99c906ece78e0e4a88fd25489e5ae16a`.

## Closure classification

Promote the five live APIs listed in scope from unreviewed to audited. Retain
`CMP_wwEX` and `CMP_xxLSLi` as unreachable. This report does not promote generic
branch consumers, NEG encoders, or any unrelated arithmetic emitter API.
