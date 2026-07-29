# AArch64 JIT AND-with-flags emitter audit

Date: 2026-07-27

Base: `31d17c79` (`master`, published ADDS emitter closure)

## Scope

This tranche originally audited the three reachable ANDS encoders selected by
`ANDS_ww3f` and now includes the X-register form reached by strict native-entry
accounting:

- `emitter_api,ANDS_ww3f`
- `emitter_api,ANDS_www`
- `emitter_api,ANDS_xxx`
- `emitter_api,ANDS_xx7fff`

The other ANDS definitions remain configured-unreachable:

- `ANDS_ww1f`, `ANDS_ww7f`;
- `ANDS_xx1f`.

No production repair is required.

## Configured and raw census

| API | Configured references | Raw calls | Role |
|---|---:|---:|---|
| `ANDS_ww3f` | 14 | 14 | mask register shift/rotate counts to six bits and set Z for count-zero routing |
| `ANDS_www` | 11 | 12 | W logical result/flags in AND and bit/division paths |
| `ANDS_xxx` | 1 | 1 | test the 64-bit strict native-entry count for a power of two |
| `ANDS_xx7fff` | 1 | 1 | mask/test the 15-bit extended-FP exponent |

The additional raw `ANDS_www` call is inside `jnf_DIVS`. Configured DIVS
unconditionally selects `jff_DIVS` for exception and overflow flag semantics,
so that spelling is service-dominated and is not an extra configured root.
The closure inventory's 11-reference count is therefore intentional.

`ANDS_ww3f` parents consume the result and Z flag to separate effective count
zero from nonzero while retaining all six 68K count bits. `ANDS_xxx` must remain
X-width because the strict evidence counter is 64-bit; its sole caller tests
`count & (count - 1)`. `ANDS_xx7fff` must remain X-width because its source also
carries extended-format sign state.

## Encoding and flag contract

```text
ANDS Wd,Wn,Wm       01101010000 Wm 000000 Wn Wd
ANDS Xd,Xn,Xm       11101010000 Xm 000000 Xn Xd
ANDS Wd,Wn,#0x3f    N=0 immr=0 imms=5 Wn Wd
ANDS Xd,Xn,#0x7fff  N=1 immr=0 imms=14 Xn Xd
```

All forms publish logical flags:

- N from the sized result's top bit;
- Z from the sized result being zero;
- C = 0;
- V = 0.

W forms truncate/zero-extend to 32 bits. The X immediate form preserves
64-bit input width before applying `0x7fff`.

Exact controls:

```text
ANDS w9,w10,w11       6a0b0149
TST  wzr,wzr           6a1f03ff
ANDS x9,x10,x11       ea0b0149
TST  xzr,xzr           ea1f03ff
ANDS w9,w10,#0x3f      72001549
TST  wzr,#0x3f         720017ff
ANDS x9,x10,#0x7fff    f2403949
TST  xzr,#0x7fff       f2403bff
```

## Direct native conformance

`jit-test/emitter-ands-conformance.cpp` includes the production header and
executes each sequence from RW-then-RX pages after instruction-cache flush.
It uses an independent sized logical-result/NZCV oracle under hostile initial
flags.

Coverage:

- 12 W-register cases across zero, negative, W truncation, disjoint and
  overlapping masks;
- 12 X-register cases across zero, negative, disjoint/overlapping masks,
  upper-32-bit significance, and destination/source aliases;
- 12 six-bit mask cases including 0, 1, 63, 64, high W bits, and nonzero upper
  32-bit input;
- 12 X 15-bit mask cases including 0, `0x7fff`, `0x8000`, sign/high bits, and
  mixed 64-bit values;
- destination-distinct and destination/source aliases;
- explicit C/V clearing for every case.

Result:

```text
METRIC emitter_ands_apis=4
METRIC emitter_ands_exact_words=8
METRIC emitter_ands_register_vectors=12
METRIC emitter_ands_xregister_vectors=12
METRIC emitter_ands_mask3f_vectors=12
METRIC emitter_ands_mask7fff_vectors=12
METRIC emitter_ands_alias_vectors=28
METRIC emitter_ands_native_vectors=48
METRIC emitter_ands_cv_clear=1
```

The complete emitter phase passes with the suite installed after ADDS and
before the previously accepted semantic-family gates.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- any register or logical-immediate encoding-field change;
- inventory drift from `14 + 11 + 1`;
- raw-call drift from `14 + 12 + 1`;
- loss of count-mask, W logical/division, or X exponent caller classes;
- loss of W/X width, alias, boundary, independent N/Z, or C/V-clear witnesses;
- omission of the bounded suite from the complete emitter phase;
- loss of configured DIVS service dominance over `jnf_DIVS`.

## Acceptance results

The accepted clean-source epoch passes:

- direct ANDS conformance: **8 exact words + 48 native result/NZCV vectors**;
- complete emitter phase: all 27 bounded suites pass;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated inventory/source hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: **APPROVE**.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
01a8068d38961974e4a8c55830238ea75b3d3d588b268b95c3cd675b41af2feb  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
fa271ce3faadf4f0e5bcb8b4e8fbd1738ab4c927f28d8c2a3d3cc9fc9bb2a914  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly:

```text
emitter_api,ANDS_ww3f: unreviewed -> audited
emitter_api,ANDS_www: unreviewed -> audited
emitter_api,ANDS_xx7fff: unreviewed -> audited
```

No unreachable ANDS form changes classification. The 2026-07-29 extension moves `emitter_api,ANDS_xxx` from unreachable to
audited when strict native-entry accounting makes it reachable. The complete
closure inventory remains at zero unreviewed rows.

## Reproduction

```sh
./jit-test/emitter-ands-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
