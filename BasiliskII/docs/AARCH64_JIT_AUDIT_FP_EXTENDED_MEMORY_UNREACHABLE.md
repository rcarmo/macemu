# AArch64 JIT legacy extended-memory conversion retirement

Date: 2026-07-26
Base: `d322f801`

## Scope

This checkpoint classifies four lower-layer rows:

- `midfunc,fp_from_exten_mr` and `raw_boundary,raw_fp_from_exten_mr`;
- `midfunc,fp_to_exten_rm` and `raw_boundary,raw_fp_to_exten_rm`.

These chains serialize or import a 12-byte extended image through the native
binary64 FP shadow. They cannot preserve the architectural 64-bit significand,
15-bit exponent range, or exact NaN metadata. The configured AArch64 compiler
therefore uses exact MPFR service before every residual composition.

## Configured roots

Full configured preprocessing expands the compatibility macros to exactly six
call sites plus the two extern declarations:

- one `fp_to_exten_rm` call in `get_fp_value(size=2)`;
- one `fp_from_exten_mr` call in `put_fp_value(size=2)`;
- two `fp_from_exten_mr` calls in the static FMOVEM store loops; and
- two `fp_to_exten_rm` calls in the static FMOVEM load loops.

The ordinary source and destination calls are dominated by their size-2
AArch64 rejection before memory-EA acquisition. Static FMOVEM is dominated by
the configured exact-service return before `get_fp_ad(opcode)`. Dynamic FMOVEM
fails still earlier on each list-form selector and contains no conversion call.
FMOVECR also enters exact service before selector dispatch, and configured
`USE_LONG_DOUBLE`/`USE_QUAD_DOUBLE` constant arms are absent.

No configured generated compiler, support path, compatibility wrapper, or
reachable MIDFUNC parent can execute either MIDFUNC. Both raw boundaries are
therefore definition-only. Their generic AArch64 emitters remain independently
classified.

## Positive runtime controls

`jit-test/fp-extended-memory-retirement-matrix.sh` composes the accepted exact
service gates:

```text
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
FPP_FMOVEM_STATIC_MATRIX service_pass=10 strict_pass=3 fail=0 total=13
FPP_FMOVEM_DYNAMIC_MATRIX service_pass=12 strict_pass=3 fail=0 total=15
FP_EXTENDED_MEMORY_RETIREMENT service=30 strict=10 fail=0 total=40
```

The 30 service cases cover exact values beyond binary64 precision and range,
NaN metadata, signed zero, guarded ordinary memory, static and dynamic masks,
all maintained EA classes, writeback, FP register ordering, integer-CCR
preservation, visible fallback, and CoW isolation. Ten strict cases require
rejection before native completion for ordinary and FMOVEM source/destination
forms.

## Closure decision

Exactly four rows move from **unreviewed** to **unreachable**. No executable or
generated source and no generic emitter classification changes. The historical
ordinary-FMOVE.X report remains the semantic-service checkpoint; this report
supersedes only its provisional lower-layer closure decision now that FMOVEM,
FMOVECR, and the complete FPP lifecycle have separately been accepted.
Whole-engine closure is not claimed.

## Acceptance

- configured service/strict control: **30 + 10 / 40**;
- structural audit: pass for exact six-call configured census, ordinary and
  FMOVEM dominance, dynamic-list exclusion, MIDFUNC/raw body ownership, and
  focused wrapper;
- deterministic closure regeneration: 998 rows with an exact four-row delta:
  - CSV: `daa3bf780db91a160fb6bd799b0cae23e9bdee77a982e3bdf9bb08a6764e9840`;
  - Markdown: `280fb2a0cd0d610331284f8c9c61a5ea975678223201302f844c75e1d47aac69`;
- independent bounded review: **APPROVE**; all ordinary, FMOVEM, FMOVECR,
  configured-preprocessor, MIDFUNC-parent, and raw definition-only roots were
  checked with no missing caller or overclaim;
- executable/generated source unchanged from `d322f801`;
- shell syntax and `git diff --check`: pass.
