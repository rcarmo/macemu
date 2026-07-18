# AArch64 JIT FPP sign-operation subtranche

## Scope

This bounded `i_FPP` subtranche covers the six sign-operation selectors:
ordinary `FABS`/`FNEG`, forced-single `FSABS`/`FSNEG`, and forced-double
`FDABS`/`FDNEG`. It also repairs the shared native/interpreter FPU ownership
boundary exposed by replaying those operations beside native JIT blocks.

On AArch64 the complete sign family is now one exact MPFR service boundary.
Other arithmetic, transcendental, remainder/scale, FMOVEM/control operations,
and the complete `i_FPP` lifecycle remain separate.

## Defects found and repaired

### Lossy native sign operations

The native implementation acquired every source through the binary64 shadow.
That is incomplete even for ordinary FABS/FNEG: an architectural 80-bit value
can have a 64-bit significand or exponent outside binary64 range, so merely
reaching the host `FABS D`/`FNEG D` instruction can round or overflow before the
sign change. FS/FD variants additionally require forced 24-/53-bit precision,
FPCR-directed rounding, and exact operation/accrued exceptions.

All six AArch64 selectors now fail before operand acquisition and execute via
the existing MPFR service. This preserves extended significands, range, NaN
metadata, signed zero, FPCR precision/rounding, and FPSR.

### Unconditional shadow publication

JIT exit previously copied all eight binary64 shadows back into MPFR. An
integer-only native block could therefore narrow untouched FP registers. A
serviced FPP opcode could also set a correct MPFR FPSR, only for the stale lazy
native result to overwrite its condition-code byte on exit.

The runtime now has an FP dirty mask. Native FP writes mark FP0-FP7 or the lazy
FP result at the exact emitted write point. JIT entry imports MPFR into shadows
and clears ownership; C exit and interpreter fallback publish only dirty native
values and clear ownership again.

### Mixed-mode call and CCR ownership

The first repair exposed two ABI defects in consecutive interpreter fallbacks:

1. synchronisation and opcode C calls are permitted to clobber host NZCV;
2. `FLAGTMP` could remain associated with a caller-clobbered register after a
   previous reload, so the following fallback reused stale CCR state.

The mixed-mode path now materialises live state and drops all allocator
associations before its first C call, publishes dirty native FP state, forms
x0/x1 only after that synchroniser, executes the interpreter opcode, re-imports
MPFR state, and rematerialises host NZCV from architectural `regflags.nzcv`.
Synchronisation calls preserve the incoming host NZCV while performing their
private bookkeeping.

## Runtime evidence

`bun jit-test/fpp-sign-fallback-matrix.ts` has 31 service vectors with fixed
80-bit and FPSR oracles. Every sequence loads an 80-bit MPFR source, executes
one sign selector, stores an 80-bit result, and re-enters the compiled sequence.
It requires exactly three visible FPP service boundaries, guarded output bytes,
unchanged A0 and integer SR, and no crash.

Covered semantics include:

- ordinary wide values that differ below binary64 precision;
- positive/negative zero, infinity, and quiet NaNs with payload/sign;
- ordinary single and double FPCR precision under all four rounding modes;
- FSABS/FSNEG halfway values under all four rounding directions;
- FDABS/FDNEG halfway values and directed rounding;
- finite maximum-extended overflow to forced single/double infinity;
- FP7 self-alias and maximum source/destination fields;
- prior accrued FPSR preservation;
- replay after adjacent native integer execution, including exact `SR=271f`.

Six strict cases cover every selector with FP7 self-alias. They require strict
opcode rejection at the sign instruction, no native entry, and no SIGSEGV.

Accepted focused result:

```text
FPP_SIGN_FALLBACK_MATRIX service_pass=31 strict_pass=6 fail=0 total=37
```

Adjacent-family composition evidence:

```text
FPP_COMPARE_NATIVE_MATRIX pass=176 fail=0 total=176
FPP_FTST_NATIVE_MATRIX pass=128 fail=0 total=128
FPP_EXPLICIT_MOVE_FALLBACK_MATRIX service_pass=13 strict_pass=2 fail=0 total=15
FPP_FMOVECR_FALLBACK_MATRIX service_pass=36 strict_pass=3 fail=0 total=39
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
FPP_FMOVE_PACKED_FALLBACK_MATRIX service_pass=9 strict_pass=4 fail=0 total=13
```

## Structural contracts

- all six AArch64 selectors must issue `FAIL(1)` and return before
  `get_fp_value()`;
- MPFR-to-shadow import must clear dirty ownership;
- native architectural FP writes must set the corresponding runtime bit;
- shadow-to-MPFR publication must touch only dirty registers/result state;
- mixed fallback must materialise and disassociate allocator state before C;
- interpreter arguments must be formed after FP publication;
- the opcode call must precede MPFR re-import and CCR rematerialisation;
- fixed-oracle service and strict matrices must remain fail-closed at 31 and 6.

## Closure decision

No pre-existing closure row is promoted. The new
`compemu_raw_call_preserve_nzcv` boundary expands the deterministic inventory
to 998 rows and is classified **audited** by this report's focused ABI, NZCV,
ordering, structural, and replay evidence.

A later configured-root reachability audit corrected the original conservative
classification of the retained native sign chain. On AArch64 every
FABS/FSABS/FDABS and FNEG/FSNEG/FDNEG selector enters semantic service before
operand acquisition; there is no other configured caller. Therefore
`fabs_rr`/`fneg_rr`, `raw_fabs_rr`/`raw_fneg_rr`, and `FABS_dd`/`FNEG_dd` are
**unreachable**, with positive ordered control-flow proofs in
`closure-inventory.ts` and `structural-audit.ts`. This is retirement, not native
acceptance: the retained post-return code is not executed. `generator,i_FPP`
remains **unreviewed** pending the remaining subfamilies.
