# AArch64 JIT untranslated-opcode counter boundary retirement

Date: 2026-07-28

Base: `43af6b50` (`master`, published raw deferred-exception closure)

## Scope

This mechanically selected checkpoint classifies only
`raw_boundary,compemu_raw_inc_opcount`. The retained body increments the
32-bit `raw_cputbl_count[opcode]` profiling table entry through a host pointer
stored in `regs.raw_cputbl_count`. It is distinct from the accepted live block
metadata counters `compemu_raw_dec_m` and `compemu_raw_inc_m`.

## Configured reachability

The sole source call is in the interpreter-fallback compiler path in
`compemu_support_arm.cpp`, guarded by:

```c
#ifdef PROFILE_UNTRANSLATED_INSNS
compemu_raw_inc_opcount(opcode);
#endif
```

The configured AArch64 Makefile does not define either `DEBUG` or
`PROFILE_UNTRANSLATED_INSNS`. The actual compiled translation unit is
`compemu_support.cpp`; it includes `compemu_support_arm.cpp` before its later
non-AArch64 `#if DEBUG` profiling definitions. Directive-only preprocessing of
that complete configured translation unit therefore has zero
`compemu_raw_inc_opcount(opcode)` calls. The clean `compemu_support.o` binary
likewise has no symbol for the inlined boundary. No generated, compatibility,
FPU, or reachable MIDFUNC root names it.

The remaining two configured references are exactly the LOWFUNC/LENDFUNC
definition markers. Its retained body still consists of:

1. loading the `regs.raw_cputbl_count` host pointer;
2. materialising the unsigned 16-bit opcode index;
3. indexed 32-bit load with scale 2;
4. wrapping 32-bit increment by one; and
5. indexed 32-bit store with scale 2.

`LDR_xXi`, `MOV_xi`, `LDR_wXxLSLi`, `ADD_wwi`, and `STR_wXxLSLi` remain
independently classified; retiring this parent does not audit or retire those
reachable generic emitter APIs.

## Closure decision

Exactly one row moves from **unreviewed** to **unreachable**. The deterministic
998-row inventory keeps all production source unchanged. Raw-boundary totals
become 47 audited / 29 unreachable / 7 unreviewed; 70 emitter APIs remain
unreviewed. Whole-engine closure is not claimed.

## Acceptance

Final acceptance:

- actual configured `compemu_support.cpp` translation-unit preprocessing:
  **zero active calls**;
- clean `obj/compemu_support.o`: no `compemu_raw_inc_opcount` symbol;
- raw definition-marker references: **2**;
- retained child emitters: **5**, with all prior independent classifications
  unchanged;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row moved to
  unreachable, leaving **70 emitter APIs** and **7 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `54f2e06ca87c61014b7f2129ca532dc31ba76871729e3681827a0ea7f8716603`,
  Markdown
  `71f98e0f5f2c37c56aae27ff27672b919161609561e4eff06328a5e77d667708`,
  and unchanged generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial reject because direct preprocessing of
  the included ARM implementation did not prove the actual wrapper translation
  unit; corrected by preprocessing `compemu_support.cpp`, pinning include/macro
  ordering, and checking the clean object; final re-review: **approve**.

## Reproduction

```sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
