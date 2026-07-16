# AArch64 generic AND emitter audit

Date: 2026-07-16
Branch: `jit-audit-next`

## Scope

This audit covers the complete three-entry reachable generic non-flag-setting
AND encoder cluster selected mechanically after the M68K AND lifecycle:

- `AND_ww3f(Wd, Wn)`, the 32-bit logical-immediate form for `#0x3f`;
- `AND_www(Wd, Wn, Wm)`, the 32-bit register form;
- `AND_xxx(Xd, Xn, Xm)`, the 64-bit register form.

These are AArch64 backend APIs, not the M68K AND lifecycle. Their consumers span
register-count shift/rotate reduction, ADDX/SUBX and NEGX sticky flags, AND and
SR lowering, bit-field insertion, Scc condition composition, special-memory
address filtering, and ROXR word handling. The M68K AND family and its writable
EA repair were closed separately in `AARCH64_JIT_AUDIT_AND_LIFECYCLE.md`.

`AND_ww1f` and `AND_xx1f` have no path from configured AArch64 roots and remain
unreachable. Flag-setting `ANDS_*` APIs are a separate semantic cluster and are
not promoted by similarity.

## Encoding contracts

Each API emits one architectural AArch64 instruction:

- `AND_ww3f` selects the 32-bit logical-immediate encoding with `N=0`,
  `immr=0`, and `imms=5`, which expands to exactly `0x0000003f`;
- `AND_www` selects the 32-bit shifted-register encoding with LSL count zero;
- `AND_xxx` selects the 64-bit shifted-register encoding with LSL count zero;
- W-form results clear the upper 32 bits, while the X form retains all 64 bits;
- all three forms keep `S=0`, so NZCV is unchanged;
- `_W` truncates the assembled expression to `uae_u32` before emission.

The direct probe checks independently assembled words with distinct registers,
high registers, and the architectural five-bit register-field maximum:

```text
AND w9,  w10, #0x3f       12001549
AND w30, w29, #0x3f       120017be
AND wsp, wzr, #0x3f       120017ff
AND w9,  w10, w11         0a0b0149
AND w30, w29, w28         0a1c03be
AND wzr, wzr, wzr         0a1f03ff
AND x12, x13, x14         8a0e01ac
AND x28, x27, x26         8a1a037c
AND xzr, xzr, xzr         8a1f03ff
```

GNU `as` independently emits the same nine words. The
`AND_ww3f(31, 31)` row is deliberately raw-field evidence: logical-immediate
register field 31 names WSP as the destination and WZR as the source. It is not
an assertion that register 31 is an allocator operand. Native semantic vectors
use the proven production domain R0-R17, while the caller census below fails
closed if an out-of-domain variable can reach the API.

## Source caller audit

The four production implementation files contain 83 direct source call
spellings, all currently in `compemu_midfunc_arm64_2.cpp`:

```text
AND_ww3f       31
AND_www        20
AND_xxx        32
```

The structural gate checks both these totals and every current call shape. The
31 immediate-mask calls use only `(REG_WORK1|REG_WORK2, i)`. Register-form
callers use allocator operands (`d`, `d2`, `s`, `adr`, or `imm_reg`) and fixed
`REG_WORK1..4`. The configured AArch64 allocator has `N_REGS=18`; fixed work
registers are R2 through R5. Therefore every current operand is within the
architectural 0..31 field, and any new raw call spelling fails the census until
its ownership and field source are reviewed.

The closure inventory's configured-root references are 25, 16, and 2 for
`AND_ww3f`, `AND_www`, and `AND_xxx`. Those graph counts are deliberately not
presented as direct-call counts: reachable static bodies and header composition
have different token accounting from the fail-closed 83-site raw census.

## Direct native conformance

`jit-test/emitter-and-conformance.cpp` includes the production header, captures
one emitted word at a time, maps short sequences RW then RX, flushes the
instruction cache, and executes them directly on the AArch64 host. Expected
results use ordinary width-bounded unsigned AND operations rather than the
production encoder.

Twenty-seven native vectors cover:

- 24 result vectors, eight for each API;
- immediate-mask inputs around `0x3f`, bit 6, and values above 32 bits;
- W-result zero extension versus true 64-bit X behavior;
- zero, alternating patterns, disjoint masks, and high-bit values;
- destination/source-N alias, destination/source-M alias, and all-three alias;
- one NZCV-preservation vector per API, starting from `N=1, Z=0, C=1, V=0`.

Current direct result:

```text
METRIC emitter_and_apis=3
METRIC emitter_and_exact_words=9
METRIC emitter_and_native_result_vectors=24
METRIC emitter_and_native_flag_vectors=3
METRIC emitter_and_native_vectors=27
METRIC emitter_and_width32=1
METRIC emitter_and_width64=1
METRIC emitter_and_alias_dn=1
METRIC emitter_and_alias_dm=1
METRIC emitter_and_alias_all=1
```

No production encoder defect was found. This is a source-led clean audit, not a
promotion inferred from the already-passing M68K AND semantic matrix.

## Acceptance gates

Post-clean acceptance is:

```text
exact independent encodings         9/9
direct native result vectors       24/24
direct native NZCV vectors           3/3
raw source caller census            83/83
integrated focused exact-native       1/1
complete active-risky              698/698
allocator-pressure                   20/20
closure inventory                  997 rows
```

The clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build passes and produces an
AArch64 ELF. Shell syntax, warning-as-error probe compilation, structural
contracts, complete equivalence, and `git diff --check` pass. All 20 allocator
cells enter native code and match the interpreter.

Pre-clean, post-clean, and explicit post-build regeneration outputs are
byte-identical:

```text
compemu.cpp   3476e73b1d78da29814d529c8493909bf00f85e7928a0e0afa0cb3e3a8f459b5
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

## Closure classification

Promote only `AND_ww3f`, `AND_www`, and `AND_xxx` from unreviewed to audited,
with this report as evidence. Retain `AND_ww1f` and `AND_xx1f` as unreachable.
The deterministic 997-row census changes the emitter layer from 34 audited /
169 unreviewed to 37 audited / 166 unreviewed, with 91 unreachable unchanged.
Closure hashes are:

```text
CSV       40a0054f8b70e0ab45186f6035fdbea00335d51ad50ce4d1047c3c28d761db75
Markdown  158ebbfc9219d3c7dc9861d5ab151c5b22d57bfcb59b1b9edbada437f6b94bfc
```

Do not promote any `ANDS_*` API, the adjacent OR/EOR emitter families, or any
M68K semantic family beyond the separately accepted AND lifecycle report. The
next mechanically selected unreviewed family is the complete M68K EOR
lifecycle; whole-engine closure is not claimed.
