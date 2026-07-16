# AArch64 generic ADD emitter audit

Date: 2026-07-16
Branch: `jit-audit-next`

## Scope

This audit covers the complete seven-entry reachable generic non-flag-setting
ADD encoder cluster selected by the closure inventory:

- `ADD_wwi(Wd, Wn, i12)` and `ADD_xxi(Xd, Xn, i12)`;
- `ADD_wwwEX(Wd, Wn, Wm, extend)` and `ADD_xxwEX(Xd, Xn, Wm, extend)`;
- `ADD_www(Wd, Wn, Wm)` and `ADD_xxx(Xd, Xn, Xm)`;
- `ADD_wwwLSLi(Wd, Wn, Wm, shift)`.

These are AArch64 backend APIs, not the M68K ADD lifecycle. Their consumers span
EA construction, host-pointer arithmetic, allocator helpers, BCD and ADDX cores,
FPU addressing, special-memory routing, and diagnostic observer preservation.
The M68K ADD family was closed separately in
`AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md`.

`ADD_xxxLSLi` has no path from configured AArch64 roots and remains unreachable.
Flag-setting `ADDS_*`, carry-consuming `ADC_*`, and unrelated arithmetic APIs
are outside this tranche and are not promoted by similarity.

## Encoding contracts

All seven APIs emit one architectural AArch64 ADD instruction:

- immediate forms select 32- or 64-bit width, clear the optional `LSL #12`
  immediate-shift bit, and place an unsigned 12-bit immediate in bits 21:10;
- `ADD_wwwEX` selects the 32-bit extended-register form, while `ADD_xxwEX`
  selects a 64-bit destination and extends a W source according to option bits
  15:13;
- plain register forms select the 32- or 64-bit shifted-register encoding with
  shift kind LSL and count zero;
- `ADD_wwwLSLi` selects 32-bit shifted-register ADD and places a legal five-bit
  LSL count in bits 14:10;
- all forms keep `S=0`, so NZCV must remain unchanged;
- `_W` truncates the assembled expression to `uae_u32` before emission.

The direct probe checks independently assembled words with nonzero register
fields and boundary field values:

```text
ADD w9,  w10, #0             11000149
ADD w9,  w10, #4095          113ffd49
ADD x11, x12, #0             9100018b
ADD x11, x12, #4095          913ffd8b
ADD w13, w14, w15, UXTB      0b2f01cd
ADD w13, w14, w15, SXTW      0b2fc1cd
ADD x16, x17, w18, UXTW      8b324230
ADD x16, x17, w18, SXTW      8b32c230
ADD w19, w20, w21            0b150293
ADD x22, x23, x24            8b1802f6
ADD w25, w26, w27, LSL #0    0b1b0359
ADD w25, w26, w27, LSL #31   0b1b7f59
```

## Source caller audit

The four production implementation files contain 72 direct source call
spellings. The structural gate audits all of them, including definitions that
are dormant in the configured graph, rather than relying on reachability to
excuse an unsafe field:

```text
ADD_wwi       17
ADD_xxi        7
ADD_wwwEX      1
ADD_xxwEX      9
ADD_www       27
ADD_xxx        3
ADD_wwwLSLi    8
```

The immediate callers are bounded before emission:

- EA and host-pointer offsets use ADD only in `0..0xfff`; negative values route
  through SUB and larger values are materialised in a register or rejected;
- IM8 inputs and `v & 0xff` remain inside imm12;
- word/long immediate helpers guard `v`, `tmp`, and constant register values at
  `0xfff` before selecting the immediate form;
- fixed values are 1, 4, 6, `0x60`, and the 240-byte observer frame.

The sole `ADD_wwwEX` caller uses `EX_SXTH`. The nine `ADD_xxwEX` callers use
seven `EX_UXTW` and two SXTW-equivalent options (`EX_SXTW` and literal 6). The
eight shifted-register callers use two explicit masked counts, two scale
switches restricted to 0..3, one fixed count 2, and three fixed counts 1.

The closure inventory records 49 configured root-token references across the
seven APIs. That value is deliberately not presented as a direct-call count:
header composition can add a token and reachable static helper bodies can hide
one from the MIDFUNC-only graph. The 72-site raw census above is the
fail-closed field-contract gate.

## Direct native conformance

`jit-test/emitter-add-conformance.cpp` includes the production header, captures
one emitted word at a time, maps short sequences RW then RX, flushes the
instruction cache, and executes them directly on the AArch64 host. Expected
results are computed independently with width-bounded unsigned arithmetic and
explicit byte/halfword/word sign or zero extension.

Forty-six native vectors cover:

- 39 result vectors across all seven APIs;
- 32-bit W-result truncation and true 64-bit X arithmetic, including wraparound;
- immediate zero, one, and the `0xfff` boundary;
- UXTB, UXTH, UXTW, SXTB, SXTH, and SXTW behavior;
- LSL counts 0, 1, 16, and 31;
- source/destination aliasing through the ABI argument/result register;
- one explicit NZCV-preservation vector for each API, starting from `N=1,
  Z=0, C=1, V=0`.

Current direct result:

```text
METRIC emitter_add_apis=7
METRIC emitter_add_exact_words=12
METRIC emitter_add_native_result_vectors=39
METRIC emitter_add_native_flag_vectors=7
METRIC emitter_add_native_vectors=46
METRIC emitter_add_width32=1
METRIC emitter_add_width64=1
```

No production encoder defect was found. This is a source-led clean audit, not a
promotion inferred from the already-passing M68K ADD semantic matrix.

## Acceptance gates

Post-clean acceptance is:

```text
exact independent encodings       12/12
direct native result vectors      39/39
direct native NZCV vectors          7/7
raw source caller census           72/72
integrated focused exact-native      1/1
complete active-risky             695/695
allocator-pressure                  18/18
closure inventory                 997 rows
```

The clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build passes. The focused and
complete runs report zero equivalence or infrastructure failures; every
allocator-pressure cell enters native code and matches the interpreter. Shell
syntax, warning-as-error probe compilation, structural contracts, closure
regeneration, and `git diff --check` pass.

Pre-clean, clean-build, and two explicit post-build regeneration outputs are
byte-identical:

```text
compemu.cpp   07a4be8b0d94300d8290c9b63110815856e7f03d54a97053f5a8691a8b5e1f82
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

## Closure classification

Promote only the seven APIs listed in scope from unreviewed to audited, with
this report as evidence. Retain `ADD_xxxLSLi` as unreachable. The deterministic
997-row census changes the emitter layer from 27 audited / 176 unreviewed to 34
audited / 169 unreviewed, with 91 unreachable unchanged. Closure hashes are:

```text
CSV       479e0b36bf600646e190882e710301a870a6267ad385dd751e96c89e9d78960e
Markdown  ab2e58db176a440975d4d7f897eb14f16ba212fef14e8636735bc846076eaac0
```

This report does not promote ADDS, ADC, unrelated arithmetic emitters, or any
M68K semantic family beyond the separately accepted ADD lifecycle report. The
next mechanically selected unreviewed family is `AND`; whole-engine closure is
not claimed.
