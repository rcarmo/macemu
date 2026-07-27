# AArch64 generic SUB/SUBS emitter audit

Date: 2026-07-16
Branch: `jit-audit-next`

## Scope

This audit covers the complete seven-entry reachable generic AArch64 SUB/SUBS
encoder cluster selected mechanically by the closure inventory:

- `SUB_wwi(Wd, Wn, i12)` and `SUB_xxi(Xd, Xn, i12)`;
- `SUB_www(Wd, Wn, Wm)` and `SUB_xxx(Xd, Xn, Xm)`;
- `SUBS_wwi(Wd, Wn, i12)` and `SUBS_www(Wd, Wn, Wm)`;
- `SUBS_wwwLSLi(Wd, Wn, Wm, shift)`.

These are AArch64 backend APIs, not the M68K SUB lifecycle. Their consumers
span EA and host-pointer arithmetic, no-flags SUB/SUBA lowering, flag-producing
SUB lowering, DBcc support, division and shift helpers, cycle accounting,
observer preservation, and legacy compatibility routing. The M68K SUB family
was closed separately in `AARCH64_JIT_AUDIT_SUB_LIFECYCLE.md`.

`SUB_wwwEX`, `SUBS_xxi`, `SUBS_wwish`, `SUBS_xxish`, `SUBS_xxx`, and
`SUBS_xxxLSLi` have no path from configured AArch64 roots and remain
unreachable. `SBCS_www` is reachable but belongs to the separate borrow/carry
cluster; it is not promoted by similarity.

## Encoding contracts

All seven APIs emit one architectural AArch64 subtraction instruction:

- immediate forms select 32- or 64-bit width, clear the optional `LSL #12`
  immediate-shift bit, and place an unsigned 12-bit immediate in bits 21:10;
- plain register forms select the 32- or 64-bit shifted-register encoding with
  shift kind LSL and count zero;
- `SUBS_wwwLSLi` selects 32-bit shifted-register SUBS and places a legal
  five-bit LSL count in bits 14:10;
- `SUB_*` keeps `S=0`, so NZCV must remain unchanged;
- `SUBS_*` sets `S=1`, so native NZCV must match 32-bit subtraction exactly:
  C is no-borrow and V is signed overflow;
- `_W` truncates the assembled expression to `uae_u32` before emission.

The direct probe checks independently assembled words with nonzero and maximum
register fields plus immediate and shift boundaries:

```text
SUB  w9,  w10, #0                    51000149
SUB  wsp, wsp, #4095                 513fffff
SUB  x11, x12, #0                    d100018b
SUB  sp,  sp,  #4095                 d13fffff
SUB  wzr, wzr, wzr                   4b1f03ff
SUB  xzr, xzr, xzr                   cb1f03ff
SUBS w9,  w10, #0                    71000149
SUBS wzr, wsp, #4095                 713fffff
SUBS wzr, wzr, wzr                   6b1f03ff
SUBS w25, w26, w27, LSL #0           6b1b0359
SUBS wzr, wzr, wzr, LSL #31          6b1f7fff
```

A standalone `aarch64-linux-gnu-objdump` decode confirms the maximum-field
words as the expected SP/ZR architectural aliases rather than a truncated or
width-swapped encoding.

## Source caller audit

At acceptance, the four production implementation files contained 115 direct
source call spellings. The later accepted `sub_l_ri` lifecycle audit retired
one dead pointer-width `SUB_xxi` branch, leaving 114. The structural gate audits
all remaining spellings, including definitions that are dormant in the
configured graph, rather than relying on reachability to excuse an unsafe
field:

```text
SUB_wwi          58
SUB_xxi           5
SUB_www          36
SUB_xxx           3
SUBS_wwi          6
SUBS_www          3
SUBS_wwwLSLi      3
```

The immediate and shift fields are bounded before emission:

- signed EA and host-pointer offsets choose immediate SUB only for
  `-0xfff..-1`, then negate the bounded value;
- guest-only `sub_l_ri` and `arm_SUB_l_ri8` receive `IM8` values; `sub_l_ri`
  now emits only `SUB_wwi` and rejects pointer-width state;
- ADDA negative immediates use the immediate form only inside `-0xfff..-1`;
- no-flags and flags-live long SUB use immediate forms only for `0..4095`;
- byte immediates are masked with `& 0xff`;
- code-generation cycle decrements are guarded by `0..0xfff`, while the fixed
  observer frame is 240 bytes;
- the remaining fixed immediates are all inside imm12;
- all three shifted SUBS callers use fixed legal W shifts: 24, 16, and 16.

The structural gate records the complete ordered immediate/shift argument
lists as well as raw call counts, so a new call or changed field source fails
closed. The closure inventory records 79 configured root-token references
across the seven APIs. That value is not presented as a direct-call count:
header composition and configured reachability deliberately differ from the
115-site raw field-contract census.

## Direct native conformance

`jit-test/emitter-sub-conformance.cpp` includes the production header, captures
one emitted word at a time, maps short sequences RW then RX, flushes the
instruction cache, and executes them directly on the AArch64 host. Expected
results and NZCV are computed independently with width-bounded unsigned
subtraction, explicit no-borrow C, and the architectural signed-overflow test.

Seventy native vectors cover:

- 42 result vectors across all seven APIs;
- W-result truncation and true 64-bit X arithmetic, including wraparound;
- immediate zero, one, and the `0xfff` boundary;
- LSL counts 0, 1, 16, and 31;
- destination/lhs and destination/rhs aliases for register forms;
- four explicit NZCV-preservation vectors for every `S=0` API;
- 24 `S=1` NZCV vectors spanning zero, negative, borrow, no-borrow, and signed
  overflow in both directions where the operand form permits it;
- hostile initial NZCV before every flag-setting sequence, proving flags come
  from the emitted SUBS instruction rather than retained state.

Current direct result:

```text
METRIC emitter_sub_apis=7
METRIC emitter_sub_exact_words=11
METRIC emitter_sub_native_result_vectors=42
METRIC emitter_sub_native_preserve_vectors=4
METRIC emitter_sub_native_nzcv_vectors=24
METRIC emitter_sub_native_vectors=70
METRIC emitter_sub_width32=1
METRIC emitter_sub_width64=1
```

No production encoder defect was found. This is a source-led clean audit, not a
promotion inferred from the already-passing M68K SUB semantic matrix.

## Acceptance gates

Post-clean acceptance is:

```text
exact independent encodings       11/11
direct native result vectors      42/42
direct native NZCV vectors         28/28
raw source caller census         115/115
integrated focused exact-native      1/1
complete active-risky             798/798
allocator-pressure                  26/26
closure inventory                 997 rows
```

The clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build passes. The focused and
complete runs report zero equivalence or infrastructure failures; every
allocator-pressure cell enters native code and matches the interpreter. Shell
syntax, warning-as-error probe compilation, structural contracts, closure
regeneration, and `git diff --check` pass.

Pre-clean, clean-build, and explicit post-build regeneration outputs are
byte-identical:

```text
compemu.cpp   17e9d3510ceb4e479d6e64520b90433278f6a15cfcf1c7d5daf1d3f36a4d12e0
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

## Closure classification

Promote only the seven APIs listed in scope from unreviewed to audited, with
this report as evidence. Retain the six unreachable SUB/SUBS forms as
unreachable and leave reachable `SBCS_www` unreviewed. The deterministic
997-row census changes the emitter layer from 42 audited / 161 unreviewed to 49
audited / 154 unreviewed, with 91 unreachable unchanged. Closure hashes are:

```text
CSV       07805a02a553935014df30a209ffdda1988625f4016289130428bde7b3c731d5
Markdown  ba52ff9502ab9f9aa828981f423e71840439c1ad1cf5df9259d5ab8134f1eab8
```

This report does not promote SBC/SBCS, unrelated arithmetic emitters, or any
M68K semantic family beyond the separately accepted SUB lifecycle report.
Whole-engine closure is not claimed.
