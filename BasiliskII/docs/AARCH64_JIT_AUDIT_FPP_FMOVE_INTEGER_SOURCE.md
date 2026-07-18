# AArch64 JIT FMOVE signed-integer source lifecycle

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `522ca63d`

## Scope

This bounded checkpoint closes the configured signed byte, word, and long
integer-to-FP source paths used by ordinary FMOVE:

- `fmov_b_rr` -> `raw_fmov_b_rr`;
- `fmov_w_rr` -> `raw_fmov_w_rr`;
- `fmov_l_rr` -> `raw_fmov_l_rr`.

Each width has exactly two configured compiler roots: direct Dn input and the
fetched/immediate source path through S2. IEEE single/double, FP-register,
memory-EA ownership, FP-to-integer destinations, explicit precision, and the
complete `generator,i_FPP` lifecycle remain separate.

## Lowering and ownership

The byte and word raw paths first use 32-bit `SXTB_ww`/`SXTH_ww` sign extension
into `REG_WORK1`, deliberately clearing the upper 32 bits, then convert the
signed W value with `SCVTF_dw`. Long input converts its signed 32-bit W value
directly with `SCVTF_dw`. Every signed 32-bit integer is exactly representable
in binary64, so these paths are independent of FPCR rounding and introduce no
new FPSR exception.

Each MIDFUNC acquires the integer source before allocating the FP destination,
emits while both are live, then releases the FP destination before the integer
source. Integer and FP values use separate allocator banks; D7->FP7 cases cover
the maximum same-number cross-bank fields.

`SCVTF_dw` remains independently audited and reachable at six source sites.
`SXTB_ww`, `SXTH_ww`, and their generic `SBFM_wwii` lowering remain separate
encoder contracts; `SXTH_ww` also has three live integer MIDFUNC sites. No
generic emitter row is promoted by this compound lifecycle checkpoint.

## Exact-native evidence

The maintained `fpp-fmove-source-matrix.ts` now has a fail-closed
`GROUP=integer` selector based on encoded source formats 0/4/6. It passes all
18 signed-integer routes:

```text
FPP_FMOVE_SOURCE_MATRIX pass=18 fail=0 total=18
```

Coverage includes:

- negative and positive byte/word/long boundaries;
- byte/word values with both clean and poisoned upper source bits;
- long minimum, maximum, and minus one;
- immediate and Dn roots for all three widths;
- D7 source and FP7 destination maximum fields;
- exact binary64 shadow images and FPSR condition classes;
- `SR=0x271f`, second-pass exact native entry, and strict no-fallback execution.

The full maintained source matrix remains green:

```text
FPP_FMOVE_SOURCE_MATRIX pass=29 fail=0 total=29
```

Unknown `GROUP` values fail closed.

## Closure decision

The authoritative inventory promotes exactly six rows to **audited**:

- `midfunc,fmov_b_rr`, `midfunc,fmov_w_rr`, `midfunc,fmov_l_rr`;
- `raw_boundary,raw_fmov_b_rr`, `raw_boundary,raw_fmov_w_rr`,
  `raw_boundary,raw_fmov_l_rr`.

`generator,i_FPP` remains **unreviewed**. `SCVTF_dw` retains its independent
audited row; `SXTB_ww`, `SXTH_ww`, `SBFM_wwii`, and other generic emitters are
not promoted here.
