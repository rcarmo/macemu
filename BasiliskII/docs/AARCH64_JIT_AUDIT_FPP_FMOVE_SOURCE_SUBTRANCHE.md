# AArch64 JIT FPP ordinary FMOVE source subtranche

## Scope

This is the second bounded subtranche of the reachable `i_FPP` generator audit.
It covers ordinary `FMOVE` inputs only:

- FP-register source copies and self aliases across all FP0-FP7 fields;
- Dn byte, word, long, and IEEE single sources;
- immediate byte, word, long, IEEE single, and IEEE double sources;
- exact native-double shadow values, FPSR condition classes, and integer-CCR
  preservation;
- FP-register ownership with all eight architectural FP registers live.

It does **not** promote `generator,i_FPP`. Explicit-precision `FSMOVE`/`FDMOVE`,
extended precision, memory effective-address lifecycle, FMOVE stores, FMOVECR,
FMOVEM, control-register moves, arithmetic, exceptions, and remaining semantic
services are separate subfamilies.

## Defect found and repaired

The AArch64 compatibility shim mapped legacy `fmovi_rm(d, m)` to
`fmov_l_rr(d, m)`. `get_fp_value()` first stored an integer source in the
host-global `temp_fp`, then passed that host pointer as `m`. The AArch64 MIDFUNC
interpreted it as a virtual integer-register number. Native FMOVE therefore
read invalid allocator state and faulted at a null address before REGDUMP.

The configured AArch64 path now bypasses the x86-era memory shuttle and uses the
existing typed register conversion MIDFUNCs directly:

- `fmov_b_rr` for signed byte;
- `fmov_w_rr` for signed word;
- `fmov_l_rr` for signed long;
- `fmov_s_rr` for IEEE single bits.

The same direct conversion applies after guest-memory/immediate fetch into S2,
but this checkpoint tests only immediate addressing; arbitrary memory EA and
writeback ownership remain deferred.

## Exact-native evidence

`bun jit-test/fpp-fmove-source-matrix.ts` runs 43 fail-closed strict cases:

- signed integer extrema and positive boundaries for byte/word/long;
- signed zero, infinities, NaNs, and fractional single/double values;
- maximum D7 and FP7 encoding fields;
- every FP0-FP7 source field routed to a distinct destination;
- FP0 and FP7 self aliases;
- all eight architectural FP registers live across FP0-to-FP7 copy;
- exact second-pass native entry at each audited FMOVE;
- exact 64-bit native shadow values, exact FPSR CCB, and `SR=0x271f`.

Accepted result:

```text
FPP_FMOVE_SOURCE_MATRIX pass=43 fail=0 total=43
```

REGDUMP exposes FP0-FP7 only when `B2_TEST_DUMP_FP=1`. This keeps the ordinary
interpreter/JIT equivalence contract stable: non-FPU interpreter runs leave the
native shadows zero while JIT block entry deliberately initializes them from
architectural MPFR state (often NaN). The dedicated FMOVE matrix opts into the
observer because it compares native FPU values directly.

Integrated evidence:

```text
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
```

FP allocator ownership is statically partitioned on AArch64: FP0-FP7 map to
callee-saved d8-d15 and FS1 maps to d7. Integer scratch-alias injection cannot
collide with those destinations. The all-eight-live exact-native vector is the
bounded ownership witness for this source/copy slice; the existing 31-cell
integer matrix catches cross-subsystem allocator regressions.

## Structural contracts

- AArch64 Dn and fetched/immediate integer sources use typed register conversion
  MIDFUNCs, never the host `temp_fp` pointer as a virtual register.
- All four conversion widths are required in both Dn and fetched-source paths.
- The focused matrix requires strict full-JIT, exact native entry, CoW disk
  isolation, exact SR/FPSR, exact FP shadow values, all eight FP register routes,
  and an exact total of 43.
- Explicit-precision operation names are rejected from the bounded matrix.

## Closure decision

No row is promoted to audited. The repair creates direct configured call paths
to `fmov_b_rr`, `fmov_w_rr`, and `fmov_s_rr`, so their mechanically derived
classification changes from unreachable to reachable/unreviewed. `fmov_l_rr`
was already reachable/unreviewed. The inventory remains exactly 997 rows;
MIDFUNC totals change from 118 to **115 unreachable** and from 42 to **45
unreviewed**.

`generator,i_FPP` remains **unreviewed** until its remaining reachable
subfamilies have direct evidence or explicit serviced/unreachable
classification. The next chunk should cover ordinary FMOVE memory sources and
EA/writeback ownership; FMOVE stores should follow separately.
