# SheepShaver PPC Opcode Equivalence Harness

## Status

**303 deterministic equivalence cases**, all passing in the accepted 2026-08-02 pre-benchmark gate (`METRIC pass=303 fail=0 total=303 score=100`). The total comprises 298 ordered interpreter-vs-production-JIT vectors plus five focused interpreter-vs-direct-JIT regressions.

## How it works

1. Set `SS_TEST_HEX` to a space-separated hex sequence of PPC instructions (big-endian 32-bit words)
2. Set `SS_TEST_DUMP=1` to emit a `REGDUMP:` line with GPR0-31, CR, LR, CTR, XER
3. Optionally set `SS_TEST_INIT` to seed GPR0-31 + optional CR before execution
4. Optionally set `SS_TEST_JIT=1` to compile and execute via the direct AArch64 JIT path

The main loop runs each vector once in interpreter mode and once through the production JIT dispatch loop, then diffs the complete `REGDUMP`. Five focused regressions compare interpreter mode with the single-block direct-JIT path. This is an equivalence gate, not the obsolete JIT-vs-JIT determinism check used before 2026-06-22. Unsupported or barrier-worthy instructions must delegate to the interpreter rather than silently compile as NOPs.

## Running

```bash
# Full opcode and structural harness
./jit-test/run.sh

# Bounded benchmark contract and binary build (host benchmark is a separate,
# coordinated operation; see docs/AARCH64_JIT_BENCHMARK.md). The accepted
# 2026-08-02 result is documented in docs/AARCH64_JIT_BENCHMARK_RESULT_20260802.md.
./jit-test/benchmark-contract.sh
./jit-test/build-benchmark-binaries.sh

# Single vector (interpreter)
SS_TEST_HEX="38600064 388000c8 7CA32214" SS_TEST_DUMP=1 src/Unix/SheepShaver

# Single vector (JIT)
SS_TEST_HEX="38600064 388000c8 7CA32214" SS_TEST_DUMP=1 SS_TEST_JIT=1 src/Unix/SheepShaver
```

## Metrics

- `METRIC pass=N` — vectors where both runs match
- `METRIC fail=N` — vectors with mismatch or error
- `METRIC total=N` — total vectors
- `METRIC score=N` — pass percentage

## Representative vectors

The table below is illustrative, not the complete 303-case inventory; `TEST_ORDER` and the five `run_equiv_test` calls in `jit-test/run.sh` are authoritative.

| Vector | Opcodes tested |
|--------|---------------|
| `alu_add` | `li`, `add` |
| `alu_sub` | `li`, `subf` |
| `alu_and` | `li`, `and` |
| `alu_or` | `li`, `or` |
| `alu_xor` | `li`, `xor` |
| `li_wide` | `lis`, `ori` (32-bit immediate) |
| `shift_slw` | `li`, `slw` |
| `shift_srw` | `li`, `srw` |
| `cmp_beq` | `cmpw`, `beq`, conditional branch skip |
| `bdnz_loop` | `mtctr`, `addi`, `bdnz` (5 iterations) |
| `mul_basic` | `li`, `mullw` |
| `rlwinm_basic` | `rlwinm` rotate + mask |
| `nop` | NOP sanity |
| `neg_basic` | `neg` |
| `sraw_signext` | `sraw` with sign extension + XER CA |
| `stw_lwz` | `stw`/`lwz` memory round-trip |
| `stb_lbz` | `stb`/`lbz` byte round-trip |
| `sth_lhz` | `sth`/`lhz` halfword round-trip |
| `addic_dot` | `addic.` with CR0 update |
| `add_dot_neg` | `add.` with negative result → CR0.LT |
| `divw_basic` | `divw` integer divide |
| `mtctr_mfctr` | `mtctr`/`mfctr` SPR round-trip |
| `addic_carry` | `addic` carry flag (XER.CA) |
| `adde_carry` | `adde` extended add with carry |
| `rlwimi_insert` | `rlwimi` rotate and mask insert |
| `cntlzw_basic` | `cntlzw` count leading zeros |
| `extsh_basic` | `extsh` sign-extend halfword |
| `extsb_basic` | `extsb` sign-extend byte |
