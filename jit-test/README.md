# BasiliskII AArch64 JIT — Opcode Equivalence Harness

## Goal

Keep `jit-test/run.sh` trustworthy and deterministic so every run emits numeric metrics:
- `score`
- `pass`
- `fail`
- `total`

Harness-first scope: prioritize benchmark correctness/completeness over emulator product behavior.

## Metric contract

`jit-test/run.sh` always emits:
- `METRIC pass=<int>` — number of opcode vectors where JIT and interpreter REGDUMP match
- `METRIC fail=<int>` — vectors with mismatch or harness infra error
- `METRIC total=<int>` — number of vectors executed
- `METRIC score=<int>` — `floor(pass * 100 / total)` (0 when `total=0`)
- `METRIC infra_fail=<int>` — subset of failures caused by harness/runtime issues
- `METRIC build_ok=<0|1>` — whether build/setup succeeded before test execution
- Infra/equivalence breakdown counters for triage (`fail_equiv`, `infra_timeout`, `infra_emu_exit`, `infra_no_regdump`, `infra_multi_regdump`, `infra_sentinel`, `infra_other`)

## Harness model

For each test vector:
1. Build BasiliskII (configures if needed)
2. Run bytecode in interpreter mode (`jit false`) and JIT mode (`jit true`)
3. Require exactly one `REGDUMP:` line in each run
4. Verify sentinel write to A6 occurred
5. Diff full REGDUMP lines to decide pass/fail

## Structural engine gates

After a successful build, `run.sh` executes `structural-audit.ts` before opcode vectors. These gates cover emitter ordering and ownership invariants which are asynchronous or compile-time and therefore cannot be scheduled reliably by a register-dump vector:

- complete successor-PC publication before every endblock exit;
- basic-block termination at every classified control transfer;
- AAPCS64-safe helper call target and allocator barrier;
- fail-fast locked-register and scratch ownership;
- exact `pc_hist[]` opcode-PC publication and successor-PC helper ABI for ordered whole-instruction semantic services;
- native CAS/CAS2/MOVES and bitfield family classification, extension-fetch ordering, effective-address side effects, and read/compare/write ordering;
- privilege-before-extension ordering for system-control helpers and exact-PC contracts for RESET, STOP, RTE, USP moves, MOVEC, and CPUSH;
- complete legal-opcode classification as native-generated code, semantic services, or architectural traps, with no fallback/null slots.

Each passing invariant emits a `METRIC structural_*=1` line. A structural failure stops the run before equivalence results can mask the engine defect.

## Current deterministic vectors

`run.sh` currently covers 421 vectors across:
- Decode/dispatch sanity (`nop`, `nop_triplet`)
- Bit manipulation boundary behavior (`bitops`, `bitops_chg`, high-bit immediate `bitops_highbit`, high-bit toggle `bitops_chg_highbit`)
- Core arithmetic/data movement (`move` + `moveq_signext` + moveq edge sign-extension checks, `alu` + negative roundtrip check, `addi/subi` incl. byte/word/long plus byte/word/long-boundary-wrap checks, `quick_ops` incl. long-negative roundtrip + word+word-wrap+long-wrap+byte+byte-wrap+address-register variants, `compare` + `cmpi` size coverage for both non-zero and zero immediates plus negative byte/word/long boundary forms, `muldiv`, `movem`, `misc` + `swap_roundtrip`, `not` size forms (`not_sizes`) plus explicit NOT.W/NOT.B upper-bit preservation checks, `clr` size forms (`clr_sizes`) plus byte/word partial-clear upper-bit preservation checks, `neg` size forms (`neg_sizes`) plus explicit zero-input NEG size path, `flags` incl. OR/AND/EOR-CCR path, `exg`, `imm_logic` incl. byte+word+long variants plus explicit byte/word/long high-bit edge logic checks, `tst` size forms on negative, zero, and positive inputs)
- Shift/rotate contracts, including register-count ROXL/ROXR in both directions and all widths, low-six-bit modulo 9/17/33 effective-zero paths, C=X with unchanged X/data, size-correct N/Z, cleared V, partial-register preservation, and populated guest-register mappings
- Ordered semantic services: CAS byte/word/long success and failure, predecrement/postincrement/displacement modes, CAS2 success/failure and aliasing, MOVES privilege/fetch ordering and register/EA aliasing, all eight bitfield operations across register and memory EAs, and width/offset/fault-order edges
- System-control services: RESET, STOP, RTE, USP moves, MOVEC, and cache operations with privilege, extension-fetch, exact fault-PC, and successor-PC vectors
- Branch condition behavior (`bra` short+word, `bne/beq` short+word, both short + `.W` displacement forms for `bpl/bmi`, `bvc/bvs`, `bge/blt`, `bgt/ble`, `bcc/bcs`, `bhi/bls`, plus chained-condition branch sequencing with explicit Z-clear, Z-set, carry-clear, carry-set, and overflow-set chain behaviors)
- Condition-byte writes via `Scc` families (`st/sf`, `shi/sls`, `scc/scs`, `sne/seq`, `svc/svs`, `spl/smi`, `sge/slt`, `sgt/sle`) plus expanded CCR-preservation interactions (`SLT`→`BLT`, `SCS`→`BCS`, `SNE`→`BNE`, `SEQ`→`BEQ`, `SVS`→`BVS`, `SVC`→`BVC`, `SHI`→`BHI`, `SLS`→`BLS`, `SPL`→`BPL`, `SMI`→`BMI`, `SGE`→`BGE`, `SGT`→`BGT`, `SLE`→`BLE` with unchanged flags)
- Loop control (`dbra` taken, terminal non-taken, bounded 3/4/5/6-iteration DBRA loops, bounded carry-flag DBcc paths (`dbcc` loop when C=1 false-condition, deterministic `dbcs` condition-true non-taken), bounded negative-flag DBcc paths (`dbpl` loop when N=1 false-condition, deterministic `dbmi` condition-true non-taken), deterministic condition-true non-taken vectors for `dbhi`/`dbls`/`dbge`/`dblt`/`dbgt`/`dble`, deterministic condition-false decrement-to-terminal vectors for those same DBcc families (`D0=0` one-shot decrement path), DBcc→Bcc CCR-preservation vectors (`dbeq`→`beq`, `dbne`→`bne`, `dbcs`→`bcs`, `dbvc`→`bvc`, `dbvs`→`bvs`, `dbhi`→`bhi`, `dbls`→`bls`, `dbge`→`bge`, `dblt`→`blt`, `dbgt`→`bgt`, `dble`→`ble`), plus bounded `dbne`/`dbeq` and `dbvc`/`dbvs` loops, and deterministic `dbvc`/`dbvs` non-taken condition-true paths)

All vectors are designed to terminate without unbounded loops.

## Harness integrity checks

Before executing vectors, `run.sh` performs deterministic preflight validation:
- no duplicate test names in `TEST_ORDER`
- every ordered test has both `TESTS[...]` bytecode and `SENTINEL_A6[...]`
- each test encoding is strict 4-hex-word tokens (machine-parseable M68K word stream)
- test vectors may not include `2C7C` (reserved for harness-appended A6 sentinel write)
- each sentinel is an 8-hex-digit value
- sentinel values are unique across vectors
- no extra `TESTS[...]`/`SENTINEL_A6[...]` keys exist outside `TEST_ORDER`

Any invariant violation aborts with machine-parseable failure metrics (`infra_fail=1`) instead of silently running a malformed suite.

## Constraints

- No ROM patches, stub-region hacks, or RAM presets to mask bugs.
- Keep outputs machine-parseable and numeric.
- Keep vectors deterministic and bounded-time.
- Pair performance changes with strict ROM marker checks: no `JIT_FALLBACK`, `SEGV_SKIP`, `JITBLOCKVERIFY`, `op=8c4c`, `bad_pcp`, or fatal host signal markers (`SIGILL`, `SIGSEGV`, `SIGBUS`, illegal instruction, bus error, segmentation fault).
