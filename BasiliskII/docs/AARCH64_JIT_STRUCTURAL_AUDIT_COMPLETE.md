# AArch64 JIT structural audit completion

Date: 2026-07-28
Audited source tip: `7d2edc52c2826f3cdc018f549db1a028f479d23b`

## Verdict

The configured BasiliskII AArch64 JIT structural audit is complete. The
deterministic closure inventory contains 998 rows and no unreviewed or deferred
entry. Every reachable entry is covered by an accepted audit report or routes
through an explicit ordered semantic boundary. Unreachable entries either have
no configured-root path or are replaced by an unconditional post-registration
service override, matching the inventory policy.

This verdict covers the configured source graph and the contracts enumerated by
`jit-test/closure-inventory.ts`. Future source, generator, registration, or
configuration changes must regenerate the inventory and re-run the maintained
gates.

## Final classification

| Layer | Total | Audited | Serviced | Unreachable | Unreviewed/deferred |
|---|---:|---:|---:|---:|---:|
| Generator | 130 | 75 | 44 | 11 | 0 |
| MIDFUNC | 422 | 291 | 0 | 131 | 0 |
| Emitter API | 294 | 191 | 0 | 103 | 0 |
| Raw boundary | 83 | 54 | 0 | 29 | 0 |
| Runtime boundary | 69 | 0 | 40 | 29 | 0 |
| **Total** | **998** | **611** | **84** | **303** | **0** |

The authoritative row-level table remains
`AARCH64_JIT_CLOSURE_INVENTORY.csv`; its generated narrative is
`AARCH64_JIT_CLOSURE_INVENTORY.md`.

## Final whole-engine gates

All final gates were run from canonical `master` at the tip above on the native
AArch64 host. The only worktree addition during report publication was this
completion document; production, generated, inventory, and harness sources were
clean.

- Maintained full gate, `bash jit-test/run.sh`: clean generated-JIT build,
  structural audit, all emitter and boundary probes, strict negative contract,
  and **904/904** active-risky vectors passed; zero failures, zero
  infrastructure failures, score 100, `validation_complete=1`.
- Allocator-pressure gate, `bash jit-test/regalloc-pressure.sh`: **33/33**
  selected cells passed.
- Post-registration coverage census: all **48,282** legal encodings classified
  as **46,087 native-generated**, **2,127 semantic services**, and **68
  architectural traps**; fallback/null **0** and normal/no-flags parity gaps
  **0**.
- Deterministic regeneration: inventory CSV and Markdown remained byte-identical,
  no `unreviewed` row appeared, and `git diff --check` passed.
- Finder retirement gate: ordinary and strict modes each scheduled **24,120,000**
  guest retirements, retained a **16,777,216-PC** (64 MiB) window, reached **21
  `DiskStatus 43`** events, and reported no host fault. The windows were
  byte-identical with SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`.
  Strict mode emitted 24 summaries, all with
  `opt0=0 fallback=0 exec_nostats=0`.

## Reproducibility identities

- Closure inventory CSV:
  `8220e4e02341ac559a4af49a0bd163e86c0f11c5ffa94df57f304fb542313afd`
- Closure inventory Markdown:
  `939fd2711ed9e42542caba28e413679b22060a1a57ad05f434fe9e8f7c00cde3`
- Post-registration coverage CSV:
  `86b137d70b0a0d7289490d808b653079b7f087e4b8db31675cb2a3b344534303`
- Post-registration coverage Markdown:
  `35eb19f43e55c1b3ea3887580aab340ba6555fb1707b268f4fcecce9b5fce23c`

The structural audit is therefore closed at this source tip. Runtime defects
found after this point are new regressions or out-of-scope configuration paths,
not unreviewed rows in this inventory.
