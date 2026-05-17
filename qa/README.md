# Shared macemu QA tooling

This repository-level QA area is for test assets that apply to more than one
emulator in the macemu tree.

## Shared VNC stories

`qa/tests/vnc/` contains user-story oriented VNC/Gherkin desktop QA that should
apply to both:

- BasiliskII (68K / Quadra profile)
- SheepShaver (PPC / Old World profile)

Keep shared stories focused on user-visible Mac desktop behaviour. Put emulator
specific launch details, target aliases, ports, ROM/disk paths, and small wording
variations in profiles or per-emulator matrix wrappers.

Examples:

```bash
# BasiliskII profile
qa/tests/vnc/run.js \
  --emulator basiliskii \
  --features qa/tests/vnc/stories \
  --artifacts BasiliskII/qa/artifacts/reports/vnc-noop

# SheepShaver profile
qa/tests/vnc/run.js \
  --emulator sheepshaver \
  --features qa/tests/vnc/stories \
  --artifacts /tmp/sheepshaver-vnc-noop

# Generate a PDF report from a run directory
qa/tests/vnc/tools/generate-pdf-report.mjs \
  --run /tmp/sheepshaver-vnc-noop \
  --output /tmp/sheepshaver-vnc-noop.pdf
```

## Layered strategy

Use the shared tooling as the desktop/human-workflow layer in a broader QA ladder:

1. Emulator-specific CPU/JIT preflight harnesses.
2. Headless ROM smoke tests.
3. VNC/Xvfb desktop reachability.
4. Deterministic screenshot assertions (PNG metrics, hashes, non-blank checks, optional OCR/OpenCV).
5. Shared user-story flows for desktop reachability, app launch, typing, networking panels, soak, diagnostics, and report generation.
6. Emulator-specific hardware/device coverage recorded in matrix wrappers.
7. Markdown/PDF evidence reports from structured artifacts.

Generated artifacts should stay in ignored report directories such as `BasiliskII/qa/artifacts/`, `qa/artifacts/`, or `/tmp/...`. Commit only curated templates, profiles, stories, and documentation.
