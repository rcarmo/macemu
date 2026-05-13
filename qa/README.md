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
