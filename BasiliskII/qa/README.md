# BasiliskII end-to-end QA

This directory contains the first-pass QA matrix and automation scaffold for BasiliskII system-level validation on the Orange Pi host.

The QA work assumes the ARM64 JIT opcode/vector layer is stable enough to test whole-emulator behaviour, but every desktop/hardware run still starts with JIT preflight checks.

## Scope

- Boot and desktop reachability with a known ROM/disk image.
- Interpreter, optlev0, optlev2, and optlev2 + stable-edge JIT comparisons.
- Headless/dummy, VNC/Xvfb, audio, disk persistence, network, and basic device coverage.
- Gherkin feature files plus a VNC runner scaffold for future desktop scripting.

## Canonical assets

| Asset | Default path |
|---|---|
| Emulator binary | `BasiliskII/src/Unix/BasiliskII` |
| ROM | `/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM` |
| Known-good disk | `/workspace/fixtures/basilisk/images/HD200MB` |
| JIT vector preflight | `jit-test/run.sh` |
| ROM smoke preflight | `jit-test/rom-harness.sh` |

Override paths with environment variables accepted by `scripts/run-matrix.sh`.

## Quick start

From `/workspace/projects/macemu`:

```bash
# List defined QA cases
BasiliskII/qa/scripts/run-matrix.sh --list

# Generate prefs/manifests without launching the emulator
BasiliskII/qa/scripts/run-matrix.sh --case optlev2-desktop-vnc --dry-run

# Run a short ROM smoke for the optlev2 case
BasiliskII/qa/scripts/run-matrix.sh --case optlev2-rom-smoke --timeout 30
```

## Directory layout

```text
qa/
  README.md
  matrix.md                         human-readable QA matrix
  reports/run-report-template.md    per-run report template
  scripts/run-matrix.sh             prefs + smoke runner scaffold
  scripts/vnc-gherkin-runner.js     compatibility wrapper for VNC tests
  tests/vnc/                        dedicated VNC/Gherkin test tooling
  tests/vnc/stories/*.feature       user-story oriented desktop scenarios
  features/*.feature                high-level desktop/network/audio scenarios
  artifacts/                        ignored/generated run outputs
```

Generated artifacts are written under `qa/artifacts/` by default and should not be committed except for curated reports/screenshots explicitly needed for review.

## VNC user-story tests

The dedicated VNC test tooling lives under `qa/tests/vnc/`:

```bash
BasiliskII/qa/tests/vnc/run.js \
  --features BasiliskII/qa/tests/vnc/stories \
  --artifacts BasiliskII/qa/artifacts/reports/vnc-noop
```

The current driver is `noop`: it validates Gherkin stories and writes action/result artifacts without sending real VNC events. A real VNC backend should implement the driver contract in `qa/tests/vnc/lib/vnc-driver.js`.

## Safety rules

- Do not require privileged networking for the default matrix.
- Prefer `ether slirp` for initial network attempts.
- Use `SDL_AUDIODRIVER=dummy` for headless automation until real audio is intentionally tested.
- Do not patch emulator logic from a QA observation until the issue is reproducible and isolated.
