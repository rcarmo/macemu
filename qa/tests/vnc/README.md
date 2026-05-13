# VNC desktop QA tests

This folder holds the VNC/Gherkin tooling used by BasiliskII end-to-end desktop QA.

The first implementation is intentionally dependency-light: it parses feature files,
creates run artifacts, and exposes a stable VNC driver interface. The default driver is
`noop`, so CI/manual dry-runs can validate stories without requiring a live Mac desktop.
A real VNC backend can be added behind the same interface without changing the feature
files.

## Layout

```text
qa/tests/vnc/
  run.js                 CLI entrypoint for VNC/Gherkin desktop tests
  lib/gherkin.js         small feature/scenario/step parser
  lib/artifacts.js       run directory and JSON/Markdown result helpers
  lib/vnc-driver.js      VNC driver abstraction (`noop` today)
  stories/*.feature      user-story oriented desktop scenarios
  stories/user-stories.md narrative user stories and acceptance criteria
```

## Usage

From `/workspace/projects/macemu`:

```bash
# Validate all VNC desktop stories with the noop driver
qa/tests/vnc/run.js \
  --features qa/tests/vnc/stories \
  --artifacts qa/artifacts/reports/vnc-noop

# Validate a specific story
qa/tests/vnc/run.js \
  --feature qa/tests/vnc/stories/desktop-reachability.feature \
  --artifacts /tmp/basilisk-vnc-story
```

## Driver contract

The runner calls a driver with these operations:

- `connect()`
- `waitForDisplay(label, timeoutMs)`
- `screenshot(name)`
- `click(labelOrCoordinates)`
- `type(text)`
- `key(keyName)`
- `close()`

The noop implementation records intended actions in `vnc-actions.jsonl` and writes a
placeholder screenshot manifest. A future real driver can use a VNC library, `vncdotool`,
or a small Python/Node bridge.

## Artifact convention

Each run should write:

- `vnc-run.json` — parsed scenarios, step results, timestamps, VNC target
- `vnc-actions.jsonl` — driver action log
- `screenshots/` — captured screenshots or placeholder metadata
- `report.md` — human-readable summary

These artifacts are generated output and are ignored by Git under `qa/artifacts/`.
