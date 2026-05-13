# VNC desktop QA tests

This folder holds shared VNC/Gherkin tooling used by both BasiliskII and SheepShaver end-to-end desktop QA.

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
  profiles/*.json        per-emulator labels/defaults (BasiliskII, SheepShaver)
  stories/*.feature      shared user-story oriented desktop scenarios
  stories/user-stories.md narrative user stories and acceptance criteria
  tools/screenshot-read.js deterministic PNG/OCR/OpenCV screenshot assertions
  templates/             committed image templates for OpenCV matching
```

## Usage

From `/workspace/projects/macemu`:

```bash
# Validate all shared VNC desktop stories for BasiliskII with the noop driver
qa/tests/vnc/run.js \
  --emulator basiliskii \
  --features qa/tests/vnc/stories \
  --artifacts BasiliskII/qa/artifacts/reports/vnc-noop

# Validate the same stories for SheepShaver's profile
qa/tests/vnc/run.js \
  --emulator sheepshaver \
  --features qa/tests/vnc/stories \
  --artifacts /tmp/sheepshaver-vnc-noop

# Validate a specific story
qa/tests/vnc/run.js \
  --emulator basiliskii \
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

## Model-free screenshot reading

CI assertions should use deterministic image checks, not model vision:

- PNG dimensions and content metrics via `lib/png.js` + `lib/screenshot.js`.
- Blank-screen detection via luminance standard deviation.
- Stable file identity via SHA-256 and 8x8 average hash.
- Optional OCR via the `tesseract` CLI (`OCR text from screenshot ... should contain ...`).
- Optional OpenCV template matching via `tools/opencv-match.py` (`... should match template ... with threshold ...`).

Standalone examples:

```bash
# Inspect dimensions, hashes, luminance statistics
qa/tests/vnc/tools/screenshot-read.js inspect screenshot.png

# Assert image is 640x480 and not blank
qa/tests/vnc/tools/screenshot-read.js assert screenshot.png --width 640 --height 480 --not-blank

# OCR, deterministic but dependent on installed tesseract language data
qa/tests/vnc/tools/screenshot-read.js assert screenshot.png --ocr-contains Finder

# OpenCV template match
qa/tests/vnc/tools/screenshot-read.js assert screenshot.png --template qa/tests/vnc/templates/finder-menu.png --threshold 0.90
```

The Gherkin runner skips these assertions when the current driver only produced a
placeholder instead of a PNG, which keeps noop CI validation useful until the real VNC
capture backend lands.

## Artifact convention

## Shared-story rule

Stories should describe user-visible Mac desktop behaviour, not emulator internals. Keep emulator-specific differences in `profiles/*.json`, launch/matrix wrappers, or step target aliases.

Each run should write:

- `vnc-run.json` — parsed scenarios, step results, timestamps, VNC target
- `vnc-actions.jsonl` — driver action log
- `screenshots/` — captured screenshots or placeholder metadata
- `report.md` — human-readable summary

These artifacts are generated output and are ignored by Git under `qa/artifacts/`.
