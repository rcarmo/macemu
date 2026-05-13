# BasiliskII VNC desktop QA user stories

## Story 1 — reach the Finder desktop

As a JIT developer, I want BasiliskII to boot a known Mac OS disk image to the
Finder desktop over VNC so that I can verify system-level behaviour beyond ROM
smoke tests.

Acceptance criteria:

- VNC accepts a connection on the configured host/port.
- A boot progress screenshot is captured.
- A desktop/Finder screenshot is captured before timeout.
- The emulator process remains alive and responsive.
- Logs are attached to the run report.

## Story 2 — launch a simple app/control panel

As a QA operator, I want to launch a simple bundled app or control panel from the
Finder desktop so that mouse/keyboard input, window drawing, and basic event loop
responsiveness are verified.

Acceptance criteria:

- The runner can click or use keyboard navigation from the desktop.
- A selected app/control panel opens visibly.
- A screenshot is captured after launch.
- The app can be closed or left in a known state for teardown.

## Story 3 — type text into a guest UI target

As a QA operator, I want to type text into a simple guest UI field/window so that
keyboard injection and modifier handling can be tested repeatably.

Acceptance criteria:

- The runner focuses a known target.
- The runner types a short ASCII string.
- The target displays the expected text or the screenshot is marked for manual review.
- Failed typing does not crash the emulator.

## Story 4 — survive a desktop soak

As a JIT developer, I want the Mac desktop to remain responsive for a timed soak
with optlev2 enabled so that native execution does not corrupt long-running UI state.

Acceptance criteria:

- Desktop screenshot at soak start.
- Desktop screenshot after the soak duration.
- No emulator crash or unbounded CPU/log anomaly without recording it.
- VNC still responds after the soak.

## Story 5 — inspect network configuration

As a network QA operator, I want to open the relevant Mac OS networking control
panel with `ether slirp` enabled so that I can confirm whether the guest sees an
emulated Ethernet/TCP/IP interface before attempting connectivity.

Acceptance criteria:

- QA case uses `ether slirp` and no privileged host network changes.
- Desktop boots with VNC enabled.
- Network/TCP/IP control panel is opened or missing guest assets are documented.
- A screenshot and logs are saved.

## Story 6 — collect failure diagnostics

As a maintainer, I want every VNC desktop test failure to collect screenshots,
logs, prefs, and a structured JSON result so that emulator bugs can be separated
from missing Mac OS assets or host permissions.

Acceptance criteria:

- Failed step and scenario are recorded.
- Last screenshot is saved or explicitly marked unavailable.
- Emulator stdout/stderr and generated prefs paths are referenced.
- Follow-up classification is one of: emulator bug, missing guest asset, host permission, automation gap, unknown.
