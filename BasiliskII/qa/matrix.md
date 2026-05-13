# BasiliskII QA matrix

## Baseline constants

Unless a case overrides them, use these defaults:

| Field | Value |
|---|---|
| Host | Orange Pi 6 Plus, Debian Trixie, host-native workspace |
| Binary | `BasiliskII/src/Unix/BasiliskII` |
| ROM | `/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM` |
| Disk | `/workspace/fixtures/basilisk/images/HD200MB` |
| RAM | `8388608` bytes |
| Model ID | `14` (Quadra 800 class) |
| CPU | `4` |
| FPU | `false` |
| JIT FPU | `false` |
| JIT cache | `8192` KB |
| Display smoke | `screen win/640/480`, `SDL_VIDEODRIVER=dummy` |
| Desktop/VNC | `screen win/640/480`, `vncserver true`, `vncport 5900`, usually under Xvfb or SDL dummy if supported |
| Audio smoke | `nosound true` or `SDL_AUDIODRIVER=dummy` |
| Safe network first pass | `ether slirp` |
| CD-ROM baseline | `nocdrom true` |
| SEGV handling | `ignoresegv true` |

## Preflight gates

Run before desktop/hardware QA:

1. Build current emulator binary: `make -C BasiliskII/src/Unix -j$(nproc)`.
2. JIT vector harness: `./jit-test/run.sh` must end with `METRIC fail=0` and `METRIC score=100`.
3. ROM smoke: `./jit-test/rom-harness.sh` or `qa/scripts/run-matrix.sh --case optlev2-rom-smoke` must complete without emulator crash, `bad pc_p`, or unexpected JIT bus-error regression.

## Core execution matrix

| Case ID | Mode | Purpose | Key prefs/env | Required pass criteria |
|---|---|---|---|---|
| `interpreter-rom-smoke` | JIT disabled | Golden non-JIT ROM smoke comparison | `jit false`; dummy video/audio; no disk write requirement | Harness reaches tick budget; no emulator crash; no host fatal errors |
| `optlev0-rom-smoke` | JIT dispatch, interpreter codegen | Mixed dispatcher baseline without native optlev2 code | `jit true`; `B2_JIT_FORCE_OPTLEV0=1`; dummy video/audio | Harness reaches tick budget; no `bad pc_p`; no unexpected bus-error regression |
| `optlev2-rom-smoke` | ARM64 optlev2 JIT | Primary native JIT smoke | `jit true`; `B2_JIT_FORCE_TRANSLATE=1`; `B2_JIT_MAX_OPTLEV=2` | JIT preflight passed; harness reaches tick budget; no `bad pc_p`; no emulator crash |
| `optlev2-stable-rom-smoke` | optlev2 + stable-edge profiling | Verify stable direct-edge profiling remains safe | optlev2 env plus `B2_JIT_ENABLE_STABLE_DIRECT_EDGES=1`, `B2_JIT_STABLE_DIRECT_ROM_ONLY=1` | Same as optlev2 plus no stable-edge trace anomalies |
| `optlev2-desktop-vnc` | optlev2 desktop QA | Boot known disk to Finder via VNC | known disk; VNC enabled; dummy audio; no network | Desktop screenshot captured; Finder responsive; app/control panel can launch |
| `optlev2-desktop-soak` | optlev2 desktop soak | Timed stability window at desktop | same as desktop VNC; configurable soak duration | No emulator crash/hang; CPU/log anomalies recorded; screenshots before/after |
| `optlev2-network-slirp` | optlev2 + slirp | Safe user-mode network attempt | `ether slirp`; VNC; dummy audio | Mac OS sees network interface or failure is documented with logs; attempt guest-to-host/local service connectivity |
| `optlev2-audio-dummy` | optlev2 + SDL dummy audio | Headless audio smoke | `nosound false`; `SDL_AUDIODRIVER=dummy` | Boots without SDL audio crash; logs contain no fatal audio setup errors |
| `optlev2-audio-real` | optlev2 + real audio | Hardware audio path, if available | `nosound false`; real SDL audio driver/device | Boot chime/beep/app sound attempted; hardware access and failures documented |
| `optlev2-disk-persistence` | optlev2 disk R/W | Verify disk writes survive restart | copy of known disk image; VNC; dummy audio | Create/change simple artifact in guest; reboot; artifact persists |

## Desktop milestone criteria

Record screenshots for these milestones when running VNC/Xvfb cases:

1. Emulator window/VNC server reachable.
2. ROM/boot screen visible.
3. Happy Mac or visible boot progress.
4. Finder desktop reached.
5. Simple app/control panel launched.
6. Post-soak desktop still responsive.
7. Shutdown/restart result if feasible.

## Network coverage plan

Initial network testing should not require host privilege changes:

1. Inventory build support: `HAVE_SLIRP`, `ENABLE_TUNTAP`, `HAVE_LIBVDEPLUG`, and available `/dev/net/tun`/tap permissions.
2. Start with `ether slirp` in prefs.
3. Enable VNC and boot to desktop.
4. In Mac OS, verify Ethernet/Open Transport/TCP/IP control panel can see an interface.
5. Try a host-local endpoint first. Suggested host setup: simple HTTP server bound to a slirp-reachable address/port, plus optional slirp redirection if supported by prefs.
6. If guest tools/assets are insufficient, document the missing Mac OS network control panel/browser/FTP client assets before changing emulator code.

## Audio coverage plan

1. `nosound true` remains the stability baseline.
2. `SDL_AUDIODRIVER=dummy` with `nosound false` is the headless automation baseline.
3. Real audio is manual/host-dependent. Record SDL driver, ALSA/Pulse/PipeWire devices, permissions, and whether the boot chime/system beep/app sound is heard.

## Reporting requirements

Each run should produce:

- Case ID and git commit.
- Full generated prefs.
- Environment overrides.
- ROM/disk checksums where practical.
- Start/end timestamps and timeout.
- Pass/fail result per criterion.
- Artifacts: logs, screenshots, optional pcaps, report markdown.
- Follow-up list, explicitly separating emulator bugs from missing test assets or host permissions.
