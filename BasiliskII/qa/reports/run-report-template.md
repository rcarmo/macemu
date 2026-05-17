# BasiliskII QA run report

## Summary

| Field | Value |
|---|---|
| Case ID |  |
| Result | PASS / FAIL / BLOCKED |
| Date/time |  |
| Host | Orange Pi 6 Plus / Debian Trixie |
| Git commit |  |
| Operator |  |

## Configuration

| Field | Value |
|---|---|
| Binary |  |
| ROM |  |
| ROM checksum |  |
| Disk image |  |
| Disk checksum/copy ID |  |
| RAM size |  |
| Model ID |  |
| CPU/FPU |  |
| JIT prefs |  |
| Display mode |  |
| VNC port |  |
| Audio mode |  |
| Network mode |  |
| Timeout / soak duration |  |

## Preflight

- [ ] Build passed.
- [ ] JIT vector harness passed (`fail=0`, `score=100`).
- [ ] ROM smoke passed or intentionally skipped with reason.

## Milestones

| Milestone | Result | Artifact |
|---|---|---|
| Emulator/VNC reachable |  |  |
| ROM/boot visible |  |  |
| Boot progress / Happy Mac |  |  |
| Finder desktop reached |  |  |
| App/control panel launched |  |  |
| Desktop soak completed |  |  |
| Shutdown/restart path tested |  |  |

## Hardware/network/audio observations

### Network

- Backend: none / slirp / tap / tun / other
- Guest interface visible: yes / no / unknown
- Connectivity attempted:
- Result:
- Logs/pcaps:

### Audio

- Backend: nosound / SDL dummy / real SDL driver
- Boot chime/system beep/app sound attempted:
- Result:
- Logs:

### Disk/device persistence

- Disk writes attempted:
- Restart attempted:
- Persistence result:

## Logs and artifacts

- Emulator stdout:
- Emulator stderr:
- Prefs file:
- Screenshots:
- Pcaps:
- Markdown report:
- PDF report:
- Screenshot assertion output:

## Failure analysis

- Reproducible: yes / no / unknown
- First bad marker:
- Suspected area:
- Existing env gates tried:
- Missing guest assets:
- Missing host permissions:
- Automation gap vs emulator bug:

## Follow-ups

- [ ] 
