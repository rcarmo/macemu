# SheepShaver SDL Docker for Raspberry Pi

This directory contains Docker configuration for running SheepShaver on a Raspberry Pi using the same direct-display assumptions as the BasiliskII SDL image: SDL2 with KMS/DRM or fbdev, ALSA audio, no X11, no Wayland, no OpenGL, and no desktop environment required.

## Quick Start

### 1. Prepare your data directory

```bash
mkdir -p data
cp /path/to/PowerMac-ROM data/rom
cp /path/to/disk.img data/hd.img
cp data/sheepshaver_prefs.example data/sheepshaver_prefs
```

Edit `data/sheepshaver_prefs` for your ROM, disk images, RAM size, screen size, and VNC port.

### 2. Build and run

```bash
docker compose build
docker compose up -d
docker compose logs -f
```

### 3. Pull pre-built image

```bash
docker pull ghcr.io/rcarmo/sheepshaver-sdl:latest
```

## Configuration

### Video Output

The container defaults to:

```text
SDL_VIDEODRIVER=kmsdrm
```

Fallback:

```text
SDL_VIDEODRIVER=fbdev
```

### Audio Output

The container defaults to:

```text
SDL_AUDIODRIVER=alsa
```

Set `AUDIODEV=hw:0,0` or another ALSA device if needed.

### Device Access

The container needs the same Raspberry Pi device access model used by the BasiliskII SDL image:

- `/dev/fb0` — framebuffer fallback
- `/dev/dri` — DRM/KMS devices
- `/dev/input` — keyboard/mouse
- `/dev/snd` — ALSA sound devices

The sample compose file uses `privileged: true`. If you want to avoid privileged mode, start with:

```yaml
cap_add:
  - SYS_RAWIO
  - SYS_ADMIN
security_opt:
  - apparmor:unconfined
group_add:
  - video
  - audio
  - input
```

You may also need host user/group setup:

```bash
sudo usermod -aG video,audio,input $USER
```

## Building for ARM

ARM64:

```bash
docker buildx build --platform linux/arm64 -f SheepShaver/docker/Dockerfile -t sheepshaver-sdl:arm64 .
```

ARMhf/ARMv7:

```bash
docker buildx build --platform linux/arm/v7 -f SheepShaver/docker/Dockerfile.armhf -t sheepshaver-sdl:armhf .
```

## Notes

- The release image is an SDL/KMS runtime package, not a desktop/X11 build.
- JIT is enabled in packaged builds where a backend is available; ARM64 builds use the AArch64 PPC JIT backend by default. Set `SS_USE_JIT=0` to force interpreter mode for diagnostics.
- Use VNC (`vncserver true`, `vncport 5999`) for remote control when running headless.
