# BasiliskII SDL Docker for Raspberry Pi

This directory contains Docker configuration for running BasiliskII on a Raspberry Pi using SDL2 with framebuffer/KMS display (no X11 required).

## Quick Start

### 1. Prepare your data directory

```bash
mkdir -p data
# Copy your Macintosh ROM
cp /path/to/your/mac.rom data/rom
# Copy or create disk images
cp /path/to/your/disk.img data/hd.img
```

### 2. Create a preferences file

Create `data/basiliskii_prefs`:

```
rom /data/rom
disk /data/hd.img
ramsize 67108864
frameskip 0
screen win/800/600
seriala /dev/null
serialb /dev/null
```

### 3. Build and run

```bash
# Build the image
docker compose build

# Run BasiliskII
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Configuration

### Video Output

The container is configured to use SDL2 with KMS/DRM by default, which works well on Raspberry Pi OS Lite (without desktop).

Environment variables:
- `SDL_VIDEODRIVER=kmsdrm` - Use KMS/DRM (recommended)
- `SDL_VIDEODRIVER=fbdev` - Use framebuffer directly (fallback)

### Audio Output

Uses ALSA by default:
- `SDL_AUDIODRIVER=alsa`

### Device Access

The container needs access to:
- `/dev/fb0` - Framebuffer
- `/dev/dri` - DRM/KMS devices
- `/dev/input` - Keyboard and mouse
- `/dev/snd` - Sound devices

### Running Without Privileged Mode

If you want to avoid `privileged: true`, you can try:

```yaml
cap_add:
  - SYS_RAWIO
security_opt:
  - apparmor:unconfined
group_add:
  - video
  - audio
  - input
```

You may also need to add your user to the appropriate groups on the host:
```bash
sudo usermod -aG video,audio,input $USER
```

## Building for ARM

The Dockerfile supports multi-architecture builds. To build for ARM64:

```bash
# Using buildx
docker buildx build --platform linux/arm64 -t basiliskii-sdl:arm64 .

# Or on a Raspberry Pi directly
docker build -t basiliskii-sdl .
```

## Troubleshooting

### No video output
- Ensure no other application is using the framebuffer/DRM
- Try `SDL_VIDEODRIVER=fbdev` instead of `kmsdrm`
- Check that `/dev/fb0` and `/dev/dri` are accessible

### No sound
- Check ALSA devices: `aplay -l`
- Try setting `AUDIODEV=hw:0,0` or appropriate device

### No keyboard/mouse input
- Ensure `/dev/input` devices are mounted
- The user may need to be in the `input` group

### Permission denied
- Use `privileged: true` or add appropriate capabilities
- Check device permissions on the host

## Files

- `Dockerfile` - Multi-stage build for BasiliskII with SDL2
- `docker-compose.yml` - Docker Compose configuration for Raspberry Pi
- `data/` - Mount point for ROM, disk images, and preferences
