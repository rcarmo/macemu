# SheepShaver SDL Docker Image for Raspberry Pi / ARM64
# Optimized for framebuffer/KMS display without X11, Wayland, or desktop UI.

FROM debian:bookworm-slim AS builder

ARG SDL_VERSION=2.32.8

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libasound2-dev \
    libudev-dev \
    libdbus-1-dev \
    libdrm-dev \
    libgbm-dev \
    libvncserver-dev \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build SDL2 from source with the same direct-display assumptions as the
# BasiliskII Raspberry Pi image: no X11/Wayland/OpenGL, KMS/DRM or fbdev at runtime.
RUN wget -q https://www.libsdl.org/release/SDL2-${SDL_VERSION}.tar.gz \
    && tar -zxf SDL2-${SDL_VERSION}.tar.gz \
    && cd SDL2-${SDL_VERSION} \
    && ./configure \
        --prefix=/usr/local \
        --disable-video-opengl \
        --disable-video-x11 \
        --disable-pulseaudio \
        --disable-esd \
        --disable-video-wayland \
        --enable-video-kmsdrm \
        --enable-libudev \
        --enable-input-events \
    && make -j$(nproc) \
    && make install

# Copy SheepShaver source.
COPY SheepShaver /build/SheepShaver

# Build SheepShaver as a lightweight SDL-only runtime.
WORKDIR /build/SheepShaver/src/Unix
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV CPPFLAGS="-I/usr/local/include -I/usr/local/include/SDL2"
ENV LDFLAGS="-L/usr/local/lib"
ENV CFLAGS=""
ENV CXXFLAGS=""
RUN NO_CONFIGURE=1 ./autogen.sh \
    && ARCH="$(dpkg --print-architecture)" \
    && if [ "$ARCH" = "arm64" ]; then \
         export CFLAGS="-march=armv8-a -mtune=cortex-a72"; \
         export CXXFLAGS="-march=armv8-a -mtune=cortex-a72"; \
       fi \
    && ./configure \
        --prefix=/usr \
        --enable-sdl-audio \
        --enable-sdl-video \
        --disable-fbdev-dga \
        --disable-xf86-dga \
        --disable-xf86-vidmode \
        --disable-vosf \
        --without-mon \
        --without-esd \
        --without-gtk \
        --enable-jit \
    && make -j$(nproc)

# Runtime image.
FROM debian:bookworm-slim

# Install runtime dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libasound2 \
    libudev1 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libvncserver1 \
    && rm -rf /var/lib/apt/lists/*

# Copy SDL2 libraries.
COPY --from=builder /usr/local/lib/libSDL2* /usr/local/lib/
RUN ldconfig

# Copy SheepShaver binary and data files.
RUN mkdir -p /usr/share/sheepshaver-sdl
COPY --from=builder /build/SheepShaver/src/Unix/SheepShaver /usr/bin/
COPY --from=builder /build/SheepShaver/src/SDL/keycodes /usr/share/sheepshaver-sdl/keycodes
COPY --from=builder /build/SheepShaver/src/Unix/tunconfig /usr/share/sheepshaver-sdl/tunconfig

# Create non-root user (container normally needs root/privileged device access,
# but this keeps a home directory ready for rootless experiments).
RUN useradd -m -s /bin/bash sheepshaver \
    && mkdir -p /home/sheepshaver/.sheepshaver \
    && chown -R sheepshaver:sheepshaver /home/sheepshaver

# Volume for ROM, disk images, and preferences.
VOLUME ["/data"]

# Direct-display defaults for Raspberry Pi console use.
ENV SDL_VIDEODRIVER=kmsdrm
ENV SDL_AUDIODRIVER=alsa

WORKDIR /data

ENTRYPOINT ["/usr/bin/SheepShaver"]
CMD ["--config", "/data/sheepshaver_prefs"]
