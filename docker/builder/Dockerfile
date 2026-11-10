# The Myotis builder image (#734, Part 5b, decision D-c): the toolchain a
# release build of the Linux and Android artifacts needs, and nothing that
# moves. Everything in it is pinned by digest or hash:
#
#   base image            by digest (BASE_IMAGE)
#   apt packages          from snapshot.ubuntu.com at one instant (APT_SNAPSHOT)
#   Temurin JDK           by SHA-256
#   rustup-init           by SHA-256; rustc by exact version
#   Android cmdline-tools by SHA-256; the NDK and build-tools by exact version,
#                         the platform by API level and checked revision
#   cargo-ndk             by exact version, built --locked
#
# Do not `docker build` this by hand: docker/builder/build.sh passes the build
# args, reading the versions from the files that pin them for the build itself
# (docker/builder/pins.env lists which). docker/builder/check.sh verifies the
# result against the same pins.
#
# linux/amd64 only: the artifacts built in it are the Android APKs and engine
# library, the Linux x86_64 host libraries and the .deb.
#
# The image has no user of its own: run it as any uid (`docker run --user`),
# with HOME, CARGO_HOME and GRADLE_USER_HOME pointing at writable directories.
# /opt is read-only at run time, which is the point: the build cannot install
# or upgrade a tool.

ARG BASE_IMAGE
FROM ${BASE_IMAGE}

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# --- apt, from one snapshot ---------------------------------------------------
# EVERY package comes from the snapshot; the live archive is never used. The
# base image has no CA certificates and the snapshot service is HTTPS-only, so
# the first fetch (the index and ca-certificates itself) runs without TLS
# peer verification. That costs no integrity: apt checks the Release file's
# signature against the archive keyring in the base image and every package's
# hash against it. Every fetch after that verifies TLS too. Release files of a
# past snapshot are past their Valid-Until by design.
ARG APT_SNAPSHOT
RUN . /etc/os-release \
 && printf '%s\n' \
      "Types: deb" \
      "URIs: https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}" \
      "Suites: ${VERSION_CODENAME} ${VERSION_CODENAME}-updates ${VERSION_CODENAME}-security" \
      "Components: main universe" \
      "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" \
      > /etc/apt/sources.list.d/ubuntu.sources \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
 && notls="-o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false" \
 && apt-get $notls update -qq \
 && apt-get $notls install -y -qq --no-install-recommends ca-certificates \
 && apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      curl git unzip zip xz-utils python3 file \
      gcc g++ libc6-dev make pkg-config binutils \
      fakeroot dpkg-dev \
      locales tzdata \
 && locale-gen en_US.UTF-8 \
 && rm -rf /var/lib/apt/lists/*

# --- JDK (Eclipse Temurin) ----------------------------------------------------
ARG JDK_VERSION
ARG JDK_BUILD
ARG JDK_SHA256
ENV JAVA_HOME=/opt/jdk
RUN major="${JDK_VERSION%%.*}" \
 && url="https://github.com/adoptium/temurin${major}-binaries/releases/download/jdk-${JDK_VERSION}%2B${JDK_BUILD}/OpenJDK${major}U-jdk_x64_linux_hotspot_${JDK_VERSION}_${JDK_BUILD}.tar.gz" \
 && curl -fsSL --retry 5 -o /tmp/jdk.tar.gz "$url" \
 && echo "${JDK_SHA256}  /tmp/jdk.tar.gz" | sha256sum -c - \
 && mkdir -p "$JAVA_HOME" \
 && tar -xzf /tmp/jdk.tar.gz -C "$JAVA_HOME" --strip-components=1 \
 && rm /tmp/jdk.tar.gz

# --- Rust ---------------------------------------------------------------------
# The exact rustc, with the Android targets. RUSTUP_HOME is read-only at run
# time; the build's CARGO_HOME (the registry) is the caller's, not this one.
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256
ARG RUST_VERSION
ARG CARGO_NDK_VERSION
ENV RUSTUP_HOME=/opt/rustup
RUN curl -fsSL --retry 5 -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && CARGO_HOME=/opt/cargo /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_VERSION}" \
      --target aarch64-linux-android --target x86_64-linux-android \
 && rm /tmp/rustup-init \
 && CARGO_HOME=/opt/cargo /opt/cargo/bin/cargo install cargo-ndk --version "${CARGO_NDK_VERSION}" --locked \
 && rm -rf /opt/cargo/registry /opt/cargo/git

# --- Android SDK --------------------------------------------------------------
ARG ANDROID_CMDLINE_TOOLS
ARG ANDROID_CMDLINE_TOOLS_SHA256
ARG ANDROID_NDK
ARG ANDROID_BUILD_TOOLS
ARG ANDROID_PLATFORM
ARG ANDROID_PLATFORM_REVISION
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/${ANDROID_NDK}
RUN curl -fsSL --retry 5 -o /tmp/clt.zip \
      "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS}_latest.zip" \
 && echo "${ANDROID_CMDLINE_TOOLS_SHA256}  /tmp/clt.zip" | sha256sum -c - \
 && mkdir -p "$ANDROID_HOME/cmdline-tools" \
 && unzip -q /tmp/clt.zip -d "$ANDROID_HOME/cmdline-tools" \
 && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
 && rm /tmp/clt.zip \
 && sdkmanager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
 && "$sdkmanager" --licenses >/dev/null < <(yes) \
 && "$sdkmanager" "ndk;${ANDROID_NDK}" "build-tools;${ANDROID_BUILD_TOOLS}" \
      "platforms;android-${ANDROID_PLATFORM}" >/dev/null < <(yes) \
 && rev=$(sed -n 's/^Pkg.Revision *= *//p' "$ANDROID_HOME/platforms/android-${ANDROID_PLATFORM}/source.properties" | tr -d '\r ') \
 && [ "$rev" = "${ANDROID_PLATFORM_REVISION}" ] \
    || { echo "platforms;android-${ANDROID_PLATFORM} is revision '$rev', pins.env expects ${ANDROID_PLATFORM_REVISION}: Google published a new one (android.jar is a compile input); review and move the pin" >&2; exit 1; } \
 && rm -rf /root/.android

# No `chmod -R a+rX /opt` layer: it would copy every file under /opt into a
# second layer and double the image. Root's umask 022 already leaves /opt
# readable by any uid, and check.sh runs every tool as an unprivileged one.
ENV PATH=/opt/jdk/bin:/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LANG=C.UTF-8
