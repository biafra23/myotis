# Build & Run — full reference

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before building for Android or iOS, or when a build fails on a missing toolchain.

## Build & Run

```bash
# Build all modules. NOTE: :android-app builds the Rust engine from source by
# default, so a full build needs the Android Rust toolchain (cargo + the cargo-ndk
# and NDK versions pinned in gradle/libs.versions.toml + the
# aarch64/x86_64-linux-android rustup targets). Without it, add
# -PskipRustEngine to build the app on the Java engine, which boots only on
# Android 13 / API 33+ (see the Rust section below).
./gradlew build                  # add -PskipRustEngine without the Android Rust toolchain

# Compile only (no tests)
./gradlew compileJava

# Run tests (all modules) — same toolchain note as `build`; :android-app's test
# tasks also go through its preBuild gate.
./gradlew test                   # add -PskipRustEngine without the Android Rust toolchain

# Run a single test class
./gradlew :networking:test --tests "com.jaeckel.ethp2p.networking.rlpx.HandshakeRoundTripTest"

# Start daemon (mainnet, blocks until stopped)
./gradlew :app:run

# Start daemon on another network
./gradlew :app:run -Pnetwork=gnosis     # Gnosis Chain (chainId 100, its own beacon chain)
./gradlew :app:run -Pnetwork=sepolia    # Ethereum testnet
./gradlew :app:run -Pnetwork=chiado     # Gnosis testnet (chainId 10200, Gnosis beacon preset)
# (holesky was retired — the EF shut it down in Oct 2025: no peers, no checkpoint servers)

# Run a second network alongside mainnet (separate daemon, separate port + socket)
./gradlew :app:run -Pnetwork=gnosis -Pport=30304

# Send IPC commands to running daemon
./gradlew :app:run -Pargs=status
./gradlew :app:run -Pargs=peers
./gradlew :app:run -Pargs="get-headers 21000000 3"
./gradlew :app:run -Pargs=stop
./gradlew :app:run -Pargs=purge-cache

# Rust workspace (rust/ — native BLS + the growing Rust engine). OPTIONAL for the
# JVM hosts (daemon/desktop): without cargo these self-skip with one note and the
# pure-Java build is unaffected. The ANDROID app is the exception — it requires the
# toolchain by default (see below), or -PskipRustEngine to opt out.
./gradlew cargoBuildHost   # cargo build --release (auto-runs before :app:run / :consensus:test)
./gradlew cargoTest        # cargo test --workspace (part of `check`)
./gradlew cargoBuildNoStd  # no_std canary: cargo build -p myotis-core --no-default-features for x86_64-unknown-none (part of `check`; self-skips without that rustup target)
./gradlew cargoNdkAndroid  # Android jniLibs, built from source (needs cargo-ndk + NDK + Android rustup targets)

# The Android engine library (:myotis-engine, the AAR the Android app consumes)
# builds the Rust engine FROM SOURCE by default — cargo + the pinned cargo-ndk and
# NDK (gradle/libs.versions.toml) +
# `(cd rust && rustup target add aarch64-linux-android x86_64-linux-android)` are REQUIRED to
# build it, and so :android-app. There is no committed .so (so nothing can drift);
# an Android build also regenerates the committed UniFFI bindings (:myotis-engine-rust)
# from source — other workflows do NOT, so regenerate them explicitly with
# `./gradlew uniffiGenerateKotlin` after changing the Rust FFI. Opt out when you
# lack the toolchain — the build tells you about the switch — with:
./gradlew :android-app:assembleDebug -PskipRustEngine  # Java engine only (no Rust engine / native BLS); boots on API 33+ only

# iOS (macOS only; needs Xcode 26+ and the rustup targets on the toolchain the
# workspace's rust-toolchain.toml pins — run inside rust/ so they land on it:
# `(cd rust && rustup target add aarch64-apple-ios aarch64-apple-ios-sim)`).
# Cargo stays optional here too: without the toolchain (and with no previously
# built libmyotis_engine.a) :myotis-engine-ios and :app-ios disable their tasks with a warning
# instead of failing the build — the full toolchain is required only to actually
# build the iOS app.
./gradlew cargoBuildIosSim                              # libmyotis_engine.a for the arm64 simulator
./gradlew cargoBuildIosDevice                           # libmyotis_engine.a for arm64 devices
./gradlew :app-ios:linkDebugFrameworkIosSimulatorArm64  # MyotisKit.framework (runs cargo first)
# The app itself builds from ios-app/ (Xcode project, regenerable with `xcodegen generate`):
#   cd ios-app && xcodebuild -project Myotis.xcodeproj -scheme Myotis \
#     -destination 'platform=iOS Simulator,name=<device>' build
```
