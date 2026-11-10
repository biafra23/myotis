# Source this before a cargo build that ships (#734, Part 4b, D2):
#     . rust/repro-env.sh
# Gradle's cargo tasks set the same variables themselves (root
# build.gradle.kts, reproducibleRustEnv) — keep the two in step.
#
# Rust embeds absolute source paths in panic locations: a release
# libmyotis_engine.so carried 726 `$CARGO_HOME/registry/src/...` paths, so its
# bytes depended on the builder's home directory. These variables remap them
# (and this checkout's rust/ directory, for OUT_DIR-generated code) to fixed
# prefixes: rustc via CARGO_TARGET_<TRIPLE>_RUSTFLAGS, which cargo MERGES with
# rust/.cargo/config.toml's per-target flags (the Android 16 KB page-size flag
# survives — RUSTFLAGS would have replaced it), and C code built by the cc
# crate via CFLAGS_<triple> (-ffile-prefix-map; not for MSVC, whose cl.exe
# does not take it). Set for the host and every target this repo builds.
# Cargo's own `trim-paths` would replace all this once it is stable.
#
# Limitations (the build still works, the paths are just not remapped): cargo
# splits these variables on whitespace, so a CARGO_HOME or checkout path with a
# space is skipped; and under Git Bash on Windows the prefixes built here
# (/c/... and mixed separators) do not match the C:\... paths rustc sees.
# Gradle's twin builds native paths, so Gradle-built Windows libs are covered.

_repro_rust=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
_repro_cargo_home=${CARGO_HOME:-$HOME/.cargo}
_repro_rustflags="--remap-path-prefix=$_repro_cargo_home/registry/src=/cargo/registry/src --remap-path-prefix=$_repro_cargo_home/git/checkouts=/cargo/git/checkouts --remap-path-prefix=$_repro_rust=/myotis/rust"
_repro_cflags="-ffile-prefix-map=$_repro_cargo_home/registry/src=/cargo/registry/src -ffile-prefix-map=$_repro_cargo_home/git/checkouts=/cargo/git/checkouts -ffile-prefix-map=$_repro_rust=/myotis/rust"
for _repro_t in $(rustc -vV 2>/dev/null | sed -n 's/^host: //p') \
    aarch64-linux-android x86_64-linux-android armv7-linux-androideabi \
    aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
    aarch64-apple-darwin x86_64-apple-darwin \
    x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-msvc \
    x86_64-unknown-none wasm32-unknown-unknown; do
    export "CARGO_TARGET_$(printf '%s' "$_repro_t" | tr 'a-z-' 'A-Z_')_RUSTFLAGS=$_repro_rustflags"
    case "$_repro_t" in
        *-msvc) ;;
        *) export "CFLAGS_$(printf '%s' "$_repro_t" | tr '-' '_')=$_repro_cflags" ;;
    esac
done
unset _repro_rust _repro_cargo_home _repro_rustflags _repro_cflags _repro_t
