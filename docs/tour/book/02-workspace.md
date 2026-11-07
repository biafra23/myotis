# The workspace: crates, features and profiles

*Stop 2 · Orientation* · 14 manifests and config files · about 70 minutes

Before any `.rs` file, read the manifests. They answer the questions Gradle answers on the JVM side: what gets built, from what, into which kind of artefact, and with which switches. A few lines here explain whole files later.

## Rust you will practise

- **Crates and artefacts** — Read a `Cargo.toml` and tell a library from a binary, and a `cdylib` from an `rlib`.
- **Features** — Follow a feature such as `tor` or `std` from a manifest down to the `#[cfg]` lines it switches on or off.
- **Profiles and workspaces** — Explain why `panic = "abort"` is set once, why `myotis-rpcd` lives under it and why `roost` and `tor-poc` live outside.

## Cargo in Gradle terms

A **package** (one `Cargo.toml`) builds one or more **crates**: at most one library (`src/lib.rs`) plus any number of binaries, examples, tests and benches. A **workspace** is a multi-project build with one shared `Cargo.lock` and one `target/` directory, like a Gradle root project with `include(...)`. Dependencies are declared by name and version (`tokio = "=1.52.3"`) or by path to a sibling crate (`myotis-net = { path = "../myotis-net" }`). The Gradle build in this repo calls cargo (`cargoBuildHost`, `cargoTest`, `cargoNdkAndroid`, the two canaries), so both worlds meet in the root `build.gradle.kts`.

A **feature** is a named compile-time switch. It has no Gradle twin. The closest picture is a set of Java source folders that exist only when a flag is set. In code, `#[cfg(feature = "x")]` on an item removes that item entirely when the feature is off: the compiler never type-checks it. A feature can also turn on an optional dependency (`"dep:jni"`) or a feature of another crate (`"myotis-net/tor"`). Features are additive: if any crate in the build turns a feature on, it is on for everyone who depends on that crate.

| Crate | Artefact | Notable switches | Stop |
|---|---|---|---|
| `myotis-bls` | cdylib + rlib | `jni`, `std` (both default) | [3](03-bls.md) |
| `myotis-core` | lib | `std` (default); no\_std canary | [4](04-core.md) |
| `myotis-wire` | lib | `std`, `eth2` (default), `test-util`; no\_std canary | [5](05-wire.md) |
| `myotis-consensus` | lib | `std` (default) | [6](06-consensus.md) |
| `myotis-evm` | lib | `fixture` (test tooling) | [7](07-evm.md) |
| `myotis-net` | lib + example | `tor`, `fixture-recorder` | [9](09-net-cl.md)–[15](15-net-tests.md) |
| `myotis-engine` | cdylib + rlib (+ staticlib for iOS) | `tor` | [16](16-engine.md) |
| `uniffi-bindgen` | bin (tool) | none | [17](17-uniffi.md) |
| `myotis-node` | cdylib | none | [18](18-node.md) |
| `myotis-rpcd` | bin | none | [19](19-rpcd.md) |
| `roost` (excluded) | bin | own profile: `panic = "unwind"` | [20](20-roost.md) |
| `tor-poc` (excluded) | bin | Arti always on | [21](21-torpoc.md) |

<a id="f-cargo-toml"></a>

### /Cargo.toml

*workspace manifest · 82 lines*

The workspace root. It lists the ten member crates, excludes the two standalone ones, pins one release version and one minimum compiler for all members, and owns the release profile. The long header comment (lines 1–41) describes the crates in one paragraph each; it is the best short description of the architecture in the repo.

`rust/Cargo.toml` · lines 43–56

```toml
[workspace]
resolver = "2"
members = ["myotis-bls", "myotis-consensus", "myotis-core", "myotis-wire", "myotis-evm", "myotis-engine", "myotis-net", "myotis-node", "myotis-rpcd", "uniffi-bindgen"]
# tor-poc (docs/privacy-and-tor.md §3 proof-of-concept) is a STANDALONE crate,
# excluded on purpose: it pulls the whole Arti dependency tree, which must never
# burden the pure-engine build or CI. It depends on myotis-net/myotis-core by
# path and builds on its own with `cargo run --manifest-path tor-poc/Cargo.toml`.
#
# roost (docs/lc-server-design.md) is excluded for the same two reasons plus one
# more: it is a SERVER daemon, so it must not inherit `panic = "abort"` below —
# in a process holding 1000+ wallet connections that turns one panic into an
# outage for all of them. Excluded, it carries its own profile with
# `panic = "unwind"`. It also pulls an HTTP stack no engine target links.
exclude = ["tor-poc", "roost"]
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Resolver 2.** `resolver = "2"` resolves features per target and per dependency kind. A `[dev-dependencies]` feature cannot leak into the shipped library, and a feature asked for under `[target.'cfg(...)'.dependencies]` stays on that target. Several manifests below rely on both rules.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Members and exclusions.** Since the September tour two members joined: `myotis-wire`, the sans-I/O protocol code split out of `myotis-net`, and `myotis-rpcd`, the JSON-RPC daemon. `exclude` keeps `tor-poc` and `roost` out of `cargo build --workspace`, even though they sit in the same directory tree.

`rust/Cargo.toml` · lines 72–82

```toml
[workspace.package]
version = "0.1.20"
rust-version = "1.91"

# Release profile is workspace-owned (crate-level [profile.*] is ignored in a
# workspace): same tuning myotis-bls always shipped with.
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Inherited package fields.** Each member writes `version.workspace = true` and `rust-version.workspace = true`, so all of them are `0.1.20` and need rustc 1.91 or newer. Gradle stays the source of truth for the version: `verifyCrateVersions` fails `check` if this line disagrees with the root `build.gradle.kts`, or if a `myotis-*` manifest stops inheriting it. The Gradle toolchain probe reads `rust-version` to decide whether an installed cargo is new enough, and `verifyRustVersionFloor` fails `check` when a lock update pulls in a crate that needs a newer compiler.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Profiles belong to the workspace.** A member's own `[profile.*]` is ignored. So `panic = "abort"` applies to every member: a panic ends the process at once instead of unwinding the stack. The roost manifest calls it the right FFI rule for the engine: a Rust panic must not unwind out through a C or JVM frame (depending on the ABI that is undefined behaviour or an abort anyway), so ending at once is the predictable choice. `roost`, which wants `unwind`, must therefore be its own workspace root. `lto = true` plus `codegen-units = 1` trade build time for smaller, faster binaries, which matters on mobile.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Why `myotis-rpcd` is a member.** The daemon links the engine in-process. The engine already lives under `panic = "abort"`, so the daemon gains nothing from a separate profile, and it adds only `tiny_http` and `clap` to the build.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The header comment's member list (lines 3–38) describes every member except `myotis-node`, which is in `members` on line 45.

<a id="f-myotis-bls-cargo-toml"></a>

### myotis-bls/Cargo.toml

*crate manifest · 30 lines*

One crate, two artefact kinds, and two features: one decides whether the JNI glue is compiled at all, the other whether the crate links the standard library.

`rust/myotis-bls/Cargo.toml` · lines 9–27

```toml
[lib]
# cdylib → libmyotis_bls.{so,dylib,dll} for the desktop JVM and (via cargo-ndk) each
# Android ABI. rlib → in-workspace reuse: myotis-consensus calls the pure verify core
# directly (feature `jni` off), no dynamic library involved.
crate-type = ["cdylib", "rlib"]

[features]
# The JNI shim is only wanted in the cdylib the JVM loads; pure-Rust consumers
# (myotis-consensus) depend with default-features = false.
default = ["jni", "std"]
jni = ["dep:jni", "std"]
# Off only for no_std hosts (firmware): myotis-consensus forwards its own `std`.
std = []

[dependencies]
# Supranational blst: the BLS12-381 lib every major Ethereum CL client ships (C + asm).
blst = "0.3"
# JNI bindings so the JVM/Android can call in (optional — see the `jni` feature).
jni = { version = "0.21", default-features = false, optional = true }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **`cdylib` and `rlib`.** A `cdylib` is a C-compatible dynamic library (`.so`/`.dylib`/`.dll`) that a JVM or Node can `dlopen`. An `rlib` is Rust's own library format, used when another crate in the workspace depends on this one. `myotis-engine` is also built as a `staticlib` (`.a`) for iOS, through `cargo rustc --crate-type staticlib`.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Optional dependency plus feature.** `jni` is compiled only when the `jni` feature is on (`"dep:jni"`), and turning on `jni` also turns on `std`. Both are on by default, so the cdylib the Java engine loads has the shim. `std = []` enables no dependency: it exists only so that the code can test `cfg(feature = "std")`.

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* `myotis-consensus` opts out of the defaults and forwards its own `std` feature down:

`rust/myotis-consensus/Cargo.toml` · lines 9–11

```toml
[dependencies]
# The pure BLS verify core (no JNI — this crate is a plain lib).
myotis-bls = { path = "../myotis-bls", default-features = false }
```

`rust/myotis-consensus/Cargo.toml` · lines 25–30

```toml
# `no_std` + `alloc` with `default-features = false`, like myotis-core: the
# light-client core is sans-I/O, so firmware and other bare-metal hosts can run
# it. `std` (default) keeps every existing consumer unchanged.
[features]
default = ["std"]
std = ["sha2/std", "tracing/std", "myotis-bls/std"]
```

So a default build of `myotis-consensus` gets the BLS verify core with `std` but without JNI. A `--no-default-features` build of consensus gets the verify core with neither.

<a id="f-myotis-core-cargo-toml"></a>

### myotis-core/Cargo.toml

*crate manifest · 53 lines*

The execution-layer primitives crate promises to build without the standard library. The manifest shows how that promise is kept: a `std` feature that forwards to the dependencies' own `std` features, dependencies with `default-features = false`, and a dependency that exists only on bare-metal targets.

`rust/myotis-core/Cargo.toml` · lines 23–39

```toml
[features]
default = ["std"]
std = ["sha3/std"]

[dependencies]
# keccak-256 (EL hashing — never mix with the CL's SHA-256, see docs/reimplementation README §11.6)
# default-features off: sha3's default `std` (→ digest/std → `extern crate std`)
# comes through this crate's `std` feature instead, so `--no-default-features`
# really is std-free.
sha3 = { version = "=0.10.9", default-features = false }
# secp256k1: sign-prehashed/recover (discv4 packets, RLPx auth) + ECDH (ECIES).
# Pure Rust (RustCrypto) — no C build, cargo-ndk/wasm32-clean. `precomputed-tables`
# deliberately off (binary size; mobile targets). NO `std` feature: k256/std →
# elliptic-curve/std → rand_core/std → getrandom, which doesn't build for plain
# wasm32-unknown-unknown and would kill the sans-I/O canary (this crate needs no
# entropy — key GENERATION lives in the I/O crates).
k256 = { version = "=0.13.4", default-features = false, features = ["ecdsa", "ecdh"] }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`no_std` + `alloc`.** Rust's standard library comes in layers. `core` has no allocation and no OS. `alloc` adds `Vec`, `String` and `Box` on top of any allocator. `std` adds files, threads, sockets and the clock. A crate marked `#![no_std]` links only the first two, so it can run in firmware. On the JVM there is no equivalent: the class library is always there.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Why every dependency says `default-features = false`.** Most crates turn on their own `std` by default. One dependency with its defaults left on would pull `std` into the whole graph, so each one is opted out and gets `std` back only through this crate's `std = ["sha3/std"]`.

`rust/myotis-core/Cargo.toml` · lines 52–53

```toml
[target.'cfg(any(target_os = "uefi", target_os = "none"))'.dependencies]
sha2 = { version = "=0.10.9", default-features = false, features = ["force-soft"] }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* A `[target.'cfg(...)'.dependencies]` table applies only when building for a matching target. Here it does not add a crate; it adds a *feature* (`force-soft`) to `sha2`, which already arrives through `k256`. Under resolver 2 that feature stays on the bare-metal targets, so every other build keeps the fast SIMD backend.

*[Tests](01-primer.md#primer-testing)* The promise is tested by the **no\_std canary**, a Gradle task wired into `check`. `x86_64-unknown-none` ships no `std` at all, so any leak fails here and nowhere else. It builds `myotis-wire` too:

`build.gradle.kts` · lines 880–892

```kotlin
val cargoBuildNoStd = tasks.register<Exec>("cargoBuildNoStd") {
    group = "rust"
    description = "cargo build -p myotis-core -p myotis-wire --no-default-features for x86_64-unknown-none — the no_std canary (self-skips without cargo + the rustup target)"
    onlyIf { rustAvailable && noStdTargetInstalled }
    workingDir = file("rust")
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(
        rustTool("cargo"), "build", "--target", "x86_64-unknown-none",
        "-p", "myotis-core", "-p", "myotis-wire", "--no-default-features",
    )
    // No declared outputs, same rationale as cargoTest.
}
tasks.named("check") { dependsOn(cargoBuildNoStd) }
```

A second canary, `cargoCheckWasm`, runs `cargo check` for `wasm32-unknown-unknown` on `myotis-consensus`, `myotis-core` and `myotis-wire`. It proves those crates stayed sans-I/O, because tokio and libp2p do not build for plain wasm32. It needs clang, because blst compiles its C sources for wasm.

<a id="f-myotis-wire-cargo-toml"></a>

### myotis-wire/Cargo.toml

*crate manifest · 48 lines*

The wire protocols without an async runtime ([Stop 5](05-wire.md)). Its features let a host take only the execution-layer half and skip the consensus crate, and with it the blst C library.

`rust/myotis-wire/Cargo.toml` · lines 17–41

```toml
[features]
default = ["std", "eth2"]
std = ["myotis-core/std", "myotis-consensus?/std", "tracing?/std", "dep:snap"]
# The consensus-layer req/resp wire (eth2::{codec, status, protocols}). It is
# the only part that needs myotis-consensus -- and through it myotis-bls and the
# blst C library -- so an execution-layer-only host (discv4, RLPx, eth, snap)
# can turn it off and skip cross-compiling blst.
eth2 = ["dep:myotis-consensus", "dep:tracing"]
# `SessionSecrets::test_pair` for other crates' tests (myotis-net's frame/session tests).
test-util = []

[dependencies]
myotis-core = { path = "../myotis-core", default-features = false }
# eth2 status/fork-digest SSZ helpers.
myotis-consensus = { path = "../myotis-consensus", default-features = false, optional = true }
# Diagnostics in the eth2 multi-chunk decoder (I/O-free facade).
tracing = { version = "=0.1.44", default-features = false, optional = true }
aes = { version = "=0.8.4", default-features = false }
ctr = { version = "=0.9.2", default-features = false }
cipher = { version = "=0.4.4", default-features = false }
hmac = { version = "=0.12.1", default-features = false }
sha2 = { version = "=0.10.9", default-features = false }
sha3 = { version = "=0.10.9", default-features = false }
subtle = { version = "=2.6.1", default-features = false }
snap = { version = "=1.1.1", optional = true }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A weak feature: `"myotis-consensus?/std"`.** The `?` means "turn on `std` in `myotis-consensus`, but only if that optional dependency is already enabled". Without the `?`, enabling `std` would also pull in `myotis-consensus`, and an execution-layer-only host could no longer leave it out.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`eth2` gates a whole module.** In `lib.rs`, `#[cfg(feature = "eth2")] pub mod eth2;` means the module does not exist without the feature. The no\_std canary builds with `--no-default-features`, so it builds neither `std` nor `eth2`, and therefore no consensus code.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **A feature for other crates' tests.** `test-util` exposes helpers under `#[cfg(any(test, feature = "test-util"))]`. `cfg(test)` is true only when this crate's own tests are compiled, so another crate's tests need the feature. `myotis-net` asks for it in its `[dev-dependencies]`.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> Lines 43–46 say that bare-metal builds must set `RUSTFLAGS="--cfg aes_force_soft"`. `rust/.cargo/config.toml` now sets that cfg per target, so any cargo invocation inside `rust/` gets it without an environment variable. Only an embedder building outside this tree still has to set it.

<a id="f-myotis-net-cargo-toml"></a>

### myotis-net/Cargo.toml

*crate manifest · 114 lines*

The I/O crate. Its runtime and networking dependencies are pinned *exactly* (`=`), because interop with live peers depends on wire-level behaviour of those versions. RLPx's crypto moved to `myotis-wire` with the code that uses it. Tor support is optional and chooses its TLS backend per target.

`rust/myotis-net/Cargo.toml` · lines 24–28

```toml
# Exact pins: this crate owns the I/O surface and interop with live CL peers
# depends on wire-level behavior of these exact versions (noise/yamux framing,
# discv5 packet format). Cargo.lock would pin them anyway; the `=` makes the
# intent explicit and survives lockfile regeneration.
tokio = { version = "=1.52.3", features = ["rt-multi-thread", "macros", "time", "sync", "signal", "net", "io-util"] }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* `"=1.52.3"` means exactly this version. A plain `"1.52"` would mean "any compatible 1.x at or above 1.52", like a Gradle dynamic version. `features = [...]` picks which parts of tokio to compile; tokio has almost nothing on by default.

`rust/myotis-net/Cargo.toml` · lines 77–97

```toml
[target.'cfg(not(target_os = "android"))'.dependencies]
arti-client = { version = "0.44", default-features = false, features = ["tokio", "native-tls"], optional = true }
tor-rtcompat = { version = "0.44", default-features = false, features = ["tokio", "native-tls"], optional = true }

[target.'cfg(target_os = "android")'.dependencies]
arti-client = { version = "0.44", default-features = false, features = ["tokio", "rustls", "static-sqlite"], optional = true }
tor-rtcompat = { version = "0.44", default-features = false, features = ["tokio", "rustls"], optional = true }
# Must stay the rustls tor-rtcompat links: install_default() (el/tor.rs) writes
# THIS crate's process-default static, so a second rustls version would leave
# Arti's copy without a provider — and its RustlsProvider::new panics (an abort
# under the workspace profile) on the first Tor read. After an Arti bump, check
# that `cargo tree --target aarch64-linux-android -p myotis-net --features tor
# -i rustls` still resolves (it errors out when there are two versions).
rustls = { version = "0.23", default-features = false, features = ["ring", "std"], optional = true }

[features]
tor = ["dep:arti-client", "dep:tor-rtcompat", "dep:rustls"]
# The EVM fixture recorder's seam (`ElReader::head_evm_oracle`) and
# myotis-evm's recorded-world files, for examples/record_shield_fixture.rs.
# Test tooling: on only through this crate's own dev-dependency below.
fixture-recorder = ["myotis-evm/fixture"]
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **One optional dependency, two target tables.** `arti-client` is declared twice, once for every target except Android (native-tls) and once for Android (rustls plus bundled SQLite). Both are `optional = true`, and the single `tor` feature enables whichever one the current target has. The comment on lines 68–76 explains why it is not one table plus a feature: tor-rtcompat silently prefers native-tls when both are on.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`fixture-recorder` forwards to another crate's feature** (`myotis-evm/fixture`), so turning it on here compiles test tooling in both crates.

`rust/myotis-net/Cargo.toml` · lines 99–114

```toml
[dev-dependencies]
myotis-wire = { path = "../myotis-wire", features = ["test-util"] }
# readstats shape tests parse their own JSON output.
serde_json = "1"
# Tests and examples build this crate with `fixture-recorder`, so the fixture
# recorder example compiles in every `cargo test`/clippy run while the engine
# library and the shipped .so never carry its seam.
myotis-net = { path = ".", features = ["fixture-recorder"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
# test-util only: `#[tokio::test(start_paused = true)]` drives the interactive
# read HEDGING on the paused clock, so the timing invariants are asserted
# exactly and instantly instead of by sleeping in real time.
tokio = { version = "=1.52.3", features = ["test-util", "macros", "rt-multi-thread", "time"] }

[[example]]
name = "live_sync"
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **`[dev-dependencies]` is Gradle's `testImplementation`.** Here it adds tokio's `test-util`, which enables `#[tokio::test(start_paused = true)]`: tests run on a *virtual clock* that jumps forward instantly whenever every task is waiting.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **A crate that depends on itself.** `myotis-net = { path = ".", features = ["fixture-recorder"] }` under `[dev-dependencies]` is a known Cargo idiom. It turns on one of the crate's own features for its tests and examples only. The library that the engine links is built without it.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`[[example]]`** declares a runnable demo in `examples/` (`cargo run --example live_sync`). Cargo also discovers the other files in `examples/` on its own; the table only matters when a target needs settings.

<a id="f-myotis-engine-cargo-toml"></a>

### myotis-engine/Cargo.toml

*crate manifest · 61 lines*

The engine library forwards a feature to its dependency: turning on `myotis-engine/tor` turns on `myotis-net/tor`, which pulls in Arti. Only the desktop host library and the Android jniLibs are built that way, and only with `-PtorEngine`.

`rust/myotis-engine/Cargo.toml` · lines 9–23

```toml
[lib]
# libmyotis_engine.{so,dylib,dll} — loaded by :myotis-engine-rust's RustEngineNative.
# The iOS static archive is NOT listed here: the cargoBuildIos* Gradle tasks
# build it with `cargo rustc --crate-type staticlib` (which overrides this
# list), so host/Android builds don't pay for an archive they never consume.
crate-type = ["cdylib", "rlib"]

[features]
# Tor verified-read routing (docs/privacy-and-tor.md) — OFF by default. `-PtorEngine`
# enables it in the host dylib (`cargoBuildHost`) and the Android jniLibs
# (`cargoNdkAndroid`, via build-android.sh's MYOTIS_TOR_ENGINE) so the desktop and
# Android apps can offer the Settings toggle; iOS builds never do. The
# `set_tor_enabled`/`tor_status`/`set_tor_storage_dirs` FFI functions exist either
# way (they no-op / report "not compiled" / refuse without this feature).
tor = ["myotis-net/tor"]
```

> [!TIP]
> **Follow the feature**<br>
>
> `-PtorEngine` (Gradle) → `cargoBuildHost` appends `--features myotis-engine/tor` (the package/feature form, because a bare `--features tor` with `--workspace` would apply to every member), and `build-android.sh` does the same for `cargo ndk` → `myotis-engine`'s `tor = ["myotis-net/tor"]` → `myotis-net`'s `tor = ["dep:arti-client", "dep:tor-rtcompat", "dep:rustls"]` → the compiler now sees `#[cfg(feature = "tor")] pub mod tor;` in `el/mod.rs` and the first block of `set_tor_enabled` in `host.rs`. Without the feature, those lines do not exist for the compiler, and the function returns `false`.

`rust/myotis-engine/src/host.rs` · lines 233–244

```rust
pub fn set_tor_enabled(on: bool) -> bool {
    #[cfg(feature = "tor")]
    {
        myotis_net::el::tor::set_enabled(on);
        true
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = on;
        false
    }
}
```

*[Macros & attributes](01-primer.md#primer-macros) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `#[cfg]` on a block keeps or deletes that block before type checking. Exactly one of the two blocks survives, and it becomes the function's tail expression. `let _ = on;` uses the parameter in the Tor-less build so the compiler does not warn about an unused variable.

`rust/myotis-engine/Cargo.toml` · lines 50–61

```toml
# localtime_r, for the data-usage ledger's local day (usage.rs). Already in the
# lock through tokio.
[target.'cfg(unix)'.dependencies]
libc = "0.2"

[dev-dependencies]
# The block/header types (re-exported through myotis-net) are constructed directly
# in the block_json golden test; myotis-core is otherwise transitive via myotis-net.
myotis-core = { path = "../myotis-core" }
# The recorded RelayAdapt7702 shield (rust/testdata/evm): its request must parse
# here exactly as the replay reads it.
myotis-evm = { path = "../myotis-evm", features = ["fixture"] }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* `[target.'cfg(unix)'.dependencies]` adds `libc` only on Unix-like targets. The dev-dependency on `myotis-evm` with `features = ["fixture"]` is how the engine's own tests reach the EVM's in-memory oracle, while the shipped library is built without it.

<a id="f-myotis-evm-cargo-toml"></a>

### myotis-evm/Cargo.toml

*crate manifest · 53 lines*

revm is pinned exactly and trimmed with `default-features = false`, which drops its C-based precompile backends in favour of pure-Rust ones. The `optional_*` features expose switches an `eth_call` needs (no balance check, no base fee, and so on). The `fixture` feature lets downstream *tests* use an in-memory oracle and recorded-world files without shipping them in the engine binary.

`rust/myotis-evm/Cargo.toml` · lines 31–53

```toml
revm = { version = "=43.0.3", default-features = false, features = [
    "std",
    "optional_balance_check",
    "optional_block_gas_limit",
    "optional_eip3607",
    "optional_no_base_fee",
] }

# Only for the `fixture` feature's recorded-world files (`fixture::EvmFixture`);
# never in a default build. A dev-dependency too, for the crate's own tests.
serde_json = { version = "1", optional = true }

[dev-dependencies]
serde_json = "1"

[features]
# Test tooling, off by default so it never ships in the engine .so; the crate's
# own tests see it through `cfg(test)`. The in-memory FixtureSnapStateOracle
# for downstream tests (the engine crate's EVM tests), and `fixture::` — the
# recorded-world files the mainnet fixture recorder
# (rust/myotis-net/examples/record_shield_fixture) writes and the replay tests
# read.
fixture = ["dep:serde_json"]
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* In code this becomes `#[cfg(any(test, feature = "fixture"))]` on `pub mod fixture;` and on `FixtureSnapStateOracle`: compiled for the crate's own tests, or when a dependent crate asks for `features = ["fixture"]`. `serde_json` appears twice: once optional (pulled in only by `fixture`) and once as a dev-dependency for the crate's own tests.

<a id="f-myotis-node-cargo-toml"></a>

### myotis-node/Cargo.toml

*crate manifest · 23 lines*

The Node addon is a `cdylib` only ([Stop 18](18-node.md)). It links `myotis-engine` as a Rust library for its C-ABI symbols and adds napi-rs. `[build-dependencies]` are used by `build.rs`, a small program cargo compiles and runs *before* building the crate.

`rust/myotis-node/Cargo.toml` · lines 9–23

```toml
[lib]
# myotis-node.node — loaded by Node's process.dlopen via a thin JS loader.
crate-type = ["cdylib"]

[dependencies]
# Linked for its exported C-ABI symbols (capi.rs) — the same seam the iOS
# cinterop consumes, JSON shapes pinned by the cross-engine golden tests.
myotis-engine = { path = "../myotis-engine" }
napi = { version = "3", default-features = false, features = ["napi8"] }
napi-derive = "3"
# Checks the JSON arguments the engine leaves to its caller (#503).
serde_json = "1"

[build-dependencies]
napi-build = "2"
```

<a id="f-myotis-rpcd-cargo-toml"></a>

### myotis-rpcd/Cargo.toml

*crate manifest · 29 lines*

The JSON-RPC daemon ([Stop 19](19-rpcd.md)). It has no `[lib]` table and no `[[bin]]` table: a package with `src/main.rs` is a binary by convention. Its dependency list is short on purpose.

`rust/myotis-rpcd/Cargo.toml` · lines 9–29

```toml
[dependencies]
# The engine's public `ffi` surface (plus the two `capi` entries `ffi` has no
# wrapper for, create-with-checkpoint and set-boot-enodes). Default features:
# no Tor.
myotis-engine = { path = "../myotis-engine" }
# No tokio and no tracing here: the engine owns its runtime and its log ring,
# and this crate only ever calls the engine's blocking functions.
serde_json = "1"
# Only for `IgnoredAny` (counting a long result's elements in the call log
# without building them); already in the lock through serde_json.
serde = "1"
# clap is already in the lock (uniffi); its default `color` feature is left off
# because it alone would add six crates to it.
clap = { version = "4", default-features = false, features = ["std", "derive", "help", "usage", "error-context", "suggestions"] }
# A blocking HTTP/1.1 server: every engine read blocks (it may hold for a
# verified head), so a fixed worker pool over a synchronous server is the whole
# design — see main.rs. No async stack is linked for it.
tiny_http = "0.12"
# The `iterator` module exists only off Windows; main.rs waits on it under
# cfg(unix) and polls `signal_hook::flag` on Windows, which needs no feature.
signal-hook = { version = "0.4", default-features = false, features = ["iterator"] }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **No async stack.** The engine owns its tokio runtime, and every engine read blocks. So the daemon uses a blocking HTTP server (`tiny_http`) with a fixed pool of worker threads, like a classic servlet container, and does not depend on tokio itself.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* **Trimming features to trim the lock file.** `clap` is already in the lock through `uniffi`. Turning its defaults off and listing only the needed features avoids the `color` feature, which would add six crates.

<a id="f-roost-cargo-toml"></a>

### roost/Cargo.toml

*standalone manifest · 63 lines*

An empty `[workspace]` table makes this package its own workspace root, with its own `Cargo.lock` and its own profile. That is the whole trick behind "excluded". It still depends on `myotis-net` and `myotis-consensus` by path, so a dependency change in `rust/` must update this lock file too.

`rust/roost/Cargo.toml` · lines 27–32

```toml
# Own workspace root: keeps this out of the parent workspace entirely.
[workspace]

[[bin]]
name = "roost"
path = "src/main.rs"
```

`rust/roost/Cargo.toml` · lines 57–63

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
# DELIBERATE divergence from the parent workspace's `panic = "abort"` — see the
# header. This is the reason the crate is excluded rather than a member.
panic = "unwind"
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Binaries, CLIs & signals](01-primer.md#primer-cli) · [Result, ? and panics](01-primer.md#primer-error-handling)* `[[bin]]` declares an executable target. With `panic = "unwind"`, a panic unwinds only the tokio task it happens in, and the task's `JoinHandle` reports it as an error value (`JoinError::is_panic()`) instead of the process dying on the spot. Be precise about what that buys. The manifest header (lines 15–16) says a malformed chunk "kills one connection", but roost's README corrects this: requests are answered inline on the single libp2p *swarm* task, so a panic there ends every connection. `serve` notices the dead task, logs it and exits non-zero, and systemd restarts the daemon ([Stop 20](20-roost.md)). The gain is a controlled, observable restart, not per-connection isolation.

<a id="f-tor-poc-cargo-toml"></a>

### tor-poc/Cargo.toml

*standalone manifest · 38 lines*

The Tor proof of concept ([Stop 21](21-torpoc.md)) uses the same empty-`[workspace]` trick, for a different reason: it always links Arti, and the Arti tree must never burden the engine build or CI. Unlike `myotis-net`, it pins only native-tls, because it runs on desktop only.

`rust/tor-poc/Cargo.toml` · lines 15–31

```toml
# Own workspace root: keeps this out of the parent workspace entirely.
[workspace]

[[bin]]
name = "tor-poc"
path = "src/main.rs"

[dependencies]
# The real Myotis EL stack — the whole point is to reuse it verbatim.
myotis-net = { path = "../myotis-net" }
myotis-core = { path = "../myotis-core" }

# Arti — the Tor Project's official embeddable Rust client (docs §3). native-tls
# (macOS Security.framework / system trust store) sidesteps the rustls 0.23
# process-wide CryptoProvider selection; tokio matches the engine's runtime.
arti-client = { version = "0.44", default-features = false, features = ["tokio", "native-tls"] }
tor-rtcompat = { version = "0.44", default-features = false, features = ["tokio", "native-tls"] }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Both standalone crates are pinned at `0.0.0`. They are not release artefacts, and `verifyCrateVersions` only checks manifests that match `myotis-*/Cargo.toml`.

<a id="f-uniffi-bindgen-cargo-toml"></a>

### uniffi-bindgen/Cargo.toml

*tool manifest · 26 lines*

The smallest crate in the repo: a binary whose three-line `main` calls `uniffi::uniffi_bindgen_main()` ([Stop 17](17-uniffi.md)). It exists so that the generator version always matches the `uniffi` version the engine links against. It sets its own `version` instead of inheriting the workspace one, because it is a pinned tool, not a release artefact.

`rust/uniffi-bindgen/Cargo.toml` · lines 8–26

```toml
publish = false

# The standard UniFFI pattern: a tiny workspace-local bin wrapping the bindgen
# CLI, so binding generation is pinned to the exact uniffi version the engine
# links against (a version skew between scaffolding and generator is a build
# error by design). Regenerate the COMMITTED Kotlin bindings only through the
# root Gradle task `uniffiGenerateKotlin`: it also masks the generated u16
# checksum comparisons to 16 bits (see the task), which a direct run does not do,
# and the APK workflow's drift check fails on unmasked bindings. A direct run is
# for inspecting output:
#   cargo run -p uniffi-bindgen -- generate \
#     --library target/release/libmyotis_engine.so --language kotlin --out-dir <dir>

[[bin]]
name = "uniffi-bindgen"
path = "src/main.rs"

[dependencies]
uniffi = { version = "0.32", features = ["cli"] }
```

> [!WARNING]
> **Worth remembering**<br>
>
> UniFFI embeds a checksum per exported function in the scaffolding, and the generated Kotlin verifies it at load time. Any change to `ffi.rs`, even a doc comment, changes a checksum, so the committed bindings must be regenerated afterwards. Regenerate them through Gradle's `uniffiGenerateKotlin`, not a direct `cargo run`: the Gradle task also masks the generated checksum comparisons to 16 bits, and the APK workflow's drift check fails on unmasked bindings.

<a id="f-cargo-config-toml"></a>

### .cargo/config.toml

*cargo config · 36 lines*

Per-target compiler flags, applied to every cargo invocation inside `rust/`. The first three tables serve Android: Android 15+ devices can use 16 KB memory pages, and a library linked with 4 KB-aligned segments fails to `dlopen` there. The last three serve the bare-metal targets of the no\_std promise.

`rust/.cargo/config.toml` · lines 13–20

```toml
[target.aarch64-linux-android]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384"]

[target.x86_64-linux-android]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384"]

[target.armv7-linux-androideabi]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384"]
```

`rust/.cargo/config.toml` · lines 29–36

```toml
[target.x86_64-unknown-none]
rustflags = ["--cfg", "aes_force_soft"]

[target.x86_64-unknown-uefi]
rustflags = ["--cfg", "aes_force_soft"]

[target.aarch64-unknown-uefi]
rustflags = ["--cfg", "aes_force_soft"]
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* `-C link-arg=...` passes a flag through to the linker. `--cfg aes_force_soft` defines a custom configuration flag for the compiler, which the `aes` crate tests with `#[cfg(aes_force_soft)]`. The `aes` crate has no Cargo feature for this, so a cfg flag is the only switch. Putting it here rather than in a CI `RUSTFLAGS` variable means the no\_std canary, an embedder building in-tree and a developer at the shell all get the same flags.

<a id="f-rust-toolchain-toml"></a>

### /rust-toolchain.toml

*toolchain pin · 5 lines*

Tells `rustup` which compiler to use inside `rust/`: the current stable. The minimum version is `rust-version` in the workspace manifest, enforced by the Gradle probe, rather than an exact pin here, because Rust is optional for most developers and an exact pin would force downloads. The file applies only under `rust/`; cargo run from the repo root uses rustup's default toolchain.

`rust/rust-toolchain.toml` · lines 1–5

```toml
# Track stable. The minimum rustc is `rust-version` in Cargo.toml [workspace.package],
# which the Gradle probe (root build.gradle.kts) enforces; pinning an exact version here would force rustup downloads on machines that
# already have a new-enough stable, which fights the "Rust is optional" build design.
[toolchain]
channel = "stable"
```

## The rest of `rust/`

- `Cargo.lock`: exact resolved versions of every transitive dependency. Committed, because this workspace produces shipped binaries. `roost/` and `tor-poc/` each have their own.
- `include/myotis_engine.h`: the hand-written C header for `capi.rs`. A unit test pins its `MYOTIS_ABI_VERSION` (55 at this snapshot) to `lib.rs`'s `ABI_VERSION` ([Stop 16](16-engine.md)).
- `build-android.sh` / `build-xcframework.sh`: cross-compilation helpers (cargo-ndk for the Android ABIs, with `MYOTIS_TOR_ENGINE` adding the `tor` feature; device and simulator slices packed into an xcframework for Swift hosts).
- `bench/sync_bench.sh`: the Rust-vs-JVM cold-sync benchmark (wall time, RSS, CPU).
- `testdata/`: conformance corpora generated from the Java engine (`el/`, `lc/`), recorded EVM worlds (`evm/`), a golden snapshot, anchor fixtures and the network catalog. Both engines replay the same bytes ([Stop 15](15-net-tests.md)).

## Checkpoint

10 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-ws-q1"></a>

**Q1** · Multiple choice

`crate-type = ["cdylib", "rlib"]` in `myotis-bls` produces…

- **A.** two copies of the same Rust library
- **B.** a C-compatible shared library the JVM can load, and a Rust library other workspace crates link against
- **C.** a static library for iOS and a WebAssembly module
- **D.** an executable and a library

[Answer →](answers.md#a-ws-q1)

<a id="q-ws-q2"></a>

**Q2** · Multiple choice

`myotis-bls` has `default = ["jni", "std"]`. `myotis-consensus` depends on it with `default-features = false` and has `std = ["sha2/std", "tracing/std", "myotis-bls/std"]` as a default feature. What does a default build of consensus get from `myotis-bls`?

- **A.** Nothing; the dependency is disabled
- **B.** The BLS verify core with `std`, but without the JNI shim and without the `jni` crate
- **C.** The JNI shim only
- **D.** Both `jni` and `std`, because defaults cannot be disabled

[Answer →](answers.md#a-ws-q2)

<a id="q-ws-q3"></a>

**Q3** · Multiple choice

Why can't `roost` simply be a workspace member with its own `panic = "unwind"`?

- **A.** Binaries may not set panic strategies
- **B.** Cargo ignores `[profile.*]` in member crates; only the workspace root's profile applies, and that one says `abort`
- **C.** `unwind` is only available on Linux
- **D.** Because `roost` uses `anyhow`

[Answer →](answers.md#a-ws-q3)

<a id="q-ws-q4"></a>

**Q4** · Multiple choice

`myotis-net` lists itself under `[dev-dependencies]` as `myotis-net = { path = ".", features = ["fixture-recorder"] }`. What is the effect?

- **A.** A build error: a crate cannot depend on itself
- **B.** The feature is on for the crate's tests and examples, and off in the library that the engine links
- **C.** The feature is on everywhere, because features are additive
- **D.** It makes `cargo publish` include the examples

[Answer →](answers.md#a-ws-q4)

<a id="q-ws-q5"></a>

**Q5** · Written answer

Trace what happens, from the Gradle flag to the source code, when the desktop host library is built with Tor support.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-ws-q5)

<a id="q-ws-q6"></a>

**Q6** · Multiple choice

What does `.cargo/config.toml` change, and for whom?

- **A.** It sets the release version for every crate
- **B.** It adds a 16 KB page-alignment linker flag for the Android targets and an `aes_force_soft` cfg for the bare-metal targets, and nothing for host builds
- **C.** It enables the `tor` feature everywhere
- **D.** It pins the Rust compiler version

[Answer →](answers.md#a-ws-q6)

<a id="q-ws-q7"></a>

**Q7** · Multiple choice

`myotis-wire` has `std = ["myotis-core/std", "myotis-consensus?/std", ...]`. What does the `?` do?

- **A.** It makes the whole `std` feature optional
- **B.** It enables `std` on `myotis-consensus` only if that optional dependency is already enabled by something else, such as the `eth2` feature
- **C.** It marks the dependency as deprecated
- **D.** It tells cargo to ignore errors in `myotis-consensus`

[Answer →](answers.md#a-ws-q7)

<a id="q-ws-q8"></a>

**Q8** · Written answer

`myotis-core` promises to build without the standard library. Name the manifest techniques that keep the promise, and explain how the project tests it.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-ws-q8)

<a id="q-ws-q9"></a>

**Q9** · Multiple choice

Why does `myotis-rpcd` not depend on tokio, even though it serves HTTP?

- **A.** tokio does not support HTTP
- **B.** The engine owns its own tokio runtime and every read it offers blocks, so the daemon uses a blocking HTTP server with a fixed worker pool
- **C.** tokio is forbidden under `panic = "abort"`
- **D.** It gets tokio through clap

[Answer →](answers.md#a-ws-q9)

<a id="q-ws-q10"></a>

**Q10** · Written answer

The root manifest sets `panic = "abort"`. Explain why that is the right rule for the engine and for `myotis-rpcd`, and what `roost`'s `panic = "unwind"` does and does not buy it.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-ws-q10)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
