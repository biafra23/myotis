# The engine library: `eth.myotis:myotis-engine`

Myotis as a library for other apps: the Rust light-client engine behind the
`io.myotis.api` contract, packaged for Android (an AAR) and the desktop JVM (a
jar), with no UI, no Java engine and no JSON-RPC server inside. A wallet built on
it runs the engine in-process and reads the chain through
`ChainHandle.reads()` — every answer verified against the sync committee, as
in the Myotis apps (README §Trust model).

Module: `:myotis-engine` (Kotlin Multiplatform, `jvm` + `android` targets). Entry
point: `io.myotis.engine.Myotis`. For iOS, `:myotis-engine-ios` (see *iOS*). Part of the `feature/android-aar` plan; this
page describes what a consumer gets today.

## Coordinates and where to get them

| artifact | what |
|---|---|
| `eth.myotis:myotis-engine:<version>` | the root: Gradle module metadata that picks `-android` for an Android consumer and `-jvm` for a desktop one |
| `eth.myotis:myotis-engine-android:<version>` | the AAR: the Kotlin entry point, `libmyotis_engine.so` + `libmyotis_bls.so` for `arm64-v8a` and `x86_64`, JNA's `libjnidispatch.so` beside them |
| `eth.myotis:myotis-engine-jvm:<version>` | the desktop jar (the host library is not inside it — see *Desktop* below) |
| `eth.myotis:myotis-engine-natives-<platform>:<version>` | the host library for one desktop platform (`darwin-aarch64`, `darwin-x86-64`, `linux-x86-64`, `linux-aarch64`): `<platform>/libmyotis_engine.{dylib,so}` in a plain jar, where JNA finds it on the classpath — see *Desktop* |
| `eth.myotis:myotis-engine-ios:<version>` | the engine for a Kotlin/Native iOS consumer (`iosArm64`, `iosSimulatorArm64`): the typed API (`Myotis.newEngine()`, the `io.myotis.api` names) over the C ABI's cinterop bindings and `io.myotis.engine.ios.RustEngine`, `libmyotis_engine.a` inside — see *iOS* |
| `eth.myotis:myotis-api` | the contract (`MyotisEngine`, `ChainHandle`, `VerifiedReads`, the ports) — one of the AAR's two `api` dependencies, so it is on the consumer's compile classpath |
| `eth.myotis:myotis-engine-ports` | the default port actuals (`io.myotis.engine.ports`: the node-key file, the file-backed peer caches, the CCIP-Read gateway, the per-network file layout) — the AAR's second `api` dependency, see *Using it* |
| `eth.myotis:myotis-engine-rust`, `myotis-engine-common`, `myotis-rpc-policy` | implementation dependencies the POMs pull in; a consumer never names them. Nothing from the Java engine, and no Tuweni or BouncyCastle: the engine library's whole third-party graph is JNA, slf4j and minimal-json |

`<version>` is the tag's: `v0.1.16` publishes `0.1.16`, a release-candidate
or hotfix tag `v0.1.16-rc1` publishes `0.1.16-rc1`. Everything else the graph
needs (JNA, slf4j, minimal-json, the Kotlin stdlib) comes from Maven
Central. The group is `eth.myotis` — `myotis.eth`, the project's ENS name, is
the one namespace the owner controls (the Java packages stay `io.myotis.*`; a
package prefix is not a claim on a domain). Maven Central would not accept it:
Central verifies a namespace through DNS, which an ENS name has none of, so a
Central publication some day would carry another group, such as
`io.github.biafra23` — none of the three channels below verifies anything.

**The `maven-repo` branch — no token.** Every `v*` tag merges the set into the
[`maven-repo`](https://github.com/biafra23/myotis/tree/maven-repo) branch, a
plain Maven repository layout that raw.githubusercontent.com serves file by
file, which is all Gradle needs:

```kotlin
// settings.gradle.kts of the consumer
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://raw.githubusercontent.com/biafra23/myotis/maven-repo")
            content { includeGroup("eth.myotis") }
        }
    }
}
```

```kotlin
// build.gradle.kts of the consumer's Android module
dependencies {
    implementation("eth.myotis:myotis-engine:0.1.16")
}
```

Versions accumulate on the branch and the per-artifact `maven-metadata.xml` is
merged on each publish, so dynamic versions (`0.1.+`) see them all. The branch
is written by the workflow only; a manual edit would be overwritten.

**GitHub Packages.** The same set goes to this repository's Maven registry.
GitHub requires a token with `read:packages` to read it, even for a public
repository — a classic personal access token of the developer, or
`GITHUB_TOKEN` in Actions:

```kotlin
// settings.gradle.kts of the consumer
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            name = "MyotisGitHubPackages"
            url = uri("https://maven.pkg.github.com/biafra23/myotis")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GITHUB_ACTOR")).orNull
                password = providers.gradleProperty("gpr.token").orElse(providers.environmentVariable("GITHUB_TOKEN")).orNull
            }
            content { includeGroup("eth.myotis") }
        }
    }
}
```

**The release's Maven repository zip.** The release page of each tag carries
`myotis-engine-<tag>-maven-repo.zip`: the same artifacts as a ready-made local
Maven repository (`eth/myotis/...`), for a build that reaches neither GitHub
host. Unzip it and point Gradle at the directory:

```kotlin
maven {
    url = uri("/path/to/myotis-engine-v0.1.16-maven-repo")   // contains eth/myotis/...
    content { includeGroup("eth.myotis") }
}
```

The bare `myotis-engine-<tag>-android.aar` is on the release page too, for
inspection or for a build system that takes an AAR file directly — remember
that its dependencies then have to come from one of the repositories
above. Verify downloads against `myotis-engine.SHA256SUMS`.

**From a working tree.** `./gradlew publishToMavenLocal` publishes
`0.1.X-SNAPSHOT` of the set into `~/.m2` (add `mavenLocal()` to the consumer).
The AAR needs the Android Rust toolchain (CLAUDE.md §Build & Run); without it,
`-PskipRustEngine` publishes an AAR with no engine inside, good for compiling a
consumer and for nothing else.

## What the AAR is

- **minSdk 29**, Java 17 class files, `compileSdk 35`. ABIs: `arm64-v8a` and
  `x86_64` (the emulator); an app that ships other ABIs gets no engine there.
- **The Rust engine only.** The Myotis app itself can still fall back to the
  Java engine on API 33+; the library has no Java engine, so a device the Rust
  engine cannot load on has no engine at all. `Myotis.isAvailable()` says
  whether it loaded.
- **No listener.** Nothing binds a port. `ChainHandle.reads()` answers
  in-process once the handle is started; `rpcPort` in the status snapshot stays
  0 and `setWebAccessPolicy` only normalizes and returns the policy — nothing stores
  or judges it, and `recentWebOrigins()` stays empty.
- **JNA is pinned.** The AAR carries `libjnidispatch.so` of one JNA version and
  its POM pins `net.java.dev.jna:jna` to that version with a *strict*
  constraint (Gradle: `strictly`). A graph that wants another JNA fails at
  resolution, which is the intended outcome: JNA refuses a jar/native version
  mismatch at class-load time, on every device. Do not force another version.
- **Size.** Two ABIs of the engine plus BLS; the AAR is tens of megabytes,
  and the app's split-per-ABI or App Bundle delivery keeps one ABI per device.

## Using it

```kotlin
import io.myotis.api.EngineConfig
import io.myotis.engine.Myotis

check(Myotis.isAvailable()) { "no Rust engine on this device" }
val engine = Myotis.newEngine()           // one per process
val dataDir = context.filesDir.resolve("myotis").toPath()   // engine-owned private state
// The library's default ports for this network: the node key and the peer caches
// under dataDir, the CCIP-Read gateway, and the DNS servers a mobile host must
// supply (ConnectivityManager's, for EIP-1459 resolution; null on a desktop).
val defaults = Myotis.defaultPorts(engine, dataDir, dataDir, "mainnet") { activeNetworkDnsServers() }
val config = EngineConfig(
    "mainnet",                            // or "gnosis", "sepolia": engine.availableNetworks()
    0, 0, 0,                              // EL port, discv5 port, rpcPort: the network's defaults
                                          // (rpcPort is unused here — nothing listens)
    defaults.syncSnapshot().toString(),   // light-client snapshot: a cache, not a trust anchor
    3,                                    // snap-peer maintainer target (keep it on behind NAT / on mobile)
    true,                                 // strict state freshness
    dataDir.toString(),
)
val handle = engine.create(config, defaults.ports())
handle.start()
// later, once handle.beaconStatus() reports SYNCED:
val reads = handle.reads()                 // null until started
val balanceWei = reads.getBalance(address20, "latest")
val result = reads.call(from, to, calldata, "0", "latest")
```

`EnginePorts` is what the host supplies (`io.myotis.api.ports`): the node-key
store, the EL and CL peer caches, DNS servers, the HTTP gateway (CCIP-Read),
the logger and a monotonic clock. `Myotis.defaultPorts` fills them from
`io.myotis.engine.ports` (`DefaultEnginePorts.forNetwork` in Java): the key
file under the first directory, the file-backed caches under the second, the
`HttpURLConnection` gateway, the engine's own logger and clock. The Rust engine
reads the DNS servers and the gateway from these ports and keeps its peer
caches and sync snapshot itself under `EngineConfig.dataDir` — in the same
file names (`NetworkFiles`), which is why the sketch passes one directory for
both; its node identity is ephemeral per run (the key file serves the Java
engine, which the Myotis apps run through their engine selector). What a host
still supplies itself: the DNS servers on mobile (Android has no system resolver
configuration the engine could read), and its lifecycle handling (the Android
app's foreground service, pause on background and wake on request are the
app's, not the library's).

The contract is Java 17 and FFI-flat (byte arrays, strings, longs, flat records,
blocking calls); `docs/reimplementation/05-engine-api-bindings.md` documents it.
Log lines from the engine come out of `Myotis.drainLogs(max)`; Tor routing of
account reads is `Myotis.Tor` (only a build with `-PtorEngine` supports it —
docs/privacy-and-tor.md).

## Desktop

`eth.myotis:myotis-engine-jvm` is the same entry point for a JVM host. The jar
does not contain the host library, which is built per OS and architecture;
`eth.myotis:myotis-engine-natives-<platform>` carries it, one artifact per
platform in `myotis-engine-natives/platforms.txt`. Put the one for the host on
the runtime classpath, at the same version as the engine:

```kotlin
dependencies {
    implementation("eth.myotis:myotis-engine:0.1.16")
    runtimeOnly("eth.myotis:myotis-engine-natives-darwin-aarch64:0.1.16") // the host's platform
}
```

JNA then loads `libmyotis_engine` from the jar's `<platform>/` entry (it
extracts it to a temporary file first) whenever `jna.library.path` has none,
so nothing has to be set; a library found on that path, or named by
`-Dmyotis.engine.lib=<file>`, still wins, which is how a development build is
tried. Keep both artifacts on one version (one catalog entry): a library whose FFI
differs from the bindings is refused at load (the ABI version and UniFFI's
checksums), and `Myotis.isAvailable()` says false, but a library from another
release with the same FFI loads and runs that release's engine, its checkpoints
and bootnodes included, with nothing to say so. The artifacts are
built on one runner per platform from the tag's tree: macOS 14 for both Mac
architectures, Ubuntu 22.04 for Linux (so glibc 2.35 or newer). A signed and
notarized macOS app with the hardened runtime may refuse a library extracted
at run time; such an app ships the library inside its bundle, signed with it,
as the Myotis desktop app does (`appResources`), and points
`jna.library.path` there. Windows has no artifact yet.

Building the host library yourself: `./gradlew cargoBuildHost` (or
`cargo build --release --workspace` in `rust/`) and `-Djava.library.path=`
`rust/target/release`; `./gradlew :myotis-engine-natives:publishToMavenLocal`
publishes it as this host's natives artifact.

## iOS

`eth.myotis:myotis-engine-ios` is the engine for a Kotlin Multiplatform app with
iOS targets. The `io.myotis.api` contract is Java, which Kotlin/Native cannot
run, so the module carries its Kotlin twin over the Rust engine's plain C ABI
(`rust/include/myotis_engine.h`), in two layers:

- **The typed API**, `Myotis.newEngine()` → `MyotisEngine` → `ChainHandle`, with
  `VerifiedReads` and `EnsApi` from the handle. The names and meanings are
  `io.myotis.api`'s, for the part of it a wallet reads: the catalog, a handle's
  lifecycle and status, the account and storage proofs, `eth_call`, gas
  estimates, the nonce (with the pending overlay), fee history, receipts, sending
  and ENS forward resolution. It decodes the engine's JSON by the JVM side's rules,
  pinned by the same golden shapes (`EngineDecodingTest`): an error envelope fails
  the call, shape drift fails closed, and the permanent `-32602` refusal is a
  result, never the retryable failure.
- **`io.myotis.engine.ios.RustEngine`**, the bindings under it: every call returns
  the engine's JSON as a `String`, copies and frees the C string, and refuses to
  run against a library whose ABI version differs from the header it was built
  from. Myotis's own iOS app (`:app-ios`) reads the JSON itself at this layer.

The calls block (a verified read can take a minute and more), so keep them off
the main thread. Two differences from the JVM handle: a read on a paused or
starting handle is not held until the node can answer, it answers at once as
unavailable, so the host resumes the handle before reading; and there is no
CCIP-Read gateway, so a name that resolves off chain is an error result.

```kotlin
val engine = Myotis.newEngine()
val sepolia = engine.create(EngineConfig("sepolia", dataDir))
sepolia.start()
// … once sepolia.status().beaconState is SYNCED:
val account = sepolia.requestAccount("0x…")   // verifyMethod set = a verdict
```

```kotlin
kotlin {
    iosArm64()
    iosSimulatorArm64()
    sourceSets {
        iosMain.dependencies {
            implementation("eth.myotis:myotis-engine-ios:0.1.16")
        }
    }
}
```

Each target's cinterop klib carries `libmyotis_engine.a` for its triple
(`aarch64-apple-ios`, `aarch64-apple-ios-sim`), so the app's framework links the
engine with no extra linker flags and no Rust toolchain on the consumer's side.
There is no x86_64 simulator. Building it yourself needs a Mac with Xcode and
`rustup target add --toolchain stable aarch64-apple-ios aarch64-apple-ios-sim`:
`./gradlew :myotis-engine-ios:publishToMavenLocal`. Anywhere else the module
disables itself.

## How it is published

`.github/workflows/engine-library.yml`. On every push to `main` that can
change the publication it stages the set into a local Maven repository
(`./gradlew -PpublishRelease publishAllPublicationsToStagingRepository` →
`build/maven-repo`; the flag drops `-SNAPSHOT`, so what is staged is laid out
as a release) and checks it with `scripts/check_engine_library.sh`: every
artifact present at one version, the AAR complete for every shipped ABI, the
JNA pin in both halves' POM and module metadata, a natives jar of the right
architecture for every platform (built first, one runner per platform), the
iOS module with the engine's archive in each target's cinterop klib (staged on
a macOS runner and merged in), and that the engine loads from the Linux x64
one with no library path. On a `v*` tag — after the
release version guard — the same build is checked again, published to GitHub
Packages, merged into the `maven-repo` branch (`scripts/merge_maven_repo.py`)
and attached to the release. A GitHub Packages version cannot be
overwritten: a republish of a tag needs the package versions deleted first.
The modules and their coordinates are defined once, in the `Publishing`
section of the root `build.gradle.kts`.
