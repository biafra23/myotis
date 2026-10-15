# The engine library: `io.myotis:myotis-engine`

Myotis as a library for other apps: the Rust light-client engine behind the
`io.myotis.api` contract, packaged for Android (an AAR) and the desktop JVM (a
jar), with no UI, no Java engine and no JSON-RPC server inside. A wallet built on
it runs the engine in-process and reads the chain through
`ChainHandle.reads()` — every answer verified against the sync committee, as
in the Myotis apps (README §Trust model).

Module: `:myotis-engine` (Kotlin Multiplatform, `jvm` + `android` targets). Entry
point: `io.myotis.engine.Myotis`. Part of the `feature/android-aar` plan; this
page describes what a consumer gets today.

## Coordinates and where to get them

| artifact | what |
|---|---|
| `io.myotis:myotis-engine:<version>` | the root: Gradle module metadata that picks `-android` for an Android consumer and `-jvm` for a desktop one |
| `io.myotis:myotis-engine-android:<version>` | the AAR: the Kotlin entry point, `libmyotis_engine.so` + `libmyotis_bls.so` for `arm64-v8a` and `x86_64`, JNA's `libjnidispatch.so` beside them |
| `io.myotis:myotis-engine-jvm:<version>` | the desktop jar (the host library is not inside it — see *Desktop* below) |
| `io.myotis:myotis-api` | the contract (`MyotisEngine`, `ChainHandle`, `VerifiedReads`, the ports) — the AAR's one `api` dependency, so it is on the consumer's compile classpath |
| `io.myotis:myotis-engine-rust`, `myotis-engine-common`, `myotis-rpc-policy`, `myotis-core` | implementation dependencies the POMs pull in; a consumer never names them |

`<version>` is the release: `v0.1.16` publishes `0.1.16`. Everything else the
graph needs (JNA, slf4j, minimal-json, Tuweni, BouncyCastle) comes from Maven
Central.

**GitHub Packages.** Every `v*` tag publishes the set to this repository's
Maven registry. GitHub requires a token with `read:packages` to read it, even
for a public repository — a classic personal access token of the developer, or
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
            content { includeGroup("io.myotis") }
        }
    }
}
```

```kotlin
// build.gradle.kts of the consumer's Android module
dependencies {
    implementation("io.myotis:myotis-engine:0.1.16")
}
```

**Without a token: the release's Maven repository zip.** The release page of
each tag carries `myotis-engine-<tag>-maven-repo.zip`: the same artifacts as a
ready-made local Maven repository (`io/myotis/...`). Unzip it and point Gradle
at the directory instead of the GitHub Packages entry:

```kotlin
maven {
    url = uri("/path/to/myotis-engine-v0.1.16-maven-repo")   // contains io/myotis/...
    content { includeGroup("io.myotis") }
}
```

The bare `myotis-engine-<tag>-android.aar` is on the release page too, for
inspection or for a build system that takes an AAR file directly — remember
that its dependencies then have to come from one of the two repositories
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
  0 and `setWebAccessPolicy` only normalizes and stores the policy.
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
import io.myotis.api.ports.EnginePorts
import io.myotis.engine.Myotis

check(Myotis.isAvailable()) { "no Rust engine on this device" }
val engine = Myotis.newEngine()           // one per process
val dataDir = context.filesDir.resolve("myotis")   // engine-owned private state
val config = EngineConfig(
    "mainnet",                            // or "gnosis", "sepolia": engine.availableNetworks()
    0, 0, 0,                              // EL port, discv5 port, rpcPort: the network's defaults
                                          // (rpcPort is unused here — nothing listens)
    dataDir.resolve("sync-state.snapshot").path,   // light-client snapshot: a cache, not a trust anchor
    3,                                    // snap-peer maintainer target (keep it on behind NAT / on mobile)
    true,                                 // strict state freshness
    dataDir.path,
)
val handle = engine.create(config, ports)  // ports: see below
handle.start()
// later, once handle.beaconStatus() reports SYNCED:
val reads = handle.reads()                 // null until started
val balanceWei = reads.getBalance(address20, "latest")
val result = reads.call(from, to, calldata, "0", "latest")
```

`EnginePorts` is what the host supplies (`io.myotis.api.ports`): the node-key
store, the EL and CL peer caches, DNS servers, the HTTP gateway (CCIP-Read),
the logger and a monotonic clock. The library ships no defaults for them yet
(the next part of the plan does); until then the Myotis apps' actuals are the
reference — `android-app/.../NodeService.java` builds them for Android,
`app-desktop/.../DesktopNode.kt` for the desktop. The Android app's lifecycle
handling (foreground service, pause on background, wake on request) is the
app's, not the library's, for the same reason.

The contract is Java 17 and FFI-flat (byte arrays, strings, longs, flat records,
blocking calls); `docs/reimplementation/05-engine-api-bindings.md` documents it.
Log lines from the engine come out of `Myotis.drainLogs(max)`; Tor routing of
account reads is `Myotis.Tor` (only a build with `-PtorEngine` supports it —
docs/privacy-and-tor.md).

## Desktop

`io.myotis:myotis-engine-jvm` is the same entry point for a JVM host. The jar
does not contain the host library: JNA loads `libmyotis_engine.{so,dylib,dll}`
from `java.library.path`, built with `cargo build --release -p myotis-engine`
in `rust/` (the Myotis desktop app bundles it the same way). No release asset
carries the host libraries yet.

## How it is published

`.github/workflows/engine-library.yml`. On every push to `main` that can
change the publication it stages the set into a local Maven repository
(`./gradlew -PpublishRelease publishAllPublicationsToStagingRepository` →
`build/maven-repo`; the flag drops `-SNAPSHOT`, so what is staged is laid out
as a release) and checks it with `scripts/check_engine_library.sh`: every
artifact present at one version, the AAR complete for every shipped ABI, the
JNA pin in both halves' POM and module metadata. On a `v*` tag — after the
release version guard — the same build is checked again, published to GitHub
Packages and attached to the release. A GitHub Packages version cannot be
overwritten: a republish of a tag needs the package versions deleted first.
The modules and their coordinates are defined once, in the `Publishing`
section of the root `build.gradle.kts`.
