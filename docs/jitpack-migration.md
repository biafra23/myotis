# JitPack → git submodules + Gradle composite builds

Goal: stop depending on JitPack *building* our library forks on demand (a
recurring source of slow/flaky/non-reproducible builds) by vendoring the fork
**sources** as git submodules under `submodules/` and wiring them as Gradle
[composite builds](https://docs.gradle.org/current/userguide/composite_builds.html)
(`includeBuild` + `dependencySubstitution`).

## Status

| Fork (JitPack coordinates) | Pinned version | Submodule | Build system | Composite build | Status |
|---|---|---|---|---|---|
| `com.github.biafra23:trueblocks-kotlin` | `main-SNAPSHOT` | `submodules/trueblocks-kotlin` | Gradle (single-module) | **Yes** | ✅ Migrated & verified |
| `com.jaeckel:netty-*` (ex `com.github.biafra23.netty-kotlin:*`) | `1.0-SNAPSHOT` | `submodules/netty-kotlin` | **Maven** | n/a (Maven) | ✅ Off JitPack — GitHub Pages Maven repo |
| `com.github.biafra23.tuweni-kotlin:*` | `2.7.2-jvm17.1` | `submodules/tuweni-kotlin` | Gradle (multi-module) | No (incompatible) | ⛔ Stays on JitPack — see below |
| `com.github.biafra23.besu:*` | `24.12.2-android.2` | `submodules/besu` | Gradle (huge) | No (not cleanly) | ⛔ Stays on JitPack — see below |

All four sources are pinned as submodules regardless of composite-build status —
that alone makes the fork inputs reproducible (a fixed commit instead of a
JitPack-rebuilt `-SNAPSHOT`) and keeps the source one `git submodule update`
away. The submodule commits are pinned to the exact refs the build consumed:

- `trueblocks-kotlin` → `main` @ `d2223849`
- `netty-kotlin` → `main` @ `bb32e27a`
- `tuweni-kotlin` → `kotlin-conversion` @ `fc19beda` (tag `2.7.2-jvm17.1`)
- `besu` → `24.12.2-android` @ `92489ca6` (tag `24.12.2-android.2`)

## Migrated: trueblocks-kotlin

Wired in `settings.gradle.kts`:

```kotlin
includeBuild("submodules/trueblocks-kotlin") {
    dependencySubstitution {
        substitute(module("com.github.biafra23:trueblocks-kotlin"))
            .using(project(":"))
    }
}
```

Verified: `./gradlew :app:dependencyInsight --configuration runtimeClasspath
--dependency com.github.biafra23:trueblocks-kotlin` resolves to
`project :trueblocks-kotlin (by composite build)`, and `./gradlew :app:compileJava`
builds the fork from source and links `:app` against it.

Caveat: trueblocks-kotlin *itself* pulls `com.github.biafra23:ipfs-api-kotlin`
and `com.github.komputing.*` transitively, so the **JitPack repository is still
required** to resolve those — we removed the JitPack *build* of trueblocks, not
JitPack entirely.

## Why JitPack can't be removed yet

`settings.gradle.kts` keeps the JitPack repository (de-duplicated to a single
entry, ordered last) because it is still needed for:

1. **tuweni-kotlin** and **besu** — see below; neither can be a clean composite
   build, so both still resolve from JitPack.
2. **trueblocks-kotlin's transitive `com.github.*` deps** (ipfs-api-kotlin,
   komputing kethereum/khex).

(netty-kotlin no longer needs JitPack — it's now consumed from a GitHub Pages
Maven repo; see below.)

## The other three forks (not composite builds)

### netty-kotlin — Maven; now consumed from a GitHub Pages Maven repo (off JitPack)

`submodules/netty-kotlin` is the upstream Netty tree converted to Kotlin and
**built with Maven** (`pom.xml`, group `com.jaeckel`). Gradle's `includeBuild`
only consumes *Gradle* builds, so a composite build is impossible — but netty is
now **off JitPack anyway**: the maintainer published the fork to a static Maven
repository on GitHub Pages, and the main build consumes it as a plain Maven
dependency.

Wired:
- `settings.gradle.kts` repositories: `maven { url = uri("https://biafra23.github.io/netty-kotlin/") }`
- `gradle/libs.versions.toml`: `com.github.biafra23.netty-kotlin:netty-{transport,codec,handler}:main-SNAPSHOT`
  → `com.jaeckel:netty-{transport,codec,handler}:1.0-SNAPSHOT`

The Pages repo serves unique-timestamped snapshots (e.g. `1.0-20260615.192006-1`)
with the parent POM and full transitive closure (common / buffer / resolver /
transport-native-unix-common / codec-base) published, so Gradle resolves it
normally. Verified: `./gradlew clean :app:compileJava` recompiles the whole JVM
stack (networking / consensus / app) against `com.jaeckel:*`.

The coords are `com.jaeckel:*` (not `io.netty`) — the same distinct group the
JitPack fork used — so the project-wide `exclude(group = "io.netty")` still
strips the upstream Netty that vertx/libp2p/discovery drag in while keeping this
fork, and the transitive shape matches the old fork, so the swap is
behaviour-preserving.

(Earlier probe, kept for history: a local subset `mvn install`
`-pl transport,codec,handler -am` fails — intra-reactor modules need
`tests`-classified jars a partial reactor doesn't produce, and the fork uses
`kotlin-maven-plugin` 2.1.10, i.e. a full reactor build, not a quick subset. The
GitHub Pages publish sidesteps this entirely.)

### tuweni-kotlin — central version management doesn't survive composite builds

The fork sources **every dependency version** from the
`io.spring.dependency-management` plugin (applied to `allprojects`), which reads
`dependency-versions.gradle` (e.g. `io.vertx:vertx-core` → `4.5.11`). Module
scripts then declare deps **without versions** — `bytes/build.gradle` has
`api 'io.vertx:vertx-core'`, `crypto` has `implementation 'com.github.jnr:jnr-ffi'`,
and so on.

That plugin injects the versions into **published POMs** (so JitPack-built
artifacts resolve fine), but a composite build consumes the **live project
metadata**, where the versions are absent — so a consumer fails at resolution:

```
Could not find io.vertx:vertx-core:.
  Required by: project :networking > project :tuweni-kotlin:bytes
```

(verified). It's systemic — bytes/crypto/rlp/units all reach version-less
transitives. Pinning each leaked version in the main build would be a brittle
mirror of the fork's BOM, defeating the stability goal. The clean fix lives in
the fork: give deps explicit versions, or publish Gradle Module Metadata that
carries the managed versions. Only `tuweni-{bytes,crypto,rlp,units}` are consumed.

### besu — no clean *scoped* composite

Besu's `:evm` **builds fine from source here** (`./gradlew :evm:jar` ≈ 90 s; the
version is pinned to `24.12.2` in `gradle.properties`, overriding git-versioning),
so the build itself isn't the blocker — scoping is. Today the fork is swapped in
**only for `:android-app`** (the JVM daemon stays on upstream Besu — the patches
are Android-runtime-only; see `besu-android-fork/README.md`) via a config-level
substitution `org.hyperledger.besu:* → com.github.biafra23.besu:*`. Two composite
wirings were tested:

1. **Scoped** — `includeBuild` mapping only the fork coords
   `com.github.biafra23.besu:* → project(...)`. Declaring explicit substitutions
   *does* disable includeBuild's build-wide auto-substitution (verified:
   `:myotis-evm` keeps `org.hyperledger.besu:evm:24.12.2`). **But** android-app's
   config-level substitution output (`com.github.biafra23.besu:evm`) is **not**
   re-fed through the includeBuild substitution, so android-app keeps resolving
   the **JitPack module** (verified via `dependencyInsight`:
   `org.hyperledger.besu:evm:24.12.2 -> com.github.biafra23.besu:evm:24.12.2-android.2`).
   The composite is a no-op for the one module that needs it.
2. **Build-wide** — substituting `org.hyperledger.besu:* → project` directly.
   This works, but also moves the **JVM daemon** onto the Android-patched fork
   (CodeCache without Caffeine; contradicts the documented design), and its
   Android/D8 effect can't be verified without the Android SDK (absent here).

Besu is **tag-pinned** on JitPack (`24.12.2-android.2`), not a flaky `-SNAPSHOT`,
so the payoff is low and the risk to the tuned dexing is real. It stays on
JitPack. A future clean migration would either accept build-wide substitution
(JVM daemon on the fork, after Android verification) or add a build seam letting
android-app point at the included project directly.

## CI

`actions/checkout` uses `submodules: recursive` in all workflows (required — an
un-checked-out submodule makes `includeBuild` fail), and caching is via the
official `gradle/actions/setup-gradle@v4` action.

## Working with the submodules

```bash
# Fresh clone:
git clone --recurse-submodules <repo>
# Existing clone after pulling this change:
git submodule update --init --recursive
```
