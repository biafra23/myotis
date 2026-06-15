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
| `com.github.biafra23.netty-kotlin:*` | `main-SNAPSHOT` | `submodules/netty-kotlin` | **Maven** | No (impossible) | ⛔ Maven — to be republished independently |
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

1. **netty-kotlin** — see below; it can't be a composite build.
2. **trueblocks-kotlin's transitive `com.github.*` deps** (ipfs-api-kotlin,
   komputing kethereum/khex).

## Blocked forks

### netty-kotlin — Maven, not Gradle (hard blocker)

`submodules/netty-kotlin` is the upstream Netty tree converted to Kotlin and
**built with Maven** (`pom.xml`, group `com.jaeckel`). Gradle's `includeBuild`
only consumes *Gradle* builds, so a composite build is impossible without a
Gradle build script for the fork.

**Decision:** the maintainer will republish netty-kotlin independently (its own
registry/coordinates); the main build keeps consuming it from JitPack until then.
The submodule stays pinned as source-of-record. A local `mvn install` was probed
and is *not* a drop-in: building a subset (`-pl transport,codec,handler -am`)
fails because intra-reactor modules depend on `tests`-classified jars
(`com.jaeckel:netty-transport:jar:tests`) that a partial reactor doesn't produce,
and the fork uses `kotlin-maven-plugin` (Kotlin 2.1.10) — a full reactor build,
not a quick subset.

Note the fork already uses group `com.jaeckel` (not `io.netty`), which is what
lets the main build `exclude(group = "io.netty")` (killing the upstream Netty
that vertx/libp2p/discovery drag in) while keeping the fork's `io.netty.*`
classes. Any future approach (independent republish included) must preserve that
distinct group.

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
