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
| `com.github.biafra23.netty-kotlin:*` | `main-SNAPSHOT` | `submodules/netty-kotlin` | **Maven** | No (impossible) | ⛔ Stays on JitPack |
| `com.github.biafra23.tuweni-kotlin:*` | `2.7.2-jvm17.1` | `submodules/tuweni-kotlin` | Gradle (multi-module) | Not yet | ⚠️ Blocked — see below |
| `com.github.biafra23.besu:*` | `24.12.2-android.2` | `submodules/besu` | Gradle (huge) | Not yet | ⚠️ Blocked — see below |

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
Gradle build script for the fork. Options, none free:

- Keep it on JitPack (current state). JitPack handles the Maven build.
- `mvn install` the fork to a local/internal Maven repo in CI and consume from
  there — reintroduces a manual publish step (not a composite build).
- Add a Gradle build to the fork (large effort; it's all of Netty).

Note the fork already uses group `com.jaeckel` (not `io.netty`), which is what
lets the main build `exclude(group = "io.netty")` (killing the upstream Netty
that vertx/libp2p/discovery drag in) while keeping the fork's `io.netty.*`
classes. Any future approach must preserve that distinct group.

### tuweni-kotlin — group collides with the upstream it replaces

The fork's Gradle projects declare `group = "io.consensys.tuweni"` — the **same
group** the main build deliberately excludes from the discovery library
(`:networking`: `implementation(libs.discovery) { exclude(group =
"io.consensys.tuweni") }`). JitPack hid this by republishing the fork under
`com.github.biafra23.tuweni-kotlin`, giving it a coordinate distinct from
upstream `io.consensys.tuweni`. A composite build resolves to the fork's *native*
`io.consensys.tuweni:*` coordinates, which:

- re-collide with the upstream tuweni `:networking` is trying to exclude, and
- risk D8 duplicate-class failures the current setup carefully avoids.

A migration would need to either re-group the fork's published projects to a
distinct coordinate or rework the `io.consensys.tuweni` excludes. The fork's
build also needs `--add-exports jdk.compiler/...` and `-Xmx8g` (it compiles
against `javac` internals), so building it from source in CI is non-trivial.
Only `tuweni-{bytes,crypto,rlp,units}` are actually consumed.

### besu — composite `includeBuild` over-applies the Android-only patch

Today the Besu fork is swapped in **only for `:android-app`** via a scoped
`resolutionStrategy.dependencySubstitution` (the JVM daemon stays on upstream
Besu — the patches are Android-runtime-only; see `besu-android-fork/README.md`).
`includeBuild("submodules/besu")` auto-substitutes `org.hyperledger.besu:*`
across the **entire** build, which would push the Android-patched EVM onto the
JVM daemon too. Besu is also a ~50-module Gradle build (spotless / checkLicense /
git-versioning); JitPack only builds the `evm` + `crypto:algorithms` + `platform`
subset. A migration would need build-scoped substitution (not the global
auto-substitution) plus confidence the Besu build configures cleanly in CI.

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
