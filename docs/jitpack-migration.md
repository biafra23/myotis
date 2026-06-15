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
| `com.github.biafra23.tuweni-kotlin:*` | `2.7.2-jvm17.1` | `submodules/tuweni-kotlin` | Gradle (multi-module) | **Yes** | ✅ Migrated (composite + version constraints) |
| `com.github.biafra23.besu:*` | `24.12.2-android.2` | `submodules/besu` | Gradle (huge) | **Yes** | ✅ Migrated (composite, build-wide) |

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

## JitPack still required (but no longer for the forks)

All four library **forks** are now off JitPack (tuweni + besu are composite
builds, netty is a Pages repo, trueblocks is a composite build). But
`settings.gradle.kts` still keeps the JitPack repository (ordered last) because
two classes of **non-fork** dependency publish only there:

1. **`com.github.multiformats:java-multibase`** — a *runtime* transitive of
   `io.libp2p:jvm-libp2p` (used by `:consensus`). Not on Maven Central. This is
   the dependency that makes JitPack unremovable from the main build today;
   removing the repo breaks `:consensus:testRuntimeClasspath`.
2. **trueblocks-kotlin's own transitive `com.github.*` deps** (komputing
   kethereum/khex, `biafra23:ipfs-api-kotlin` → multiformats), resolved inside
   the trueblocks composite via the submodule's own repo list.

So the migration removed JitPack as a build dependency *for our forks* — the
remaining usage is third-party libraries that are themselves JitPack-only.

(netty-kotlin no longer needs JitPack — it's now consumed from a GitHub Pages
Maven repo; see below.)

## The other three forks

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

### tuweni-kotlin — composite build + version constraints (migrated)

The fork sources **every dependency version** from the
`io.spring.dependency-management` plugin (applied to `allprojects`), which reads
`dependency-versions.gradle` (e.g. `io.vertx:vertx-core` → `4.5.11`). Module
scripts then declare deps **without versions** — `bytes/build.gradle` has
`api 'io.vertx:vertx-core'`, `crypto` has `implementation 'com.github.jnr:jnr-ffi'`,
and so on. That plugin injects the versions into **published POMs** (so JitPack
artifacts resolve fine), but a composite build consumes the **live project
metadata**, where the versions are absent — so a consumer first fails with:

```
Could not find io.vertx:vertx-core:.
  Required by: project :networking > project :tuweni-kotlin:bytes
```

**Fix:** supply those versions as dependency constraints in the main build (root
`build.gradle.kts` `subprojects` for the JVM modules, and `android-app`), taken
from the fork's `dependency-versions.gradle` — the same versions JitPack's POMs
baked in, all resolvable from Maven Central:

```
io.vertx:vertx-core:4.5.11            org.connid:framework:1.3.2
com.github.jnr:jnr-ffi:2.2.14         org.connid:framework-internal:1.3.2
org.bouncycastle:bcprov-jdk15on:1.70  commons-codec:commons-codec:1.16.0
com.google.guava:guava:32.1.2-jre
```

**Second gotcha:** the composite declares `crypto → units` as `implementation`
(runtime-only), whereas JitPack's custom POM exposed it at *compile* scope — so
modules that touch `UInt64`/`UInt256` through tuweni APIs (networking, consensus,
app, android-app) must declare `tuweni-units` directly. Only
`tuweni-{bytes,crypto,rlp,units}` are consumed; their internal siblings (e.g.
`:io`) resolve inside the included build.

```kotlin
includeBuild("submodules/tuweni-kotlin") {
    dependencySubstitution {
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-bytes")).using(project(":bytes"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-crypto")).using(project(":crypto"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-rlp")).using(project(":rlp"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-units")).using(project(":units"))
    }
}
```

### besu — composite build, build-wide (migrated)

Besu's `:evm` builds fine from source (`./gradlew :evm:jar` ≈ 90 s; the version is
pinned to `24.12.2` in `gradle.properties`, overriding git-versioning). The only
real question was scoping. The fork used to be swapped in **only for
`:android-app`** (JVM daemon on upstream Besu) via a config-level substitution
`org.hyperledger.besu:* → com.github.biafra23.besu:*`. A *scoped* composite turned
out impossible: that config-level substitution's output is **not** re-fed through
the includeBuild substitution, so android-app kept resolving the JitPack module
(verified via `dependencyInsight`). The wiring that works is **build-wide**:

```kotlin
includeBuild("submodules/besu") {
    dependencySubstitution {
        substitute(module("org.hyperledger.besu:evm")).using(project(":evm"))
        substitute(module("org.hyperledger.besu:besu-datatypes")).using(project(":datatypes"))
        substitute(module("org.hyperledger.besu.internal:algorithms")).using(project(":crypto:algorithms"))
        substitute(module("org.hyperledger.besu.internal:rlp")).using(project(":ethereum:rlp"))
        substitute(module("org.hyperledger.besu:bom")).using(project(":platform"))
    }
}
```

Explicit substitutions are required because Besu's publication coordinates don't
match its project names (e.g. project `:datatypes` publishes as `besu-datatypes`),
so auto-substitution doesn't fire. Build-wide moves the **JVM daemon** onto the
fork too — acceptable because the patches are JVM-safe (API-1 `Provider` ctor;
`LinkedHashMap` `CodeCache` instead of Caffeine) and the composite produces
classes identical to the old JitPack fork (same source commit), so android-app's
D8 path is unchanged. The per-module substitution in `android-app/build.gradle.kts`
was removed; the `io.tmio` exclude and Guava jre-variant resolution stay. Verified:
`:myotis-evm`/`:app`/`:android-app` all resolve `org.hyperledger.besu:evm ->
project :besu:evm`, and a clean `build` of all JVM modules (with tests) is green.
The android APK is verified by CI (no Android SDK in this sandbox).

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
