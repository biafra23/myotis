# Besu-for-Android fork patch set

Hyperledger Besu's `evm` module (and its `algorithms` crypto module) assume
JDK/runtime features that Android's ART runtime lacks. Running the EVM on
Android (for on-device ENS resolution / view calls in `:android-app`) needs
**two source patches**. This directory documents them.

**Status: DONE — fork published and consumed.** The patches live in
**[biafra23/besu](https://github.com/biafra23/besu)** (branch `24.12.2-android`,
tag **`24.12.2-android.2`**), published via JitPack, and `:android-app` consumes
them. `vitalik.eth` resolves end-to-end on an API-35 emulator against the fork
artifacts (→ `0xd8dA…96045`, 5.68 ETH, account read over SNAP). The earlier
in-tree class-replacement + strip-transform mechanism has been removed.

Besu base version: **24.12.2**. The fork is built with `version=24.12.2`
(gradle.properties) so its non-patched sibling refs resolve from Maven Central.

---

## The two patches

### 1. `BesuProvider` — JCA provider constructor
`patches/0001-besuprovider.patch` · full file: `BesuProvider.java`
Besu module: **`crypto/algorithms`** (artifact `org.hyperledger.besu.internal:algorithms`)
Path: `crypto/algorithms/src/main/java/org/hyperledger/besu/crypto/BesuProvider.java`

One line: `super(PROVIDER_NAME, "1.0", info)` → `super(PROVIDER_NAME, 1.0, info)`.
The 3-`String` `java.security.Provider(String,String,String)` ctor (JDK 9) is in
Android's compile stubs but **absent from the ART runtime even on API 35/36**,
so any Besu keccak (`MessageDigestFactory` → `new BesuProvider()`) throws
`NoSuchMethodError`. The API-1 `(String,double,String)` ctor is present on all
Android levels and behaviourally identical here.

### 2. `CodeCache` — EVM bytecode cache off Caffeine
`patches/0002-codecache.patch` · full file: `CodeCache.java`
Besu module: **`evm`** (artifact `org.hyperledger.besu:evm`)
Path: `evm/src/main/java/org/hyperledger/besu/evm/internal/CodeCache.java`

Replaces the Caffeine-backed cache with a `LinkedHashMap` LRU (same public API).
Caffeine's `StripedBuffer.<clinit>` reflects into the JDK-internal field
`java.lang.Thread.threadLocalRandomProbe` via `Unsafe` — **a field Android's
`Thread` does not have** — so building any Caffeine cache throws
`NoSuchFieldException` at `EVM.<init>`. This is fundamental to Caffeine on
Android (2.8.x and 2.9.x alike; **not** version-fixable). `CodeCache` + its
weigher `CodeScale` are the only Caffeine users in `:evm` on the EVM path;
after this patch nothing loads Caffeine, and **`CodeScale.java` is unused and
may be deleted** (or left — it's harmless if never loaded).

> Paths above are the Besu 24.12.2 repo layout; confirm against your fork
> checkout, as module locations occasionally shift between Besu releases.

---

## How the fork was built & published (as done)

1. Branched `biafra23/besu` off tag `24.12.2` → `24.12.2-android`; prepended
   `FORK-README-PREAMBLE.md` to its README; applied both patches
   (`patches/0001-besuprovider.patch`, `patches/0002-codecache.patch`).
2. Set **`version=24.12.2`** in `gradle.properties` — Besu's git-versioning
   otherwise stamps a `26.6-develop-<hash>` version into the published POMs'
   sibling refs, which isn't on Maven Central. Pinning to the released base
   makes the non-patched siblings (besu-datatypes, internal:rlp) resolve from
   Central, and avoids duplicate `org.hyperledger.besu.datatypes.*` classes
   downstream (we do NOT republish those modules).
3. Added `jitpack.yml` (JDK 21) publishing the two patched modules **plus
   `:platform`** (the `bom` they import via `<scope>import</scope>`, which Besu
   never publishes to Central — so the fork must provide a resolvable one):
   ```yaml
   jdk:
     - openjdk21
   install:
     - ./gradlew :evm:publishToMavenLocal :crypto:algorithms:publishToMavenLocal :platform:publishToMavenLocal -x test -x spotlessCheck -x spotlessApply -x checkLicense -x javadoc --no-daemon --stacktrace
   ```
4. Tagged **`24.12.2-android.2`** and pushed → JitPack built it (~50s) and
   published `com.github.biafra23.besu:{evm,algorithms,platform/bom}:24.12.2-android.2`.
   (JitPack's full Besu build is feasible thanks to building only this subset +
   skipping tests/spotless/docs.)

---

## How the consumer is wired (in `android-app/build.gradle.kts`)

The JVM daemon stays on upstream Besu (the patches are Android-only); the swap
is scoped to `:android-app` and does **not** touch `gradle/libs.versions.toml`.
Substitute the two patched modules + redirect the `bom` import (note
`platform(...)` on both sides — the bom is a Gradle java-platform, so a plain
module substitution mismatches variants):

```kotlin
val besuForkVersion = "24.12.2-android.2"
configurations.all {                       // eager, so AGP classpaths see it
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.hyperledger.besu:evm"))
            .using(module("com.github.biafra23.besu:evm:$besuForkVersion"))
        substitute(module("org.hyperledger.besu.internal:algorithms"))
            .using(module("com.github.biafra23.besu:algorithms:$besuForkVersion"))
        substitute(platform(module("org.hyperledger.besu:bom")))
            .using(platform(module("com.github.biafra23.besu:bom:$besuForkVersion")))
    }
}
```
(JitPack repo is already in `settings.gradle.kts`.) The in-repo workarounds
(in-tree `BesuProvider`/`CodeCache`, the strip transform + its `compileOnly`
besu deps, the Caffeine pin) have been **removed**. Kept (independent of Besu
source): the `io.tmio` exclude and the Guava **jre-variant** capability
resolution.

To bump the fork later: push a new tag (e.g. `24.12.2-android.3`) and update
`besuForkVersion`.

Keep (these are independent of Besu source): the `io.tmio` exclude, the Guava
**jre-variant** capability resolution, and the Android CCIP gateway / SnapPeer
adapter / unified-input + history UI.

---

## Maintenance

Re-apply both patches on any Besu upgrade, and re-audit for new Android-runtime
gaps (scan dependency jars for `System$Logger`, `Provider(String,String,String)`,
`Unsafe`/`Thread.threadLocalRandomProbe`). See the `besu-on-android-compat-chain`
project memory for the full history.
