# Besu-for-Android fork patch set

Hyperledger Besu's `evm` module (and its `algorithms` crypto module) assume
JDK/runtime features that Android's ART runtime lacks. Running the EVM on
Android (for on-device ENS resolution / view calls in `:android-app`) needs
**two source patches**. They're currently applied *in-repo* via in-tree class
replacements + a `stripBesuProvider` Gradle artifact transform
(`android-app/build.gradle.kts`); this directory is the handoff for moving them
into a proper Besu fork so the in-repo hacks can be deleted.

**Status: verified.** With exactly these two patches, `vitalik.eth` resolves
end-to-end on an API-35 emulator (→ `0xd8dA…96045`, account read over SNAP).
No other Besu/dependency Android-runtime gap remains on the EVM path.

Besu version pinned: **24.12.2** (`gradle/libs.versions.toml` → `besu`).

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

## Building & publishing the fork

1. In the fork (**https://github.com/biafra23/besu**), branch off tag `24.12.2`
   (e.g. `24.12.2-android`). Prepend `FORK-README-PREAMBLE.md` to the fork's
   `README.md`.
2. Apply the patches:
   ```
   git apply /path/to/besu-android-fork/patches/0001-besuprovider.patch
   git apply /path/to/besu-android-fork/patches/0002-codecache.patch
   # (or copy the full reference files over the originals)
   ```
3. Publish. Two options:

   **a) JitPack** (matches the netty-kotlin / tuweni-kotlin / discovery fork pattern).
   Add `jitpack.yml` at the fork root pinning JDK 21 (Besu requires it):
   ```yaml
   jdk:
     - openjdk21
   install:
     - ./gradlew :evm:publishToMavenLocal :crypto:algorithms:publishToMavenLocal -x test -x spotlessCheck
   ```
   Tag and push; JitPack builds `com.github.biafra23.besu:evm:<tag>` and
   `com.github.biafra23.besu:algorithms:<tag>`.
   ⚠️ Besu is a large, build-heavy repo — JitPack's time/memory limits and
   Besu's full build (errorprone, spotless, integration setup) can make this
   flaky. Skipping tests/spotless (above) helps. If JitPack can't build it:

   **b) Local/private Maven** — `./gradlew :evm:publish :crypto:algorithms:publish`
   to a Maven repo the project can reach (or `publishToMavenLocal` + add
   `mavenLocal()` on the android-app branch only, as an interim).

---

## Wiring the consumer (when the fork is published)

The **JVM daemon** must stay on upstream Besu (the patches are Android-only;
on a desktop JVM the 3-String ctor and Caffeine both work). So scope the swap
to `:android-app` via dependency substitution — do **not** change
`gradle/libs.versions.toml` globally.

In `android-app/build.gradle.kts`, replace the in-tree mechanism with:
```kotlin
configurations.configureEach {
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.hyperledger.besu:evm"))
            .using(module("com.github.biafra23.besu:evm:<tag>"))
        substitute(module("org.hyperledger.besu.internal:algorithms"))
            .using(module("com.github.biafra23.besu:algorithms:<tag>"))
    }
}
```
(plus the JitPack repo in `settings.gradle.kts`, already present).

Then **delete the in-repo workarounds** (no longer needed):
- `android-app/src/main/java/org/hyperledger/besu/crypto/BesuProvider.java`
- `android-app/src/main/java/org/hyperledger/besu/evm/internal/CodeCache.java`
- the `StripBesuProvider` transform + its registration in `build.gradle.kts`
- the `compileOnly(libs.besu.evm/datatypes)` lines added for those patches
- the `resolutionStrategy.force("…caffeine:2.9.3")` (moot once CodeCache is patched)

Keep (these are independent of Besu source): the `io.tmio` exclude, the Guava
**jre-variant** capability resolution, and the Android CCIP gateway / SnapPeer
adapter / unified-input + history UI.

---

## Maintenance

Re-apply both patches on any Besu upgrade, and re-audit for new Android-runtime
gaps (scan dependency jars for `System$Logger`, `Provider(String,String,String)`,
`Unsafe`/`Thread.threadLocalRandomProbe`). See the `besu-on-android-compat-chain`
project memory for the full history.
