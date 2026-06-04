<!-- Paste this block at the TOP of biafra23/besu's README.md, above Besu's own README. -->

# Android fork of Hyperledger Besu

This is a minimal fork of [Hyperledger Besu](https://github.com/hyperledger/besu)
that makes the **`evm`** module runnable on Android's ART runtime. It exists so
the [devp2p-playground / myotis](https://github.com/biafra23/myotis) wallet can
run the EVM **on-device** (ENS resolution and view calls over SNAP-verified
state) instead of trusting a remote RPC.

Based on Besu **24.12.2**. Two source changes only — both work around JDK/runtime
APIs that exist on a desktop JVM but are missing from Android's ART:

| Change | File | Why |
|---|---|---|
| **`BesuProvider`** ctor | `crypto/algorithms/.../crypto/BesuProvider.java` | Uses the API-1 `Provider(String, double, String)` ctor instead of the JDK-9 `(String, String, String)` overload, which is absent from the ART runtime **even on API 35/36** → keccak threw `NoSuchMethodError`. |
| **`CodeCache`** off Caffeine | `evm/.../evm/internal/CodeCache.java` | Backs the EVM bytecode cache with a `LinkedHashMap` LRU instead of Caffeine. Caffeine's `StripedBuffer` reflects into the JDK-internal `Thread.threadLocalRandomProbe` field (missing on Android) → `NoSuchFieldException` at `EVM.<init>`. Not fixable by a Caffeine version pin. (`CodeScale`, the Caffeine weigher, is now unused.) |

Both are behaviour-preserving for the wallet's workload; verified end-to-end
(`vitalik.eth` resolves on an API-35 emulator). Nothing else on the EVM path
needed patching.

### Building / publishing
Publish the two needed modules (JitPack builds them on tag push):
```yaml
# jitpack.yml
jdk:
  - openjdk21
install:
  - ./gradlew :evm:publishToMavenLocal :crypto:algorithms:publishToMavenLocal -x test -x spotlessCheck
```
Consumers use the JitPack coordinates `com.github.biafra23.besu:evm:<tag>` and
`com.github.biafra23.besu:algorithms:<tag>` (Android only — the JVM/desktop build
should stay on upstream Besu, where these APIs work).

### Maintenance
On every upstream Besu bump, re-apply both changes and re-audit for new
Android-runtime gaps (`System.Logger`, `Provider(String,String,String)`,
`Unsafe`/`Thread.threadLocalRandomProbe`, etc.).

---
<!-- end fork preamble — upstream Besu README follows -->
