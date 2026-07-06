# BLS acceleration: native blst behind a `BlsBackend` seam

## Status: IMPLEMENTED on `prototype/bls-blst-acceleration` (desktop + Android)

The seam, the native Rust crate, the timing/compare mechanism, and the Android build are
all done and verified. Summary first; the original evaluation follows.

**What's wired**
- `BlsBackend` seam + `BlsBackends.active()` (selects via `-Dmyotis.bls.backend=auto|milagro|native|compare`),
  always wrapped in `TimingBlsBackend` (logs per-verify ms + running stats).
- `rust/myotis-bls` — a `blst` + `jni` cdylib; `NativeBlsBackend` calls it with the whole
  committee flattened into one JNI crossing. One crate → desktop `.so` **and** Android ABIs.
- Daemon: `./gradlew :app:run` puts the desktop `.so` on `java.library.path` and auto-selects
  native; `-Pbls=compare` runs the head-to-head.
- Android: `rust/build-android.sh` (cargo-ndk) builds `arm64-v8a` + `x86_64`
  `libmyotis_bls.so` into `android-app/src/main/jniLibs` (confirmed packaged in the debug
  APK); compare mode is an explicit opt-in (-Dmyotis.bls.backend=compare) — it was briefly the debuggable default, but 10-16 s of Milagro per update froze on-device catch-up (Pixel 7, 2026-07-06).

**Measured — `BlsBackendBenchmark`, real 511-pubkey mainnet aggregate, x86-64 desktop:**
| backend | cold (ms) | warm (ms/op) |
|---|---|---|
| Milagro (pure-Java) | 128.1 | 30.28 |
| jblst (blst SWIG) | 35.9 | 28.21 |
| **blst (native/rust)** | **8.2** | **7.54** |

**Measured — live Gnosis sync, daemon `compare` mode, real ~500-pubkey verifies:**
```
[bls-compare] pubkeys=503 Milagro=81.3ms native=8.1ms  speedup=10.0x agree=true
[bls-compare] pubkeys=500 Milagro=72.7ms native=8.5ms  speedup=8.5x  agree=true
[bls-compare] pubkeys=501 Milagro=50.0ms native=11.6ms speedup=4.3x  agree=true
```
Native is **4–15× faster and agrees on every real verify.** On Android/ART (Milagro cold =
30–55 s per the in-code comments) the win is far larger — measure it on-device via the
`[bls-compare]` logcat lines.

**To compare on your phone:** build `:android-app:assembleDebug` (the `.so` is already in
jniLibs / committed), install, and `adb logcat -s ComparingBlsBackend` while it syncs.
Rebuild the libs with `rust/build-android.sh` (needs `cargo-ndk` + `ANDROID_NDK_HOME`).

---



## Why
`BlsVerifier` (Milagro AMCL, pure Java) is the light client's heaviest regular
operation — a sync-committee `fastAggregateVerify` runs on every finality/optimistic
update and ×N during catch-up (512 pubkeys → G1 decompress + aggregate + hash-to-G2 +
pairing). The code already carries an elaborate apparatus to survive it on Android: a
decompressed-pubkey cache, a `warmPubkeyCache()` pre-pass, and a **bounded,
low-priority `ForkJoinPool`** that exists solely so a hot verify "can never occupy the
whole CPU" and trigger input-dispatch ANRs. That complexity is a symptom: Milagro is
too slow on ART.

Myotis actually *used* native blst (jblst) before commit `8acd8f1`, which swapped it
for Milagro "for Android portability" — i.e. jblst ships no Android natives. So the
desktop win is already proven; the missing piece is an **Android NDK-built blst**.

## The seam
`consensus/.../bls/BlsBackend` — `fastAggregateVerify(pubkeys, message, signature)`.
- `MilagroBlsBackend` (main) — delegates to the portable pure-Java `BlsVerifier`. Default.
- `JblstBlsBackend` (test, prototype) — Supranational blst via `tech.pegasys:jblst`.
- Future `AndroidBlstBackend` — NDK-built blst via JNI/UniFFI.

The host picks the fastest backend available; verification code is unchanged. blst,
libsecp256k1, etc. are *more* audited than Milagro/BouncyCastle (every major client
ships them), so this strengthens — not weakens — the trust story.

## Benchmark (this repo: `BlsBackendBenchmark`)
Real mainnet aggregate, 511 pubkeys (`resources/bls_real_failure.txt`). Both backends
agree on the result; only wall-clock differs.

**x86-64 desktop (HotSpot JIT):**
| regime | Milagro | jblst | ratio |
|---|---|---|---|
| **cold** (empty cache — committee rotation / fresh bootstrap) | 122 ms | 40 ms | **3×** |
| **warm** (Milagro pubkey-cache hot) | 27.7 ms | 27.2 ms | 1.0× |

### Reading the numbers honestly
- **Desktop understates the Android win.** Milagro is bignum-heavy pure Java; HotSpot
  JITs it well on x86-64, ART does not. The in-code comments cite **30–55 s** for a
  *cold* sync-aggregate verify on Android — vs 122 ms here. Native blst runs at
  near-these-desktop-native speeds on ARM too (it has aarch64 assembly), so the Android
  cold-verify speedup is ~**100–1000×**, not 3×. That is the real prize, and it's
  exactly the regime that causes the ANRs.
- **Warm "parity" still favors blst.** Milagro hits parity only via its pubkey cache +
  the bounded ForkJoinPool + `warmPubkeyCache()`. jblst matches it **with none of that**
  — adopting blst lets us *delete* the cache, the pool, and the warm-up machinery.
- **jblst has headroom here.** The prototype re-deserializes all 511 pubkeys across the
  JNI boundary on every call (no caching), while Milagro reads its hot cache — so the
  warm comparison is stacked *against* jblst. Caching the deserialized native
  `P1_Affine` points (or using blst's multi-point/`Pairing` aggregate API) would push
  jblst warm well below Milagro.

## Android: NDK-built blst (the actual work)
jblst = desktop JVM natives only. For Android, build blst for each ABI and load it via
JNI. Two routes:

**A. Compile blst's C directly with the NDK** (smallest dep surface)
- blst ships a portable `build.sh`/`blst.h` and Java SWIG bindings (`bindings/java`).
- Cross-compile `libblst.a` + the SWIG JNI shim per ABI with `cmake`/`ndk-build`
  (toolchains: `aarch64-linux-android`, `x86_64-linux-android`).
- Reuse jblst's generated `supranational.blst.*` Java classes (same SWIG output), so the
  `JblstBlsBackend` code is unchanged — only the `.so` differs per platform.

**B. Rust `blst` crate + UniFFI** (fits the Kotlin-Multiplatform direction)
- Thin Rust wrapper crate exposing `fast_aggregate_verify(pubkeys, msg, sig) -> bool`
  over the `blst` crate; generate Kotlin bindings + JNI glue with **UniFFI**.
- Cross-compile with **`cargo-ndk`**; wire into Gradle with Mozilla's
  **`rust-android-gradle`** plugin (drops `.so` into `jniLibs`/the AAR).
- Same wrapper builds a desktop `.so`/`.dylib`/`.dll` for the daemon — one Rust crate,
  both hosts — so jblst could be retired entirely in favor of the in-house wrapper.

**Packaging / build**
- ABIs: prioritize `arm64-v8a` (all modern phones); add `x86_64` for the emulator;
  `armeabi-v7a` only if you still target very old devices. Use ABI splits / App Bundle
  so each device downloads one `.so`.
- minSdk 29 + native `.so` is fine (no desugaring concerns for native libs).
- FFI overhead (~tens of ns/call) is negligible against a pairing; but don't cross the
  boundary per-pubkey — pass the whole committee in one call (and cache native points).

## Suggested path
1. Land the `BlsBackend` seam (done) + keep Milagro as default.
2. Wire `JblstBlsBackend` into the **daemon** (desktop) behind the seam, retire the
   Milagro cache/pool there, and A/B it. (Daemon-testable on a dev host.)
3. Build **route B** (Rust `blst` + UniFFI + cargo-ndk) for Android; select
   `AndroidBlstBackend` when the `.so` loads, else fall back to Milagro. Measure cold
   verify on a real device — expect seconds → tens of ms.
4. Once the wrapper covers both hosts, drop jblst + Milagro.

## Next candidates (same seam pattern)
secp256k1 (libsecp256k1), keccak/whole-MPT-proof (alloy-trie), SSZ SHA-256 (`sha2`
asm), and — separate, larger — EVM (`revm`) for `eth_call`. See the evaluation summary.
