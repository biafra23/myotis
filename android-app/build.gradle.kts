import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

// === Android-compatible Besu (biafra23/besu fork) ======================
// Besu's evm + algorithms modules assume JDK/runtime APIs Android's ART lacks
// (the JDK-9 Provider(String,String,String) ctor; Caffeine's StripedBuffer
// reflecting into Thread.threadLocalRandomProbe). The biafra23/besu fork
// patches both (BesuProvider → API-1 ctor; CodeCache → LinkedHashMap LRU, no
// Caffeine) and publishes them via JitPack. See besu-android-fork/README.md.
// We swap only these two modules to the fork — scoped to :android-app so the
// JVM daemon stays on upstream Besu, where those APIs work.
val besuForkVersion = "26.4.0-android.1"

// log4j-api is excluded because its `LogManager.getLogger()` no-args overload
// uses StackWalker to name the logger after the caller class, and Android's
// StackWalker returns null `getDeclaringClass()` for some frames — every
// discovery class with `static final Logger LOG = LogManager.getLogger()`
// blows up at <clinit>. Replaced with a tiny shim under
// src/main/java/org/apache/logging/log4j that routes to slf4j.
configurations.all {
    exclude(group = "org.apache.logging.log4j")
    // Swap Besu's evm + algorithms to the Android-patched fork (biafra23/besu via
    // JitPack); everything else stays upstream. Eager `all` so AGP's classpaths
    // pick up the resolutionStrategy before they resolve.
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.hyperledger.besu:besu-evm"))
            .using(module("com.github.biafra23.besu:besu-evm:$besuForkVersion"))
        // 26.4 renamed the crypto module's distribution artifact; our vendored
        // repo serves it as besu-crypto-algorithms — swap THAT to the fork's
        // algorithms module (same sources, ART-patched BesuProvider ctor).
        substitute(module("org.hyperledger.besu.internal:besu-crypto-algorithms"))
            .using(module("com.github.biafra23.besu:besu-crypto-algorithms:$besuForkVersion"))
        // The fork's POMs import org.hyperledger.besu:bom:24.12.2, which Besu
        // never publishes to Maven Central; redirect it to the fork-published
        // bom. The fork is pinned to version 24.12.2, so its other sibling refs
        // (besu-datatypes, internal:rlp) are the real released 24.12.2 on
        // Central and need no redirect — keeping them un-forked also avoids
        // duplicate org.hyperledger.besu.datatypes.* classes at dex time.
        substitute(platform(module("org.hyperledger.besu:bom")))
            .using(platform(module("com.github.biafra23.besu:bom:$besuForkVersion")))
    }
    // Historical: Besu ≤24.12 pulled the pre-rename io.tmio:tuweni-* 2.4.2,
    // colliding with our tuweni fork. Besu 26.4 targets tuweni 2.7.2 (the
    // fork's exact version) so nothing pulls io.tmio anymore — the exclude
    // stays as a cheap guard against a transitive reintroducing it.
    exclude(group = "io.tmio")
    // Requesting the STANDARD_JVM Guava variant (below) clashes with the
    // `android` variant that Besu pulls transitively — both provide the guava
    // capability. Resolve the conflict toward the JRE variant, which is the one
    // whose com.google.common.base.Supplier extends java.util.function.Supplier
    // (what Besu's crypto.Hash needs).
    // Guava declares two capabilities (its own, plus the legacy
    // com.google.collections:google-collections); both see the variant clash.
    listOf("com.google.guava:guava", "com.google.collections:google-collections").forEach { cap ->
        resolutionStrategy.capabilitiesResolution.withCapability(cap) {
            val jre = candidates.firstOrNull { it.variantName.contains("jre", ignoreCase = true) }
            if (jre != null) {
                select(jre)
                because("Besu needs the JRE variant of Guava on Android")
            }
        }
    }
    // (No Caffeine pin needed: the fork drops Caffeine from
    // JumpDestOnlyCodeCache AND nulls the 14 static precompile result caches
    // 26.4 added — nothing on the EVM path constructs a Caffeine cache, so its
    // StripedBuffer/System.Logger ART incompatibilities never trigger.)
}

// Optional JSON-RPC upstream-proxy URL (DEBUG/dev only) read from local.properties
// (`rpc.upstream=...`), which is gitignored — the Infura key never enters the repo.
// Empty when unset → the JSON-RPC server runs in strict (no-proxy) mode.
val rpcUpstream: String = run {
    val props = Properties()
    val lp = rootProject.file("local.properties")
    if (lp.exists()) lp.inputStream().use { props.load(it) }
    props.getProperty("rpc.upstream", "")
}

// Derived from the project version so a release sweep can't leave the app
// reporting a stale version in Settings → Apps, the same way :app-desktop
// derives its installer versions. 0.1.4-SNAPSHOT -> 0.1.4.
val releaseVersion = project.version.toString().substringBefore('-')

// versionCode is DERIVED too: the release guard does not check it, so as a
// hand-bumped literal a forgotten bump shipped an APK that refuses to install
// over the previous one (INSTALL_FAILED_VERSION_DOWNGRADE) with green CI. The
// mapping (and why it is monotonic) lives in the root build's
// releaseBuildNumber, shared with the iOS CFBundleVersion check.
val derivedVersionCode: Int = rootProject.extra["releaseBuildNumber"] as Int

android {
    namespace = "com.jaeckel.ethp2p.android"
    compileSdk = 35
    // The app has NO jniLibs of its own: every native lib it ships (the engine,
    // native BLS, JNA's dispatcher) arrives inside the engine library's AAR. Said
    // explicitly because AGP's default src/main/jniLibs is where cargoNdkAndroid
    // used to write, and an app's own copy wins the merge over a library's — a
    // libmyotis_*.so left there by an earlier build (not removed by `clean`) would
    // shadow the AAR's fresh one and fail UniFFI validation on-device, a silent
    // Java fallback. With no source dir, nothing from the app's tree reaches the APK.
    sourceSets.getByName("main").jniLibs.setSrcDirs(emptyList<String>())

    defaultConfig {
        applicationId = "com.jaeckel.ethp2p.android"
        minSdk = 29
        targetSdk = 34
        versionCode = derivedVersionCode // see derivedVersionCode above
        versionName = releaseVersion
        buildConfigField("String", "RPC_UPSTREAM", "\"$rpcUpstream\"")
        // -PtorEngine (root build.gradle.kts): whether these jniLibs were built with
        // Arti. Lets a Tor-less APK answer "no Tor" without loading the engine library.
        buildConfigField("boolean", "TOR_ENGINE", (rootProject.extra["torEngine"] as Boolean).toString())
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // Core-library desugaring. At minSdk 29 this supplies the Java 9-11 API
        // backports (List.of, String.strip, Collection.toArray(IntFunction),
        // Collectors.toUnmodifiable*, …) and — from desugar_jdk_libs 2.1.5 —
        // Stream.toList(), for our modules AND third-party jars alike. It does
        // NOT cover CompletableFuture.failedFuture/orTimeout/exceptionallyCompose,
        // java.util.HexFormat, Path.of, or BigInteger.int/longValueExact — those
        // are avoided in source instead (core's Futures, evm's Hex, Paths.get).
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // Pin the debug signing identity to a keystore checked into the repo so
    // every developer (and CI) signs debug APKs with the same key. This is a
    // widely used convention — the Android Studio-generated debug keystore
    // uses these exact defaults (password `android`, alias `androiddebugkey`,
    // key password `android`). Do not reuse these credentials for release.
    // That key is PUBLIC, so anything it signs can be "updated" by anyone: which
    // is why the debug build type is a separate app (below), never the release one.
    signingConfigs {
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        // Its own app next to the release one: com.jaeckel.ethp2p.android.debug,
        // "Myotis Debug", amber launcher icon (src/debug/res). Android accepts an
        // update only from the installed app's signer, and the debug signer above is
        // reproducible by anyone, so sharing the release app's package would let any
        // lookalike debug-signed APK install over Myotis, keep its data and answer the
        // wallets with unverified data. A separate package keeps the public key away
        // from the release app; its own icon and label keep a user from mistaking one
        // for the other.
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        // No signingConfig ON PURPOSE: assembleRelease writes
        // android-app-release-unsigned.apk, and only the tag-only signing job in
        // .github/workflows/android-apk.yml signs it, with the release key from the
        // `android-release` environment's secrets (docs/android-release-signing.md).
        // Signing here would put that key in the environment of the whole Gradle +
        // cargo build, third-party plugins and build scripts included.
        release {
            isMinifyEnabled = false
        }
    }

    testOptions {
        // No UI interactions in the smoke test, but system animations still cost
        // main-thread time on a software-rendered emulator — keep them off.
        animationsDisabled = true
        // Gradle Managed Device pinned to minSdk (API 29) for NodeBootSmokeTest
        // (androidTest — its KDoc carries the full why: real-ART boot coverage the
        // static dex scan cannot give). Run it with
        //   ./gradlew :android-app:api29DebugAndroidTest
        // (CI adds -Pandroid.testoptions.manageddevices.emulator.gpu=
        // swiftshader_indirect for its GPU-less runners — see
        // .github/workflows/android-apk.yml). It needs the Android Rust toolchain:
        // below API 33 the app is Rust-engine-only (EngineGate), so a
        // -PskipRustEngine build cannot boot a network on this device.
        // "aosp", not "aosp-atd": the leaner ATD images only exist for API 30+.
        // x86_64 hosts only — Google never published an API-29 arm64 emulator
        // image, so an Apple-Silicon Mac can't run this device locally; the CI
        // job is the enforcement point.
        managedDevices {
            localDevices {
                create("api29") {
                    device = "Pixel 2"
                    apiLevel = 29
                    systemImageSource = "aosp"
                    // REQUIRED, not a preference: the APK always carries native
                    // libs for exactly arm64-v8a + x86_64 (the engine library's AAR
                    // packages libjnidispatch.so even under -PskipRustEngine), and
                    // an APK with native libs installs only on a device offering a
                    // matching ABI. Left false, AGP resolves this device to the
                    // 32-BIT image (verified against AGP 8.7.3: aosp images get
                    // x86_64 only for apiLevel 26 and 30 — a two-element set, not
                    // a range — and everything else <= 30 falls through to x86),
                    // and the install dies with INSTALL_FAILED_NO_MATCHING_ABIS
                    // before any test runs.
                    require64Bit = true
                }
            }
        }
    }

    packaging {
        resources {
            // Common collisions when shipping JVM libs in an APK
            excludes += setOf(
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/DEPENDENCIES",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/INDEX.LIST",
                "META-INF/io.netty.versions.properties",
                // Upstream netty jars each carry license texts under META-INF/license/;
                // several ship identical filenames and the merger rejects duplicates.
                "META-INF/license/**",
                "META-INF/com.jaeckel.versions.properties",
                // JNA's jar carries jnidispatch for every DESKTOP platform. On
                // Android JNA takes the System.loadLibrary path and reads
                // lib/<abi>/libjnidispatch.so (added from the aar at the bottom
                // of this file), never these resources — ~2.2 MB of dead weight.
                "com/sun/jna/aix-*/**",
                "com/sun/jna/darwin-*/**",
                "com/sun/jna/win32-*/**",
                "com/sun/jna/linux-*/**",
                "com/sun/jna/freebsd-*/**",
                "com/sun/jna/openbsd-*/**",
                "com/sun/jna/sunos-*/**",
            )
            // Multiple netty modules ship the same native-image hint file;
            // metadata-only, take the first.
            pickFirsts += setOf(
                "META-INF/native-image/io.netty/netty-common/native-image.properties",
                // jvm-libp2p drags in four bouncycastle jars (bcprov, bcpkix,
                // bctls, bcutil) that all ship the same OSGI manifest under
                // META-INF/versions/9; the file is metadata-only.
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
    }
}

// Two-layer setup so AGP can compile against class-file-65 dependencies
// (ConsenSys discovery 26.4.0 and its transitive Vert.x, plus our own
// :networking module pinned to JVM 21 for discovery) while still emitting
// Java 17 bytecode for our own sources:
//
//   1. jvmToolchain(21) — Gradle uses a Java 21 toolchain to *run* javac.
//      JDK 17's javac cannot parse class file 65, so without this we'd get
//      "class file has wrong version 65.0, should be 61.0" at parse time.
//
//   2. compileOptions stays at JavaVersion.VERSION_17 — javac targets
//      Java 17 bytecode, our output is class file 61 (D8/ART-friendly),
//      and we don't admit Java 18+ language features.
kotlin {
    jvmToolchain(21)
}

// The Rust engine, its jniLibs and JNA's Android dispatcher all arrive through
// the engine library (:myotis-engine, the AAR): nothing here builds or packages a
// native lib any more. The -PskipRustEngine opt-out is honoured there too.

dependencies {
    testImplementation(libs.junit4)
    testImplementation(libs.okhttp2.urlconnection) // Android's HttpURLConnection upstream (see the catalog)
    // 2.1.5 is the first release whose config desugars Stream.toList() (via an
    // emulated Stream interface at minSdk ≤ 33) — earlier 2.1.x left it as a raw
    // API-34 call that crashes on Android 10-13 devices.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    // On-device boot smoke test (the api29 managed device above). Test APK only.
    androidTestImplementation(libs.junit4)
    androidTestImplementation(libs.androidx.test.core)      // ActivityScenario / ApplicationProvider
    androidTestImplementation(libs.androidx.test.runner)    // AndroidJUnitRunner (testInstrumentationRunner)
    androidTestImplementation(libs.androidx.test.rules)     // ServiceTestRule
    androidTestImplementation(libs.androidx.test.ext.junit) // AndroidJUnit4

    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    // ENS resolution runs the ENS contracts in a local Besu EVM over
    // SNAP-verified state. :myotis-evm is needed directly (not just
    // transitively) because our SnapPeer adapter (EthHandlerSnapPeer)
    // references its SnapPeer type, and Gradle hides a transitive
    // `implementation` dep from the consumer's compile classpath.
    implementation(project(":myotis-ens"))
    implementation(project(":myotis-evm"))

    // Embedded JSON-RPC HTTP server (Ktor) so wallets like MetaMask can point
    // at the phone. Hosted by NodeService.
    implementation(project(":jsonrpc-server"))

    // Shared verified-RPC backend (the single VerifiedRpcBackend the :app daemon
    // also constructs). NodeService delegates every verified read/call + ENS
    // resolution to it, so the verified machinery — and the confirm-screen fixes —
    // live once for both Android and the daemon. Pulls RpcLogger/RpcClock/
    // SnapQualitySink (the host seams) onto the compile classpath too.
    implementation(project(":rpc-backend"))

    // Shared per-network host core: ChainStack + NodeRegistry (same the :app daemon
    // hosts). NodeService builds one ChainStack per enabled network via Android cache
    // adapters, so the per-network EL+CL+RPC lifecycle lives once for both hosts.
    implementation(project(":node-core"))
    // Engine selector: NodeService.ENGINE is Engines.engine(); the Settings "Rust
    // engine" toggle drives it via NodeService.applyEngineChoice.
    implementation(project(":myotis-engines"))
    // The engine library: the Rust engine with the jniLibs and JNA's Android
    // dispatcher inside its AAR. The Android app consumes the Rust engine through
    // it; the JNA classes come with it (and from Besu), the natives ride in the AAR.
    implementation(project(":myotis-engine"))
    // The Rust engine's Tor seam (io.myotis.engines.rust.Tor — NodeService's Tor
    // toggle, AndroidNodeBridge), a documented API-boundary exemption (CLAUDE.md):
    // the library keeps the engine module off consumers' classpaths, so the app
    // names it itself.
    implementation(project(":myotis-engine-rust"))
    // TrueBlocks tx-history scan for the Query tab (documented API-boundary exemption:
    // NodeService reaches the raw connector via SelectorEngine.javaDelegate().debugStack).
    // Java-21 classfiles like :networking — already dexed fine (see libs.versions.toml).
    implementation(project(":tx-history"))

    // Shared Compose-Multiplatform UI + the NodeController/Settings seam. The Android
    // actuals (AndroidNodeController/AndroidSettings) back it with NodeService, so the
    // same NodeScreen renders on Android and Desktop.
    implementation(project(":ui"))

    // Force the JRE *variant* of Guava. Guava publishes jre and android
    // variants under one module; on an Android project Gradle's
    // org.gradle.jvm.environment=android attribute selects the `android`
    // variant, whose com.google.common.base.Supplier does NOT extend
    // java.util.function.Supplier. Besu's crypto.Hash memoizes a Supplier and
    // invokes it as java.util.function.Supplier, so the android variant throws
    // IncompatibleClassChangeError at runtime. The JRE variant's Supplier does
    // extend it (native at minSdk 29). A version force can't fix this — it's
    // variant selection — so request STANDARD_JVM explicitly for guava.
    implementation("com.google.guava:guava") {
        attributes {
            attribute(
                org.gradle.api.attributes.java.TargetJvmEnvironment.TARGET_JVM_ENVIRONMENT_ATTRIBUTE,
                objects.named(
                    org.gradle.api.attributes.java.TargetJvmEnvironment::class.java,
                    org.gradle.api.attributes.java.TargetJvmEnvironment.STANDARD_JVM
                )
            )
        }
    }

    // core/networking expose tuweni and netty only as `implementation`, so
    // add what the service code references directly.
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)
    implementation(libs.netty.transport)

    // consensus stack — BeaconLightClient, libp2p, BLS, snappy.
    implementation(libs.jvm.libp2p) {
        // Mirror :consensus (single-netty policy): keep libp2p's own netty set out —
        // it drags netty-tcnative-boringssl (macOS/Windows natives, ~9.6 MB of dead
        // APK weight), codec-http, and epoll classes we never load. The netty modules
        // we DO use (transport/codec/handler 4.2.x + their transitives) arrive via
        // :networking/:consensus, exactly like the daemon.
        exclude(group = "io.netty")
    }
    implementation(libs.milagro)
    implementation(libs.snappy)

    implementation(libs.bouncycastle)
    implementation(libs.slf4j.api)
    // The SLF4J service provider is in-tree (com.jaeckel.ethp2p.android.log
    // .AppSlf4jProvider) and registered via META-INF/services. It tees every
    // SLF4J call to logcat *and* the in-app LogBuffer so the Logs tab can
    // render output from consensus / networking / libp2p alongside our own
    // android.util.Log calls. No third-party binding needed.

    // Jetpack Compose UI (BOM pins all compose-* versions together)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)

    // WorkManager: the ~daily beacon catch-up while the node is idle-paused
    // (resume → sync → persist snapshot → pause), so wakes stay fast after
    // days of sleep. Java-only Worker — no ktx/coroutines artifact needed.
    implementation(libs.androidx.work.runtime)
}

// JNA version pin. The engine library's AAR carries libjnidispatch.so from
// jna-<catalog version>.aar, and JNA's Native.<clinit> compares the classpath
// jar's version against that native library's, throwing on a mismatch. Besu's
// BOM also constrains jna, so without this force the jar side would float with a
// Besu bump and silently reintroduce the failure (JNA throws, RustEngineNative
// reports the engine unavailable, the toggle falls back to Java) — and CI could
// not catch it, since it builds the APK but never runs it. Force keeps the two
// sides equal by construction; to move jna, move the catalog entry.
configurations.configureEach {
    resolutionStrategy.force("net.java.dev.jna:jna:${libs.versions.jna.get()}")
}
