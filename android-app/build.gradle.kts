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
val besuForkVersion = "24.12.2-android.2"

// The JitPack netty-kotlin fork republishes netty-common/buffer/etc. with the
// same fully-qualified classes; the JVM tolerates the shadowing but the dexer
// doesn't. vertx-core (transitive via tuweni-crypto) drags upstream netty in,
// so strip it project-wide and rely on the fork.
//
// log4j-api is excluded because its `LogManager.getLogger()` no-args overload
// uses StackWalker to name the logger after the caller class, and Android's
// StackWalker returns null `getDeclaringClass()` for some frames — every
// discovery class with `static final Logger LOG = LogManager.getLogger()`
// blows up at <clinit>. Replaced with a tiny shim under
// src/main/java/org/apache/logging/log4j that routes to slf4j.
configurations.all {
    exclude(group = "io.netty")
    exclude(group = "org.apache.logging.log4j")
    // Swap Besu's evm + algorithms to the Android-patched fork (biafra23/besu via
    // JitPack); everything else stays upstream. Eager `all` so AGP's classpaths
    // pick up the resolutionStrategy before they resolve.
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.hyperledger.besu:evm"))
            .using(module("com.github.biafra23.besu:evm:$besuForkVersion"))
        substitute(module("org.hyperledger.besu.internal:algorithms"))
            .using(module("com.github.biafra23.besu:algorithms:$besuForkVersion"))
        // The fork's POMs import org.hyperledger.besu:bom:24.12.2, which Besu
        // never publishes to Maven Central; redirect it to the fork-published
        // bom. The fork is pinned to version 24.12.2, so its other sibling refs
        // (besu-datatypes, internal:rlp) are the real released 24.12.2 on
        // Central and need no redirect — keeping them un-forked also avoids
        // duplicate org.hyperledger.besu.datatypes.* classes at dex time.
        substitute(platform(module("org.hyperledger.besu:bom")))
            .using(platform(module("com.github.biafra23.besu:bom:$besuForkVersion")))
    }
    // Besu (via :myotis-evm) pulls the pre-rename tuweni coordinates
    // io.tmio:tuweni-* 2.4.2, whose org.apache.tuweni.* classes collide with
    // our JitPack fork (com.github.biafra23.tuweni-kotlin 2.7.2-jvm17.1) —
    // D8 rejects the duplicates. Strip io.tmio and route Besu's tuweni to the
    // fork (same package, newer version; API-compatible for the units/bytes
    // Besu uses).
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
    // (No Caffeine pin needed: the fork's CodeCache drops Caffeine, so nothing
    // on the EVM path loads a Caffeine class — its StripedBuffer/System.Logger
    // Android incompatibilities never trigger.)
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

android {
    namespace = "com.jaeckel.ethp2p.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jaeckel.ethp2p.android"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("String", "RPC_UPSTREAM", "\"$rpcUpstream\"")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // Sugar for java.time, java.nio.file etc. missing from Android's stdlib
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
    signingConfigs {
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
                "META-INF/com.jaeckel.versions.properties",
            )
            // The jitpack netty-kotlin fork ships the same native-image hint
            // file as upstream netty-common; just take the first one.
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

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    // ENS resolution runs the ENS contracts in a local Besu EVM over
    // SNAP-verified state. :myotis-evm is needed directly (not just
    // transitively) because the SnapPeer/CcipGateway/BlockContext/Address
    // types are referenced from our adapter + NodeService, and Gradle hides
    // a transitive `implementation` dep from the consumer's compile classpath.
    implementation(project(":myotis-ens"))
    implementation(project(":myotis-evm"))

    // Embedded JSON-RPC HTTP server (Ktor) so wallets like MetaMask can point
    // at the phone. Hosted by NodeService.
    implementation(project(":jsonrpc-server"))

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
    implementation(libs.jvm.libp2p)
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
}
