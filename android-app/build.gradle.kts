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

android {
    namespace = "com.jaeckel.ethp2p.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.jaeckel.ethp2p.android"
        minSdk = 29
        targetSdk = 34
        // Stays a manual literal: a monotonic install counter with no relation
        // to semver, so there is nothing to derive it from. Bump it on every
        // release or the new APK won't install over the previous one.
        versionCode = 6
        versionName = releaseVersion
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

// JNA reaches the APK in TWO pieces, because no single artifact carries both:
//   - com.sun.jna.* classes come from the plain jna JAR, transitively via
//     :myotis-engines and Besu (nothing here declares it directly);
//   - jni/<abi>/libjnidispatch.so comes from jna-<v>.aar, extracted at the
//     bottom of this file into jniLibs.
// The aar cannot just be put on a classpath instead: it carries the same
// classes as the jar and fails the duplicate-class check.
//
// A previous attempt used variant-aware dependency substitution with an
// `artifactType = "aar"` attribute. That silently matched NO artifact — jna
// publishes no Gradle Module Metadata (only jna-<v>.pom, <packaging>jar</packaging>),
// so there is no aar variant to select — and the module resolved with its jar
// artifact dropped. The APK ended up with NO JNA at all, so the UniFFI bindings
// died on `NoClassDefFoundError: com.sun.jna.Native`, RustEngineNative reported
// the engine unavailable, and the "Rust engine" toggle silently fell back to
// Java. That is what shipped in v0.1.3 and v0.1.4.

dependencies {
    testImplementation("junit:junit:4.13.2")
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
    // JNA (the UniFFI bindings' loader) arrives transitively via :myotis-engines
    // and Besu, supplying com.sun.jna.*. Its ANDROID natives are added separately
    // at the bottom of this file — see "JNA's Android natives". Do NOT also put
    // jna-<v>.aar on a classpath here: it carries the same classes and fails the
    // duplicate-class check.
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

// Rebuild the Rust jniLibs from source when the full toolchain (cargo +
// cargo-ndk + NDK) is on this machine; cargoNdkAndroid self-skips otherwise
// and the committed jniLibs ship as-is. Root build.gradle.kts owns the task.
tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(rootProject.tasks.named("cargoNdkAndroid"))
}

// === JNA's Android natives =============================================
// The graph resolves the plain jna JAR, which supplies com.sun.jna.* but
// carries desktop natives only (win32/darwin/linux/aix). jni/<abi>/libjnidispatch.so
// — without which JNA cannot dispatch at all — ships exclusively in jna-<v>.aar.
//
// Take ONLY the natives from the aar and leave the classes on the jar: putting
// the aar on a classpath alongside the jar duplicates com.sun.jna.* and fails
// the duplicate-class check. A detached, non-consumable configuration keeps the
// aar off every classpath, so this adds files to the APK and changes no
// dependency resolution.
val jnaVersion = libs.versions.jna.get()

// The classpath jar and the extracted natives MUST be the same version: JNA's
// Native.<clinit> compares its own version against the native library's and
// throws on a major/minor mismatch. The natives below are hard-pinned via
// artifact-only @aar notation, which bypasses conflict resolution entirely, so
// without this the jar side would float free — today it lands on the right
// version only because Besu's BOM happens to constrain jna to the same value.
// A Besu bump could therefore silently reintroduce the very failure this file
// exists to prevent (JNA throws, RustEngineNative reports the engine
// unavailable, the toggle falls back to Java) and CI could not catch it, since
// it builds the APK but never runs it. Force keeps the two sides equal by
// construction; to move jna, move the catalog entry.
configurations.configureEach {
    resolutionStrategy.force("net.java.dev.jna:jna:$jnaVersion")
}

val jnaAndroidNatives: Configuration by configurations.creating {
    isTransitive = false
    isCanBeConsumed = false
}

dependencies {
    jnaAndroidNatives("net.java.dev.jna:jna:$jnaVersion@aar")
}

// Every ABI that gets libmyotis_engine.so needs a matching libjnidispatch.so,
// or UniFFI cannot load and that ABI silently falls back to the Java engine.
//
// KEEP IN SYNC with `cargo ndk -t ...` in rust/build-android.sh and the
// cargoNdkAndroid output paths in the root build.gradle.kts — one list, three
// places. Deliberately a literal rather than a listing of src/main/jniLibs:
// that directory is cargoNdkAndroid's EXECUTION-time output while this is read
// at CONFIGURATION time, so the first build after an ABI was added would read
// the pre-cargo state, omit the new ABI and ship it without a dispatcher — then
// self-heal on the next build, which is the worst way for this to fail. What
// actually enforces the invariant is the APK post-condition in
// .github/workflows/android-apk.yml, which checks the built artifact.
val shippedAbis = listOf("arm64-v8a", "x86_64")

// aar layout is jni/<abi>/lib*.so; the jniLibs source set wants <abi>/lib*.so.
// Sync, not Copy: Copy leaves behind files no longer in the spec, so a narrowed
// abi list (or a jna upgrade dropping one) would keep packaging a stale .so.
// NOT configuration-cache compatible, knowingly: the `from {}` / `eachFile {}`
// lambdas capture the build script, so `--configuration-cache` fails the whole
// build with "cannot serialize Gradle script object references". CC is off
// project-wide today (nothing sets it in gradle.properties or the Android CI
// workflow), so this is latent — enabling it for :android-app means moving this
// into a typed task in buildSrc first, which would also let the jniLibs wiring
// use AGP's addGeneratedSourceDirectory (a real producer->consumer edge)
// instead of the preBuild anchor below.
val extractJnaAndroidNatives = tasks.register<Sync>("extractJnaAndroidNatives") {
    from(jnaAndroidNatives.elements.map { zipTree(it.single().asFile) }) {
        shippedAbis.forEach { abi -> include("jni/$abi/**") }
    }
    eachFile { path = path.substringAfter("jni/") }
    includeEmptyDirs = false
    into(layout.buildDirectory.dir("jna-android-natives"))
    // Gradle does not warn about include patterns that match nothing, so an ABI
    // the aar has never carried (riscv64 being the realistic one) would extract
    // silently to nothing and that ABI would ship an engine with no dispatcher.
    doLast {
        val got = destinationDir.listFiles { f: java.io.File -> f.isDirectory }
            ?.map { it.name }.orEmpty().toSet()
        val missing = shippedAbis.filterNot { it in got }
        check(missing.isEmpty()) {
            "jna-$jnaVersion.aar carries no libjnidispatch.so for $missing — those ABIs " +
                "would ship libmyotis_engine.so with no JNA dispatcher and silently fall " +
                "back to the Java engine at runtime."
        }
    }
}

android {
    sourceSets.getByName("main").jniLibs.srcDir(extractJnaAndroidNatives)
}

// srcDir(<TaskProvider>) registers the DIRECTORY but does NOT carry a task
// dependency through AGP's source sets: on a clean build the jniLib merge runs
// before anything has extracted and the APK silently ships without
// libjnidispatch.so (incremental builds hide this — the directory is already
// populated from a previous run). Wire it through the same preBuild hook
// cargoNdkAndroid uses, which runs ahead of every merge/assemble/bundle path.
tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(extractJnaAndroidNatives)
}
