// :myotis-engine — THE ENGINE LIBRARY: Myotis as a Kotlin Multiplatform module the
// hosts consume — the Android AAR (the Myotis app and a separate wallet product)
// and the desktop jar (the desktop apps). It is the Rust engine
// (:myotis-engine-rust, behind the :myotis-api contract) packaged with what each
// platform needs to run it, and nothing else: no Java engine, no HTTP server, no
// UI (owner's requests, 2026-10-15).
//
//   jvmSharedMain  the entry point (Myotis) + the engine modules, shared by both
//                  JVM targets; the Java engine contract rides along as `api`
//   androidMain    the Android half: the jniLibs (libmyotis_engine.so +
//                  libmyotis_bls.so, cross-compiled FROM SOURCE by the root
//                  cargoNdkAndroid task into src/androidMain/jniLibs — nothing is
//                  committed, so nothing can drift) and JNA's Android dispatcher
//                  (libjnidispatch.so, taken from jna-<v>.aar at build time)
//   jvmMain        the desktop half (JNA finds the host dylib on java.library.path)
//
// The Android app's Rust-engine build contract used to live in android-app; it
// lives here now, where the artifact is produced: requireAndroidRustEngine,
// cargoNdkAndroid, uniffiGenerateKotlin and verifyAndroidJniLibs hang off this
// module's preBuild (root build.gradle.kts owns the tasks), and -PskipRustEngine
// builds the AAR without the engine (the Myotis app then runs the Java engine,
// API 33+ only — EngineGate).

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
}

// Mirror the root build's -PskipRustEngine parse (same truthy rules). When set,
// the AAR omits the Rust native libs — so packaging must also drop any
// libmyotis_*.so LEFT OVER in the source tree from an earlier toolchain build,
// or the AAR would ship a stale engine and the app would silently fall back to
// Java on-device (the very failure this contract prevents).
val skipRustEngine = project.hasProperty("skipRustEngine") &&
    (project.property("skipRustEngine") as? String).let {
        it.isNullOrBlank() || it.trim().lowercase() !in setOf("false", "0", "no", "off")
    }

kotlin {
    jvmToolchain(21)

    // Java 17 class files on both targets (CLAUDE.md's default): every dependency
    // here is 17 or dependency-free, and the AAR must be consumable by a plain
    // Android app with no toolchain two-step.
    androidTarget {
        // The AAR a consumer gets: the release variant (part 4 publishes it).
        publishLibraryVariants("release")
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    }
    jvm {
        compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    }

    // The custom jvmSharedMain dependsOn edge below would otherwise make KGP skip
    // the default hierarchy; applying it explicitly keeps androidMain/jvmMain wired
    // the standard way (same as :ui).
    applyDefaultHierarchyTemplate()

    sourceSets {
        // Both JVM targets run the same engine over the same bindings: one shared
        // source set for the entry point instead of two copies.
        val jvmSharedMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                // The engine contract every consumer codes against (io.myotis.api)…
                api(project(":myotis-api"))
                // …and the Rust engine behind it, with its host-side seams (the Tor
                // toggle, availability, the log drain) — reachable from the hosts
                // through this module, which is what they now depend on.
                api(project(":myotis-engine-rust"))
            }
        }
        val jvmMain by getting { dependsOn(jvmSharedMain) }
        val androidMain by getting { dependsOn(jvmSharedMain) }
        val jvmTest by getting {
            dependencies {
                implementation(project.dependencies.platform(libs.junit.bom))
                implementation(libs.junit.jupiter)
                runtimeOnly("org.junit.platform:junit-platform-launcher")
                runtimeOnly(libs.logback.classic)
            }
        }
    }
}

android {
    namespace = "io.myotis.engine"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets.getByName("main") {
        // cargoNdkAndroid's output: <abi>/libmyotis_engine.so + libmyotis_bls.so.
        jniLibs.srcDir("src/androidMain/jniLibs")
    }
    packaging {
        // -PskipRustEngine means "no Rust engine in this AAR". The jniLibs live in
        // the source tree, outside build/, so a lib left there by an earlier
        // toolchain build is NOT removed by `clean`, by .gitignore, or by
        // cargoNdkAndroid being skipped — AGP would happily package it, and
        // on-device it would fail UniFFI validation (bindings vs a stale .so) and
        // silently fall back to Java. Exclude them so the flag means what
        // requireAndroidRustEngine says it does.
        if (skipRustEngine) {
            jniLibs {
                excludes += setOf("**/libmyotis_engine.so", "**/libmyotis_bls.so")
            }
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
tasks.named<Test>("jvmTest") {
    // Build the Rust workspace first (no-op without cargo) and put its release dir on
    // java.library.path so the test sees the real libmyotis_engine; declared as an
    // INPUT so a rebuilt native lib re-runs it (mirrors :myotis-engine-rust). On a
    // cargo-less machine the test asserts the "unavailable" branch instead.
    inputs.files(rootProject.tasks.named("cargoBuildHost")).withPropertyName("nativeRustLibs")
    doFirst {
        val nativeDir = rootProject.file("rust/target/release")
        if (nativeDir.exists()) {
            val sep = System.getProperty("path.separator")
            systemProperty(
                "java.library.path",
                nativeDir.absolutePath + sep + System.getProperty("java.library.path"),
            )
        }
    }
}

// === The Rust engine, built from source into this module's jniLibs ===========
// requireAndroidRustEngine enforces the contract: with the toolchain present,
// cargoNdkAndroid cross-compiles the jniLibs and uniffiGenerateKotlin refreshes
// the committed bindings (:myotis-engine-rust) from the same source; without it,
// the build fails and names `-PskipRustEngine`. verifyAndroidJniLibs is the
// post-build backstop that the produced .so exports every UniFFI symbol the
// (now-fresh) bindings require. Auto-regen is scoped to the Android build ON
// PURPOSE — the JVM hosts must stay buildable without cargo (see
// myotis-engine-rust/build.gradle.kts), and CI enforces bindings freshness for
// everyone via the regenerate-and-diff step in android-apk.yml. Root
// build.gradle.kts owns the tasks.
tasks.matching { it.name == "preBuild" }.configureEach {
    // Always run the gate: with -PskipRustEngine it just logs the opt-out.
    dependsOn(rootProject.tasks.named("requireAndroidRustEngine"))
    // Only pull the Rust build tasks into the graph when we actually want the
    // engine — under -PskipRustEngine they'd only self-skip anyway, and keeping
    // them out avoids the JVM build touching cargo/bindings at all.
    if (!skipRustEngine) {
        dependsOn(rootProject.tasks.named("uniffiGenerateKotlin"))
        dependsOn(rootProject.tasks.named("cargoNdkAndroid"))
        dependsOn(rootProject.tasks.named("verifyAndroidJniLibs"))
    }
}
// The backstop must see the FRESH outputs of BOTH producers: cargoNdkAndroid's
// .so and uniffiGenerateKotlin's regenerated bindings (which verifyAndroidJniLibs
// reads as an input — without this ordering Gradle fails the build with an
// implicit-dependency validation error, and the check could otherwise validate
// against the stale .kt it is about to replace). The gate should fail first
// (before we spend time cross-compiling) when the toolchain is missing.
rootProject.tasks.named("verifyAndroidJniLibs").configure {
    mustRunAfter(rootProject.tasks.named("cargoNdkAndroid"))
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}
// Both expensive Rust producers run AFTER the gate, so a machine with cargo but
// without the Android toolchain (cargo-ndk / NDK / targets) fails fast instead of
// first building the whole host workspace: cargoNdkAndroid directly, and
// cargoBuildHost because uniffiGenerateKotlin dependsOn it (ordering the generator
// alone wouldn't hold cargoBuildHost back). Both edges are inert off-Android,
// where requireAndroidRustEngine isn't in the graph.
rootProject.tasks.named("cargoNdkAndroid").configure {
    mustRunAfter(rootProject.tasks.named("requireAndroidRustEngine"))
}
rootProject.tasks.named("cargoBuildHost").configure {
    mustRunAfter(rootProject.tasks.named("requireAndroidRustEngine"))
}

// === JNA's Android dispatcher, inside the AAR ==================================
// The engine's UniFFI bindings load through JNA. com.sun.jna.* comes from the
// plain jna JAR (:myotis-engine-rust's dependency, so every consumer has it), but
// that jar carries desktop natives only (win32/darwin/linux/aix) —
// jni/<abi>/libjnidispatch.so, without which JNA cannot dispatch at all, ships
// exclusively in jna-<v>.aar. Take ONLY the natives from the aar, into this
// module's jniLibs, so the AAR a consumer gets is complete on its own: no
// consumer has to know about the aar, and none can hit the duplicate-class
// failure of putting it on a classpath next to the jar. A detached,
// non-consumable configuration keeps the aar off every classpath.
//
// The classpath jar and the extracted natives MUST be the same version: JNA's
// Native.<clinit> compares its own version against the native library's and
// throws on a major/minor mismatch. Both come from the one catalog entry; a
// consumer that forces another jna version (the Myotis app does, against Besu's
// BOM) forces the SAME catalog value for that reason.
val jnaVersion = libs.versions.jna.get()

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
// places. Deliberately a literal rather than a listing of src/androidMain/jniLibs:
// that directory is cargoNdkAndroid's EXECUTION-time output while this is read
// at CONFIGURATION time. What actually enforces the invariant is the APK
// post-condition in .github/workflows/android-apk.yml, which checks the built
// Myotis app.
val shippedAbis = listOf("arm64-v8a", "x86_64")

// aar layout is jni/<abi>/lib*.so; the jniLibs source set wants <abi>/lib*.so.
// Sync, not Copy: Copy leaves behind files no longer in the spec, so a narrowed
// abi list (or a jna upgrade dropping one) would keep packaging a stale .so.
// NOT configuration-cache compatible, knowingly (the lambdas capture the build
// script); CC is off project-wide today.
val extractJnaAndroidNatives = tasks.register<Sync>("extractJnaAndroidNatives") {
    from(jnaAndroidNatives.elements.map { zipTree(it.single().asFile) }) {
        shippedAbis.forEach { abi -> include("jni/$abi/**") }
    }
    eachFile { path = path.substringAfter("jni/") }
    includeEmptyDirs = false
    into(layout.buildDirectory.dir("jna-android-natives"))
    // Gradle does not warn about include patterns that match nothing, so an ABI
    // the aar has never carried would extract silently to nothing and that ABI
    // would ship an engine with no dispatcher.
    doLast {
        val got = destinationDir.listFiles { f: java.io.File -> f.isDirectory }
            ?.map { it.name }.orEmpty().toSet()
        val missing = shippedAbis.filterNot { it in got }
        check(missing.isEmpty()) {
            "jna-$jnaVersion.aar carries no libjnidispatch.so for $missing — those ABIs " +
                "would ship libmyotis_engine.so with no JNA dispatcher, so the Rust engine " +
                "could not load at runtime (a silent Java fallback on API 33+, a failed boot below)."
        }
    }
}

android {
    sourceSets.getByName("main").jniLibs.srcDir(extractJnaAndroidNatives)
}

// srcDir(<TaskProvider>) registers the DIRECTORY but does NOT carry a task
// dependency through AGP's source sets: on a clean build the jniLib merge runs
// before anything has extracted and the AAR silently ships without
// libjnidispatch.so. Wire it through the same preBuild hook cargoNdkAndroid
// uses, which runs ahead of every merge/assemble/bundle path.
tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(extractJnaAndroidNatives)
}
