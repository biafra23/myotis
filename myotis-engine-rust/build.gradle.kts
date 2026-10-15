// :myotis-engine-rust — the RUST engine behind the :myotis-api contract, on its own:
// RustMyotisEngine / RustChainHandle / RustVerifiedReads / RustEnsApi over the
// COMMITTED UniFFI-generated Kotlin bindings (src/main/kotlin/uniffi/myotis_engine/,
// regenerated via the root `uniffiGenerateKotlin` task) and JNA, plus the Tor seam.
// It depends on NOTHING from the Java engine (node-core / networking / consensus /
// Besu) and carries NO HTTP server: the loopback JSON-RPC listener is a port
// (LoopbackRpc) the :myotis-engines selector fills with the Ktor server for the
// JVM hosts, and the engine library (the Android AAR, the desktop jar) ships this
// module without one (owner's request, 2026-10-15). So a consumer needs none of
// the Java engine's Android build hacks (the Besu fork substitutions, the Guava
// variant pin, the log4j shim) and no Ktor. Host composition roots keep using the
// :myotis-engines selector; this module is what the selector routes `rust`/`auto`
// to, and what the Kotlin Multiplatform engine library will wrap.

plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

// Java 17 class files (CLAUDE.md's default — consumable from Android without the
// toolchain two-step): every dependency here is 17 or dependency-free, so nothing
// forces 21. `release`, not just source/target, so no JDK-21-only library API can
// slip into the engine library.
kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // The Kotlin half (the committed UniFFI bindings) gets the same guard as
        // javac's `release`: compiled against the JDK 17 class library.
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}

// The committed UniFFI bindings are NOT force-regenerated from compileKotlin:
// a `dependsOn(uniffiGenerateKotlin)` would drag a full `cargo build --release`
// (via cargoBuildHost) in front of every JVM host's Kotlin compile and make a
// broken rust/ break the JVM build — violating "Rust is OPTIONAL for the JVM
// hosts". Auto-regeneration is scoped to the Android build (:myotis-engine's
// preBuild, where cargo is already required); CI enforces freshness everywhere
// via the regenerate-and-diff step in android-apk.yml; regenerate manually
// elsewhere with `./gradlew uniffiGenerateKotlin`.
//
// mustRunAfter (NOT dependsOn) is ORDERING ONLY — inert when uniffiGenerateKotlin
// isn't in the graph (every non-Android build: no cargo pulled in), and, when it
// IS (an Android build regenerating the bindings), it makes compileKotlin read
// the fresh .kt and satisfies Gradle's implicit-dependency validation, since
// compileKotlin consumes uniffiGenerateKotlin's declared output.
tasks.named("compileKotlin") {
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}
// The sources jars of the publication (root build.gradle.kts, `Publishing`)
// read the same committed bindings, so they need the same ordering for the
// same reason — in an Android build Gradle refuses a sources jar that reads
// uniffiGenerateKotlin's output without it (implicit-dependency validation).
tasks.matching { it.name == "sourcesJar" || it.name == "kotlinSourcesJar" }.configureEach {
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}

dependencies {
    // The contract this engine implements.
    api(project(":myotis-api"))
    // WakeGate + SleepMetrics: the lifecycle primitives both engines' handles wire.
    implementation(project(":myotis-engine-common"))
    // RpcBlockWindow, the block-selector serving window RustVerifiedReads applies,
    // and WebOrigins, the origin form a web-page policy is normalized to: ONE
    // definition shared with the JSON-RPC router and the iOS backend — and no
    // server with it (that is the whole point of the module).
    implementation(project(":myotis-rpc-policy"))
    // No :core: its Hex was the one thing this module used, and :core carries
    // Tuweni and BouncyCastle, which would ride into every consumer of the AAR.
    // The FFI hex boundary uses io.myotis.engines.common.Hex instead (strict,
    // minSdk-29-safe — java.util.HexFormat is API 34; see CLAUDE.md).
    implementation(libs.minimal.json)
    implementation(libs.slf4j.api)
    // The FFI layer under the UniFFI-generated Kotlin bindings. Plain JVM artifact
    // here; the engine library (:myotis-engine) packs the @aar natives
    // (libjnidispatch.so) into its AAR for Android.
    implementation(libs.jna)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Build the Rust workspace first (no-op without cargo) and put its release dir on
    // java.library.path so the native-backed tests exercise the real libmyotis_engine.
    // Declared as an INPUT so a rebuilt native lib re-runs these tests (mirrors
    // :consensus). inputs.files tolerates missing outputs on cargo-less machines,
    // where those tests self-skip via assumeTrue.
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
