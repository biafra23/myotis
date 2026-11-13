// :myotis-engine-go — the GO engine behind the :myotis-api contract: GoMyotisEngine /
// GoChainHandle / GoVerifiedReads over the Go engine's plain C ABI (go/cmd/myotis-capi,
// the same rust/include/myotis_engine.h contract the Rust engine exports) loaded via
// JNA. The desktop-only step-1 embed of the owner's program (2026-11): selectable via
// `myotis.engine=go`, never under `auto` (Rust stays the auto choice until engine
// parity). Like :myotis-engine-rust it depends on NOTHING from the Java engine and
// carries NO HTTP server: the loopback listener is the shared LoopbackRpc port
// (:myotis-engine-common) the :myotis-engines selector fills with the Ktor server.

plugins {
    `java-library`
}

// Java 17 class files (CLAUDE.md's default), `release` so no JDK-21-only API slips
// in — the same discipline as :myotis-engine-rust, though this module ships
// desktop-only for now.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}

dependencies {
    // The contract this engine implements.
    api(project(":myotis-api"))
    // The shared LoopbackRpc port (the listener port moved here from
    // :myotis-engine-rust exactly so this module need not depend on it).
    implementation(project(":myotis-engine-common"))
    // WebOrigins — the one pure-normalization definition the no-listener
    // setWebAccessPolicy answer must agree with (same reason :myotis-engine-rust
    // depends on :myotis-rpc-policy; no server rides along).
    implementation(project(":myotis-rpc-policy"))
    implementation(libs.minimal.json)
    implementation(libs.slf4j.api)
    // Plain-JVM JNA: the desktop host runs this, so the bare `jna` artifact
    // (its own jnidispatch shipped) is enough — no per-platform AAR handling.
    implementation(libs.jna)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Build the Go c-shared library first (no-op without go) and put go/build on
    // java.library.path so the native-backed tests exercise the real
    // libmyotis_engine_go (the Go twin of the cargoBuildHost wiring in
    // :myotis-engine-rust). Declared as an INPUT so a rebuilt library re-runs
    // these tests; inputs.files tolerates the missing output on go-less machines,
    // where those tests self-skip via assumeTrue.
    inputs.files(rootProject.tasks.named("goBuildCShared")).withPropertyName("nativeGoLibs")
    doFirst {
        val nativeDir = rootProject.file("go/build")
        if (nativeDir.exists()) {
            val sep = System.getProperty("path.separator")
            systemProperty(
                "java.library.path",
                nativeDir.absolutePath + sep + System.getProperty("java.library.path"),
            )
        }
    }
}
