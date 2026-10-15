// :myotis-rpc-policy — the JSON-RPC SERVING POLICY every backend applies, with no
// server attached: RpcBlockWindow, the block-selector window that decides which
// `latest`/`finalized`/number pins a verified read may answer from head state
// (#366), and the web-page policy's pure half (WebAccessMode / WebAccessPolicy /
// WebOrigins — which browser origins a listener admits, and the one canonical
// origin form, #502). It lives in its own Kotlin Multiplatform module so that the
// policy stays ONE definition for the JVM Rust engine (:myotis-engine-rust), the
// JSON-RPC router (:jsonrpc-server) and the iOS backend (:app-ios), while the
// engine module carries no Ktor listener — the engine library (the Android AAR,
// the desktop jar) must not ship the loopback server (owner's request,
// 2026-10-15). Dependency-free, so it compiles for every target the consumers do.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    jvmToolchain(21)

    // JVM 17 bytecode (CLAUDE.md's default): nothing here forces 21, and the
    // engine library consumes this from Android.
    jvm {
        compilerOptions {
            jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
            // Compile against the JDK 17 class library too, so no JDK-21-only API
            // slips in (jvmTarget alone only sets the class-file version).
            freeCompilerArgs.add("-Xjdk-release=17")
        }
    }
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        jvmTest.dependencies {
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            runtimeOnly("org.junit.platform:junit-platform-launcher")
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
