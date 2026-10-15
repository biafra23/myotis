// :myotis-rpc-policy — the JSON-RPC SERVING POLICY every backend applies, with no
// server attached: today RpcBlockWindow, the block-selector window that decides
// which `latest`/`finalized`/number pins a verified read may answer from head
// state (#366). It lives in its own Kotlin Multiplatform module so that the
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
