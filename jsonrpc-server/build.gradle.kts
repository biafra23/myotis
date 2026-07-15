// :jsonrpc-server — a JSON-RPC HTTP endpoint on top of Myotis, hosted by the
// Android app, the CLI daemon, AND the iOS app. Measurement-driven: starts as a
// logging proxy and progressively serves verified light-client data (see the plan).
//
// Kotlin MULTIPLATFORM since the iOS listener landed: commonMain holds the
// router/server/logger against this module's own pure-Kotlin seams (RpcBackend /
// RpcStatusSource); jvmMain adapts them from the io.myotis.api contracts for the
// JVM hosts, iosMain supplies the platform actuals (the iOS host adapts the seams
// over the Rust engine's C ABI in :app-ios). The HTTP server is Ktor CIO and the
// upstream proxy client is Ktor Client CIO — pure Kotlin, multiplatform, and
// Android-safe (no java.net.http, no com.sun.net.httpserver).

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(21)

    // JVM 21 bytecode: this module depends on :networking (discv5) and :myotis-evm
    // (Besu) on the JVM side, both of which publish JVM-21 metadata, so Gradle
    // variant resolution requires a 21 consumer. CLAUDE.md's 17 default explicitly
    // yields when a transitive forces 21 — and AGP 8.7's D8 dexes 21 class files
    // for :android-app (already proven for :networking).
    jvm {
        compilerOptions {
            jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
        }
    }
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            // HTTP server (endpoint) + client (upstream proxy).
            implementation(libs.ktor.server.core)
            implementation(libs.ktor.server.cio)
            implementation(libs.ktor.server.cors)
            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.cio)

            implementation(libs.kotlinx.serialization.json)
            implementation(libs.kotlinx.coroutines.core)
        }
        jvmMain.dependencies {
            // The verified-read contract the JVM adapters wrap (io.myotis.api.VerifiedReads).
            api(project(":myotis-api"))
            // Shared verified-read primitives — the same modules :android-app and :app use.
            implementation(project(":core"))
            implementation(project(":networking"))
            implementation(project(":consensus"))
            implementation(project(":myotis-evm"))

            implementation(libs.slf4j.api)
        }
        jvmTest.dependencies {
            implementation(project.dependencies.platform(libs.junit.bom))
            implementation(libs.junit.jupiter)
            // Cross-check the commonMain Keccak-256 against Tuweni's (KeccakTest) —
            // test-only; the seam itself must stay dependency-free for iOS.
            // Tuweni's keccak256 resolves via JCA, so BouncyCastle registers as
            // the provider in the test.
            implementation(libs.tuweni.bytes)
            implementation(libs.tuweni.crypto)
            implementation(libs.bouncycastle)
            // logback on the test COMPILE classpath (not just runtime): RpcAccessLogTest attaches a
            // ListAppender to the io.myotis.jsonrpc.access logger to assert the access-log lines.
            implementation(libs.logback.classic)
            // Besu's BOM pins junit-platform 1.13 onto any classpath that sees :myotis-evm;
            // an unaligned launcher fails discovery. The root build adds this for plain-JVM
            // modules, but this module left that block when it went multiplatform.
            runtimeOnly("org.junit.platform:junit-platform-launcher")
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
