// :jsonrpc-server — a JSON-RPC HTTP endpoint on top of Myotis, hosted by BOTH
// the Android app and the CLI daemon. Measurement-driven: starts as a logging
// proxy and progressively serves verified light-client data (see the plan).
//
// MUST run on Android (ART): no java.net.http, no com.sun.net.httpserver. The
// HTTP server is Ktor CIO and the upstream proxy client is Ktor Client CIO —
// pure Kotlin, matching the project's Ktor/Compose-Multiplatform direction.
// Targets JVM 17 bytecode so :android-app can consume + dex it (CLAUDE.md
// default for new modules), even though the root toolchain runs on JDK 21.

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

// JVM 21 bytecode: this module depends on :networking (discv5) and :myotis-evm
// (Besu), both of which publish JVM-21 metadata, so Gradle variant resolution
// requires a 21 consumer. CLAUDE.md's 17 default explicitly yields when a
// transitive forces 21 — same situation as those modules — and AGP 8.7's D8
// dexes 21 class files for :android-app (already proven for :networking).
// compileJava inherits the root's JDK-21 toolchain; match Kotlin to it.
kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
    }
}

dependencies {
    // The verified-read contract the router serves (io.myotis.api.VerifiedReads).
    implementation(project(":myotis-api"))
    // Shared verified-read primitives — the same modules :android-app and :app use.
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))

    // HTTP server (endpoint) + client (upstream proxy) — Android-safe.
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.cors)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.cio)

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)

    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)
    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
