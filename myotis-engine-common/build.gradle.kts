// :myotis-engine-common — the lifecycle primitives BOTH engines' chain handles wire
// (WakeGate: wake-on-request over pause/resume with its hold/single-flight
// semantics; SleepMetrics: the idle-sleep accounting the Status screens show).
// They used to live in :node-core, which made the Rust engine's handle depend on
// the Java engine for two classes; here they depend on :myotis-api alone, so
// :myotis-engine-rust can be packaged without node-core (the Android library).
// Java 17 class files, Android-safe (minSdk 29 budget: see CLAUDE.md).

plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    // `release`, not just source/target: no JDK-21-only library API can slip in.
    options.release = 17
}

dependencies {
    // LifecycleState / WakeReason — the contract types the primitives speak.
    api(project(":myotis-api"))
    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
