// :myotis-logindex-presets — the log index's PREDEFINED CONTRACTS: the watch
// entries of RAILGUN, Swarm, Privacy Pools and Tornado Cash per network (each
// contract's creation block, measured), what downloading and verifying their
// history costs (download and disk estimates, and whether adding them together
// saves a re-walk), and the engine config push that starts the download. One
// definition for the Index tab (:ui, every platform) and for an app that embeds
// the engine library and has no UI of ours (re-exported by :myotis-engine and
// :myotis-engine-ios), so the from-blocks — a trust assertion — and the
// "unmetered only" default cannot drift between them. Dependency-free Kotlin
// Multiplatform, like :myotis-rpc-policy, so it compiles for every target its
// consumers have. docs/how-it-works/log-index-presets.md.

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
