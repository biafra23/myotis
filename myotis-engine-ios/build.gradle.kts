// :myotis-engine-ios — the Rust engine for a Kotlin/Native iOS consumer: the cinterop
// bindings of the engine's plain C ABI (rust/include/myotis_engine.h) and RustEngine,
// the thin Kotlin face over them (the string-memory contract and the ABI handshake).
// The iOS twin of what eth.myotis:myotis-engine is for Android and the desktop JVM,
// published as
//
//   eth.myotis:myotis-engine-ios   (Gradle module metadata; -iosarm64, -iossimulatorarm64)
//
// so a Kotlin Multiplatform app with iOS targets (a separate wallet product is the
// first) depends on one coordinate, as :app-ios depends on this project. The cinterop
// absorbs libmyotis_engine.a (the def file's staticLibraries) into each target's
// cinterop klib, so the consumer's framework links the engine with no extra flags and
// no cargo of its own (docs/android-library.md, *iOS*).
//
// macOS only: the cinterop needs Apple's SDK and the .a needs the Apple rustup
// targets. Elsewhere the module disables its tasks (below) — so engine-library.yml
// stages it on a macOS runner and merges that into the Linux-staged set.

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    // Cargo triple per Kotlin/Native target, and the root cargo task that builds its
    // libmyotis_engine.a. x86_64 simulators are deliberately absent (Apple-Silicon-only
    // dev fleet); add iosX64 + a cargo task if an Intel simulator is ever needed.
    val rustTargets = mapOf(
        "ios_arm64" to "aarch64-apple-ios",
        "ios_simulator_arm64" to "aarch64-apple-ios-sim",
    )

    listOf(iosArm64(), iosSimulatorArm64()).forEach { target: KotlinNativeTarget ->
        val triple = rustTargets.getValue(target.konanTarget.name)
        target.compilations.getByName("main").cinterops.create("myotisEngine") {
            defFile(project.file("src/nativeInterop/cinterop/myotis_engine.def"))
            includeDirs(rootProject.file("rust/include"))
            // The def file names the static library; the search path is per-target
            // (device and simulator builds live in different cargo target dirs).
            extraOpts("-libraryPath", rootProject.file("rust/target/$triple/release").absolutePath)
        }
    }

    sourceSets {
        // This module is the FFI seam: cinterop symbols are what it is made of.
        all {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }
    }
}

// The cinterop step absorbs libmyotis_engine.a — cargo must have produced it first.
mapOf(
    "cinteropMyotisEngineIosArm64" to "cargoBuildIosDevice",
    "cinteropMyotisEngineIosSimulatorArm64" to "cargoBuildIosSim",
).forEach { (cinteropTask, cargoTask) ->
    tasks.matching { it.name == cinteropTask }.configureEach {
        dependsOn(rootProject.tasks.named(cargoTask))
    }
}

// Cargo stays STRICTLY OPTIONAL (the root build's contract): the cinterop fails
// outright when libmyotis_engine.a is missing, so when any triple's .a can neither
// be built now nor absorbed from an earlier build, this module disables its tasks,
// and :app-ios, which depends on it, does the same on the same verdict (the root
// build's myotis.iosFrameworkBuildable, beside the cargo probes it derives from).
// A disabled module publishes nothing: on Linux the staging leaves it out, and the
// publication check then asks for the macOS-staged set (engine-library.yml).
if (!(rootProject.extra["myotis.iosFrameworkBuildable"] as Boolean)) {
    tasks.configureEach {
        if (name != "clean" && group != "help") enabled = false
    }
}
