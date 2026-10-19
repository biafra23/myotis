// :app-ios — the iOS host: a Kotlin/Native framework (MyotisKit) bundling the shared
// Compose UI (:ui) with the iOS actuals of its seams, driving the RUST engine
// in-process over the plain C ABI (rust/include/myotis_engine.h) through
// :myotis-engine-ios — the engine library's iOS module, whose cinterop absorbs
// libmyotis_engine.a, so the framework links it and the Xcode side needs no extra
// link flags. The JVM engine never runs on iOS — this host has no :myotis-engines /
// :node-core dependency at all. Consumed by ios-app/ (the Xcode project) via the
// standard embedAndSignAppleFrameworkForXcode build phase.

import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    // The targets :myotis-engine-ios has (x86_64 simulators deliberately absent there).
    // Bundles the per-target frameworks into MyotisKit.xcframework (device +
    // arm64 simulator) — the single distributable a consumer drops in. The
    // Xcode app doesn't use it (it links a per-target framework via
    // embedAndSignAppleFrameworkForXcode); this exists for the CI release
    // artifact. `assembleMyotisKitReleaseXCFramework` is the produced task.
    val xcf = XCFramework("MyotisKit")

    listOf(iosArm64(), iosSimulatorArm64()).forEach { target: KotlinNativeTarget ->
        target.binaries.framework {
            baseName = "MyotisKit"
            // Static framework: the Rust .a and the Kotlin objects end up in one
            // archive the app links directly — no embed step, no dyld at launch.
            isStatic = true
            xcf.add(this)
        }
    }

    sourceSets {
        // platform.* (Foundation/UIKit) APIs are this host's bread and butter.
        all {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }
        iosMain.dependencies {
            // The engine: RustEngine over the C ABI, libmyotis_engine.a inside.
            implementation(project(":myotis-engine-ios"))
            implementation(project(":ui"))
            // The JSON-RPC listener (Ktor CIO in commonMain; the backend here
            // adapts its seams over the Rust engine's C ABI).
            implementation(project(":jsonrpc-server"))
            // The serving-window policy the iOS backend applies (RpcBlockWindow).
            implementation(project(":myotis-rpc-policy"))
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation(libs.kotlinx.coroutines.core)
            // Parses the engine's JSON (status/account/ENS/catalog) — the Kotlin
            // twin of :myotis-engine-rust's minimal-json marshalling layer.
            implementation(libs.kotlinx.serialization.json)
        }
    }
}

// -----------------------------------------------------------------------------
// Cargo stays STRICTLY OPTIONAL (the root build's contract): :myotis-engine-ios's
// cinterop fails outright when libmyotis_engine.a is missing, so when any target's
// .a can neither be built now (macOS + cargo + the rustup target — the cargo task's
// own onlyIf) nor absorbed from an earlier build, this module disables its whole
// task chain instead, as :myotis-engine-ios does on the same verdict. `./gradlew
// build` then passes on a cargo-less machine — the root build prints one warning
// per skipped triple naming the missing prerequisites. The verdict is computed once
// in the root build (single source, beside the cargo probes it derives from).
// Building the actual iOS app DOES require the full toolchain — against a disabled
// module the Gradle step reports success with every task SKIPPED, and it is Xcode's
// subsequent link that fails at the missing framework, with the same warnings
// explaining why.
// -----------------------------------------------------------------------------
if (!(rootProject.extra["myotis.iosFrameworkBuildable"] as Boolean)) {
    tasks.configureEach {
        // `clean` keeps working (nothing about a missing toolchain makes deleting
        // build output wrong), and the help/diagnostic tasks (`tasks`,
        // `dependencies`, …) stay usable for debugging this module; everything
        // else is skipped.
        if (name != "clean" && group != "help") enabled = false
    }
}
