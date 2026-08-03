// :ui — the shared Compose-Multiplatform UI + the pure-Kotlin NodeController/Settings seam.
// commonMain holds the screens + seam interfaces (no backend dependency); the Android,
// Desktop, and iOS hosts each supply the actuals. Targets: Android + Desktop JVM + iOS
// (arm64 device + arm64 simulator — :app-ios supplies the actuals over the Rust engine).

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin {
    jvmToolchain(21)

    androidTarget()
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    // The custom jvmSharedMain dependsOn edge below would otherwise make KGP
    // skip the default hierarchy (silently dropping iosMain and its actuals);
    // applying it explicitly keeps both.
    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material3)
                implementation(compose.ui)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)  // local-time formatting in the Logs tab
            }
        }
        // CacheFileStats' stat/read actuals are plain java.nio, identical on the
        // Android and Desktop JVM targets: one shared intermediate source set
        // instead of two copied actual files.
        val jvmSharedMain by creating {
            dependsOn(commonMain)
        }
        val desktopMain by getting {
            dependsOn(jvmSharedMain)
        }
        val androidMain by getting {
            dependsOn(jvmSharedMain)
        }
        // Desktop-JVM UI tests: drive the real composables headless (skiko software
        // rendering — no display needed, CI-safe). Regression tests for screen-level
        // state lifetimes (e.g. the Logs-tab filter surviving tab switches) live here.
        val desktopTest by getting {
            dependencies {
                implementation(compose.desktop.uiTestJUnit4)
                implementation(compose.desktop.currentOs)
            }
        }
    }
}

android {
    namespace = "io.myotis.ui"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}
