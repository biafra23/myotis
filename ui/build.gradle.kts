// :ui — the shared Compose-Multiplatform UI + the pure-Kotlin NodeController/Settings seam.
// commonMain holds the screens + seam interfaces (no backend dependency); the Android and
// Desktop hosts each supply the actuals. Targets: Android + Desktop JVM now (iOS later, once
// the backend has a native/KMP path — see docs/bls-rust-acceleration.md for the on-ramp).

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
    }
}

android {
    namespace = "io.myotis.ui"
    compileSdk = 34
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}
