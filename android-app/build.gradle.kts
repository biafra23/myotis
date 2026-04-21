plugins {
    alias(libs.plugins.android.application)
}

// The JitPack netty-kotlin fork republishes netty-common/buffer/etc. with the
// same fully-qualified classes; the JVM tolerates the shadowing but the dexer
// doesn't. vertx-core (transitive via tuweni-crypto) drags upstream netty in,
// so strip it project-wide and rely on the fork.
configurations.all {
    exclude(group = "io.netty")
}

android {
    namespace = "com.jaeckel.ethp2p.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jaeckel.ethp2p.android"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // Sugar for java.time, java.nio.file etc. on minSdk 28
        isCoreLibraryDesugaringEnabled = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    packaging {
        resources {
            // Common collisions when shipping JVM libs in an APK
            excludes += setOf(
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/DEPENDENCIES",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/INDEX.LIST",
                "META-INF/io.netty.versions.properties",
                "META-INF/com.jaeckel.versions.properties",
            )
            // The jitpack netty-kotlin fork ships the same native-image hint
            // file as upstream netty-common; just take the first one.
            pickFirsts += setOf(
                "META-INF/native-image/io.netty/netty-common/native-image.properties",
            )
        }
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    implementation(project(":core"))
    implementation(project(":networking"))

    // core/networking expose tuweni and netty only as `implementation`, so
    // add what the service code references directly.
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)
    implementation(libs.netty.transport)

    implementation(libs.bouncycastle)
    implementation(libs.slf4j.api)
    // slf4j-android binding would be nicer, but slf4j-simple keeps the POC self-contained
    runtimeOnly("org.slf4j:slf4j-simple:2.0.12")
}
