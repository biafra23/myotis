java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":core"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    implementation(libs.snappy)
    implementation(libs.slf4j.api)
    implementation(libs.milagro)
    // Single-netty policy (one netty everywhere — Android, daemon, desktop — so
    // any libp2p reliability difference stays diagnosable): exclude jvm-libp2p's
    // own netty 4.2.10 set (which includes tcnative/codec-http modules we never
    // load) and supply the catalog's netty explicitly; libp2p ran fine on this
    // reduced 4.2 set throughout the netty-kotlin era.
    implementation(libs.jvm.libp2p) {
        exclude(group = "io.netty")
    }
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // Tuweni's Hash.keccak256 resolves "KECCAK-256" via a JCE provider; the trie
    // proof tests build fixtures with it, so BouncyCastle must be on the test path.
    testImplementation(libs.bouncycastle)
    // BLS acceleration benchmark: jblst (blst JNI) vs the pure-Java Milagro path.
    // Test scope only — not shipped; see docs/bls-rust-acceleration.md.
    testImplementation(libs.jblst)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Regeneration knobs for the conformance corpora (LcVectorConformanceTest,
    // ElMptVectorConformanceTest): forward them into the forked test JVM, where
    // -D on the gradlew line doesn't reach.
    System.getProperty("myotis.lc.writeExpected")?.let {
        systemProperty("myotis.lc.writeExpected", it)
    }
    System.getProperty("myotis.el.writeExpected")?.let {
        systemProperty("myotis.el.writeExpected", it)
    }
    // Build the Rust workspace first (no-op without cargo) and put its release dir on
    // java.library.path so NativeBlsBackend.isAvailable() is true and the BLS fixture
    // tests + BlsBackendBenchmark exercise the native backend. Declared as an INPUT
    // (not just dependsOn): a rebuilt native lib must re-run these tests — a doFirst
    // systemProperty alone is invisible to the up-to-date fingerprint. inputs.files
    // tolerates the outputs not existing on cargo-less machines.
    inputs.files(rootProject.tasks.named("cargoBuildHost")).withPropertyName("nativeRustLibs")
    // Resolved in doFirst — the dir only exists AFTER cargoBuildHost has run once.
    doFirst {
        val nativeDir = rootProject.file("rust/target/release")
        if (nativeDir.exists()) {
            val sep = System.getProperty("path.separator")
            systemProperty(
                "java.library.path",
                nativeDir.absolutePath + sep + System.getProperty("java.library.path"),
            )
        }
    }
}
