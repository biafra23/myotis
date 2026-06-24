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
    // jvm-libp2p transitively pulls UPSTREAM io.netty (4.1.x). On Android we
    // strip io.netty group-wide and let the JitPack netty-kotlin fork (same
    // io.netty.* FQCNs, different coordinates) satisfy it. The JVM daemon must
    // resolve to the EXACT SAME netty bytecode as Android, otherwise the two
    // run different transport stacks and any libp2p reliability difference is
    // un-diagnosable. Exclude upstream io.netty here and supply the fork
    // explicitly (mirrors :networking's discovery exclude).
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
    // If the native blst lib (rust/myotis-bls) has been built, put it on java.library.path
    // so NativeBlsBackend.isAvailable() is true and BlsBackendBenchmark exercises it.
    // Build with: (cd rust/myotis-bls && cargo build --release)
    val nativeDir = rootProject.file("rust/myotis-bls/target/release")
    if (nativeDir.exists()) {
        val sep = System.getProperty("path.separator")
        systemProperty(
            "java.library.path",
            nativeDir.absolutePath + sep + System.getProperty("java.library.path"),
        )
    }
}
