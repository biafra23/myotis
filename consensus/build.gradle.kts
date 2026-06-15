java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":core"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    // Composite tuweni exposes units only at runtime; declare it for the compile
    // path (UInt64/UInt256 surface in tuweni APIs used by the light client).
    implementation(libs.tuweni.units)
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
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
