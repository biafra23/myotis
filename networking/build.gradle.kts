java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":core"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)
    implementation(libs.bouncycastle)
    implementation(libs.snappy)
    implementation(libs.slf4j.api)
    implementation(libs.dnsjava)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.register<JavaExec>("dnsSmoke") {
    group = "verification"
    description = "Live DNS smoke test against the Ethereum Foundation EL tree"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass = "com.jaeckel.ethp2p.networking.dns.DnsSmokeTest"
}
