dependencies {
    implementation(project(":core"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    implementation(libs.snappy)
    implementation(libs.slf4j.api)
    implementation(libs.jblst)
    implementation(libs.jvm.libp2p)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}
