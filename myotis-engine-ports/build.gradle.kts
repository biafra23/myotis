// :myotis-engine-ports — the engine library's DEFAULT port actuals: what a host
// hands the engine through io.myotis.api.ports.EnginePorts when it has nothing
// of its own — the node-key file (FileNodeKeyStore), the EL and CL peer caches
// (FilePeerCache / FileClPeerCache), the CCIP-Read HTTP gateway
// (UrlConnectionHttpGateway) and the per-network file layout they share
// (NetworkFiles), assembled by DefaultEnginePorts.forNetwork. These are the
// implementations the Myotis Android app carried in NodeService until the engine
// library existed (the daemon and desktop keep their own twins in :app for now);
// moved here so a consumer of io.myotis:myotis-engine gets a working engine from
// a data directory alone instead of re-implementing four ports.
//
// Java 17 class files, Android-safe (the minSdk-29 budget in CLAUDE.md: plain
// java.io / java.nio.file.Files.readAllBytes + write, hand-rolled hex, no
// java.net.http — HttpURLConnection is the one HTTP client present on every
// API level). Over :myotis-api and slf4j only, so the AAR stays free of the
// Java engine and of Ktor.

plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    // `release`, not just source/target: no JDK-21-only library API can slip in.
    options.release = 17
}

dependencies {
    // The port interfaces these implement, and the flat records they return.
    api(project(":myotis-api"))
    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // The gateway test runs on OkHttp 2.7.5's HttpURLConnection — the code
    // Android's platform HttpURLConnection is forked from — because the
    // deadline rests on how disconnect() cancels a call, and the JDK's works
    // differently (see UrlConnectionHttpGatewayTest).
    testImplementation(libs.okhttp2.urlconnection)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
