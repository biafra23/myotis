dependencies {
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)
}

tasks.register<JavaExec>("run") {
    group = "application"
    description = "Run the devp2p demo"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass = "devp2p.app.Main"
    // Use Java 21 toolchain JVM (matches compile target)
    javaLauncher = javaToolchains.launcherFor {
        languageVersion = JavaLanguageVersion.of(21)
    }
}
