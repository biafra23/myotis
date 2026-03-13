plugins {
    java
}

allprojects {
    group = "com.jaeckel.ethp2p"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    // Exclude native Netty transports for Android compatibility
    configurations.all {
        exclude(group = "io.netty", module = "netty-transport-native-epoll")
        exclude(group = "io.netty", module = "netty-transport-native-kqueue")
        exclude(group = "io.netty", module = "netty-transport-native-unix-common")
    }

    tasks.test {
        useJUnitPlatform()
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }
}
