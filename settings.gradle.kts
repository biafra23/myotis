rootProject.name = "Myotis"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        maven {
            name = "ConsenSys"
            url = uri("https://artifacts.consensys.net/public/maven/maven/")
        }
        maven {
            name = "Cloudsmith-libp2p"
            url = uri("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/")
        }
        maven {
            name = "JitPack"
            url = uri("https://jitpack.io")
        }
        // Hyperledger Besu publishes release artifacts (incl. the standalone
        // `evm` module) here. Maven Central mirrors are inconsistent across
        // versions, so we pin the source.
        maven {
            name = "Hyperledger"
            url = uri("https://hyperledger.jfrog.io/artifactory/besu-maven")
        }
    }
}

include("core", "networking", "consensus", "app", "android-app", "myotis-evm", "myotis-ens", "jsonrpc-server", "rpc-backend", "node-core")
