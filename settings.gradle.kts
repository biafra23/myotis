rootProject.name = "myotis"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
        // Compose Multiplatform Gradle plugin dev builds (org.jetbrains.compose).
        // Never probed while the stable plugin resolves from the Plugin Portal;
        // filtered so the escape hatch cannot serve arbitrary other plugin ids.
        maven {
            url = uri("https://maven.pkg.jetbrains.space/public/p/compose/dev")
            content {
                includeGroupAndSubgroups("org.jetbrains.compose")
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // JitPack builds arbitrary GitHub repos on demand, so an unfiltered
        // entry lets resolution ask it for ANY group — a dependency-confusion
        // surface. Serve only the groups it actually provides, established
        // empirically from a cold-cache full resolve (re-establish the same
        // way: isolated GRADLE_USER_HOME + --info, which names the serving
        // repo per artifact). Adding a JitPack dependency? Its group must be
        // included below — a cold resolve's "Could not find" error will NOT
        // mention this filter, the repo is simply absent from the searched
        // locations. Other com.github.* groups in the graph (ben-manes.caffeine,
        // luben, jnr, …) are Maven-Central-hosted and must NOT route through
        // here.
        maven {
            name = "JitPack"
            url = uri("https://jitpack.io")
            content {
                // biafra23 forks: trueblocks-kotlin (gradle/libs.versions.toml),
                // the besu fork under the com.github.biafra23.besu subgroup
                // (android-app substitutions), and — once #397 lands — the
                // discovery fork.
                includeGroupAndSubgroups("com.github.biafra23")
                // kethereum + khex: bare group (khex root) plus the
                // .kethereum / .khex subgroups.
                includeGroupAndSubgroups("com.github.komputing")
                // java-multibase, a jvm-libp2p transitive.
                includeGroup("com.github.multiformats")
            }
        }
        // Still needed for two tech.pegasys artifacts Maven Central does not
        // serve: noise-java 22.1.0 (jvm-libp2p transitive; no other declared
        // repo has it — it alone keeps this repo alive) and jblst 0.3.15
        // (:consensus BLS benchmark; Central carries only 0.3.17+, so a bump
        // may move jblst to Central — noise-java still pins the repo).
        // io.consensys.protocols:discovery moved to Maven Central and is gone
        // from here.
        maven {
            name = "ConsenSys"
            url = uri("https://artifacts.consensys.net/public/maven/maven/")
            content {
                includeGroup("tech.pegasys")
            }
        }
        // jvm-libp2p's own repo. Filtered: unfiltered, this entry was probed
        // for — and, declared first, could shadow — the org.hyperledger.besu
        // artifacts served by the Hyperledger repo below.
        maven {
            name = "Cloudsmith-libp2p"
            url = uri("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/")
            content {
                includeGroup("io.libp2p")
            }
        }
        // Besu's release repo. The pinned Besu artifacts (besu-evm,
        // besu-datatypes, the org.hyperledger.besu.internal modules) are not
        // on Maven Central at all — this repo is their only source (Central
        // is probed first and 404s them).
        maven {
            name = "Hyperledger"
            url = uri("https://hyperledger.jfrog.io/artifactory/besu-maven")
            content {
                includeGroupAndSubgroups("org.hyperledger.besu")
            }
        }
    }
}

include("core", "networking", "consensus", "app", "android-app", "myotis-evm", "myotis-ens", "jsonrpc-server", "rpc-backend", "node-core", "ui", "app-desktop", "app-ios", "myotis-api", "myotis-engines", "tx-history")
