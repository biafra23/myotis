// :myotis-engine-natives — the Rust engine's HOST library for a desktop consumer of
// the engine library. eth.myotis:myotis-engine-jvm carries the engine's bindings but
// not libmyotis_engine itself, which is built per OS and architecture; this module
// publishes it as one plain jar per platform,
//
//   eth.myotis:myotis-engine-natives-<jna-prefix>   e.g. -darwin-aarch64, -linux-x86-64
//
// holding the library at <jna-prefix>/<library>: the classpath path JNA loads
// `myotis_engine` from when jna.library.path has none, so a consumer that puts the
// one matching its host on the runtime classpath gets a working engine with no
// java.library.path at all (docs/android-library.md, *Desktop*). The platforms are
// platforms.txt's lines.
//
// Where the libraries come from:
//   - -PengineNativesDir=<dir> — <dir>/<jna-prefix>/<library> for EVERY platform in
//     platforms.txt; engine-library.yml builds them on one runner per platform (the
//     host-natives matrix) and stages the set from one place. A platform missing there
//     fails its jar task, so a publication is never short of one.
//   - otherwise the host's own, from the root cargoBuildHost (RUST_TARGET /
//     -PrustTarget picks the platform when it cross-compiles): one publication, for
//     publishToMavenLocal while developing a consumer.
//
// No dependencies, no classes, no module metadata of its own: a consumer names the
// artifact of its platform next to eth.myotis:myotis-engine at the SAME version. A
// mismatched pair is refused at load (RustEngineNative's ABI check and UniFFI's
// per-function checksums), never half-loaded.

data class HostNative(val jnaPrefix: String, val rustTarget: String, val library: String)

val platforms: List<HostNative> = file("platforms.txt").readLines()
    .map { it.substringBefore('#').trim() }
    .filter { it.isNotEmpty() }
    .map { line ->
        val fields = line.split(Regex("\\s+"))
        require(fields.size == 3) { "platforms.txt: expected <jna-prefix> <rust target> <library>, got '$line'" }
        HostNative(fields[0], fields[1], fields[2])
    }

val nativesDir: String? = providers.gradleProperty("engineNativesDir").orNull?.takeIf { it.isNotBlank() }

// The host's platform, for the cargoBuildHost mode: the cross target when one is set
// (the root build's own rule), else the JVM's OS and architecture in JNA's spelling.
fun hostPlatform(followRustTarget: Boolean = true): HostNative {
    val rustTarget = rootProject.extra["rustTargetTriple"] as String?
    if (followRustTarget && rustTarget != null) {
        return platforms.firstOrNull { it.rustTarget == rustTarget }
            ?: throw GradleException("rust target $rustTarget is not in myotis-engine-natives/platforms.txt")
    }
    val os = System.getProperty("os.name").lowercase()
    val arch = when (val a = System.getProperty("os.arch").lowercase()) {
        "aarch64", "arm64" -> "aarch64"
        "amd64", "x86_64" -> "x86-64"
        else -> a
    }
    val prefix = when {
        os.contains("mac") -> "darwin-$arch"
        os.contains("win") -> "win32-$arch"
        else -> "linux-$arch"
    }
    return platforms.firstOrNull { it.jnaPrefix == prefix }
        ?: throw GradleException("this host ($prefix) is not in myotis-engine-natives/platforms.txt")
}

val published: List<HostNative> = if (nativesDir != null) platforms else listOf(hostPlatform())

// The platform this JVM runs on, when platforms.txt has it: its jar is the one the
// load test below can actually load (a cross-compiled one is not).
val hostPlatformOrNull: HostNative? = runCatching { hostPlatform(followRustTarget = false) }.getOrNull()
var hostJar: TaskProvider<Jar>? = null

extensions.configure<PublishingExtension> {
    published.forEach { platform ->
        val taskSuffix = platform.jnaPrefix.split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) }
        val artifactId = "myotis-engine-natives-${platform.jnaPrefix}"
        val dir = nativesDir
        val source: Provider<File> = if (dir != null) {
            provider { rootProject.file(dir).resolve("${platform.jnaPrefix}/${platform.library}") }
        } else {
            val releaseDir = rootProject.extra["rustReleaseDir"] as String
            rootProject.tasks.named("cargoBuildHost").map { rootProject.file("$releaseDir/${platform.library}") }
        }
        val jar = tasks.register<Jar>("nativesJar$taskSuffix") {
            description = "The Rust engine's host library for ${platform.jnaPrefix}, at JNA's classpath path"
            archiveBaseName.set(artifactId)
            if (nativesDir == null) dependsOn(rootProject.tasks.named("cargoBuildHost"))
            from(source) { into(platform.jnaPrefix) }
            if (nativesDir != null) {
                // A publication is never short of a platform: a missing library is
                // an error, never an empty jar.
                doFirst {
                    val lib = source.get()
                    if (!lib.isFile || lib.length() == 0L) {
                        throw GradleException("no ${platform.library} for ${platform.jnaPrefix} at $lib: -PengineNativesDir lacks it")
                    }
                }
            } else {
                // cargoBuildHost self-skips without cargo, and so does this jar, so a
                // cargo-less `./gradlew build` stays green; publishing it then fails
                // on the missing file, which is the right answer.
                onlyIf("the host library was built") { source.get().isFile }
            }
        }
        if (platform == hostPlatformOrNull) hostJar = jar
        publications.create<MavenPublication>("natives$taskSuffix") {
            this.artifactId = artifactId
            artifact(jar)
        }
    }
}

// The load test: the engine's bindings (:myotis-engine-rust, what
// eth.myotis:myotis-engine-jvm's entry point runs; a plain Java module, so no
// Android-or-JVM variant choice here) plus this host's natives jar on the classpath, NOTHING on java.library.path or jna.library.path — what a
// consumer of the two artifacts gets — must yield the Rust engine. Proves the path
// inside the jar is the one JNA reads and that the library matches the bindings
// (UniFFI's checksums and the ABI version run at load). Skipped where this host has
// no jar (no cargo, or a host not in platforms.txt).
dependencies {
    testImplementation(project(":myotis-engine-rust"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.named<Test>("test") {
    val jar = hostJar
    val host = hostPlatformOrNull
    if (jar == null || host == null) {
        enabled = false
    } else {
        dependsOn(jar)
        classpath += files(jar.flatMap { it.archiveFile })
        onlyIf("this host's natives jar was built") { jar.get().archiveFile.get().asFile.isFile }
        // Exactly the consumer's setup: no library path of any kind.
        systemProperty("java.library.path", "")
        systemProperty("myotis.natives.expectedEntry", "${host.jnaPrefix}/${host.library}")
    }
}
