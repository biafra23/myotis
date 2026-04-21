import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

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

// -------------------------------------------------------------------------
// Trust anchor refresh: fetch the current mainnet finalized block root from
// multiple independent public checkpoint endpoints, cross-validate, and
// rewrite the `@checkpoint:mainnet` region in NetworkConfig.java.
// -------------------------------------------------------------------------

tasks.register("refreshMainnetCheckpoint") {
    group = "trust"
    description = "Fetch the finalized mainnet block root from 3 public checkpoint providers, cross-validate, and update NetworkConfig.java. Use -Pdry to preview the diff without writing."

    doLast {
        // Three independent mainnet checkpoint-sync endpoints. These serve only a narrow
        // slice of the Beacon API (/eth/v1/beacon/blocks/{id}/root + /eth/v2/beacon/blocks/{id}),
        // which is enough for what we need here.
        val endpoints = listOf(
            "https://beaconstate.info",
            "https://sync-mainnet.beaconcha.in",
            "https://mainnet-checkpoint-sync.attestant.io",
        )
        val dryRun = project.hasProperty("dry")
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

        fun fetch(url: String): String? = try {
            val req = HttpRequest.newBuilder()
                .uri(URI(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .GET().build()
            val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
            if (resp.statusCode() == 200) resp.body()
            else { logger.warn("[refresh] $url → HTTP ${resp.statusCode()}"); null }
        } catch (e: Exception) {
            logger.warn("[refresh] $url failed: ${e.message}"); null
        }

        // `data.root` is nested directly under `data`; target that specifically to avoid
        // matching `parent_root`/`state_root`/`body_root` inside a header. Some endpoints
        // omit the `0x` prefix, so accept either form.
        val rootRe = Regex(""""data"\s*:\s*\{\s*"root"\s*:\s*"(0x)?([0-9a-fA-F]+)"""")
        // Anchor the slot search inside the "data" object. A full beacon block response
        // contains nested attestations that each carry a "slot" field — without the
        // anchor the regex would otherwise match those.
        val slotRe = Regex(""""data"\s*:\s*\{.*?"slot"\s*:\s*"?(\d+)"?""", RegexOption.DOT_MATCHES_ALL)

        fun normRoot(m: MatchResult): String = m.groupValues[2].lowercase()

        data class Fetched(val base: String, val slot: Long, val root: String? = null)

        // Phase 1: discover each endpoint's currently-finalized slot. Providers can disagree
        // by an epoch because they poll upstream nodes at different rates.
        val probed = endpoints.mapNotNull { base ->
            val body = fetch("$base/eth/v2/beacon/blocks/finalized") ?: return@mapNotNull null
            val slot = slotRe.find(body)?.groupValues?.get(1)?.toLong()
            if (slot == null) {
                logger.warn("[refresh] $base response missing slot"); null
            } else {
                logger.lifecycle("[refresh] $base → finalized slot=$slot")
                Fetched(base, slot)
            }
        }
        if (probed.size < 2) {
            throw GradleException("Need at least 2 successful endpoints; got ${probed.size}")
        }

        // Phase 2: normalize to the oldest observed finalized slot (which all endpoints can
        // serve) and re-query each for the canonical root AT that slot.
        val minSlot = probed.minOf { it.slot }
        val resolved = probed.map { f ->
            val body = fetch("${f.base}/eth/v1/beacon/blocks/$minSlot/root")
                ?: throw GradleException("${f.base} could not resolve slot $minSlot")
            val root = rootRe.find(body)?.let { normRoot(it) }
                ?: throw GradleException("${f.base} response at slot $minSlot missing root field")
            logger.lifecycle("[refresh] ${f.base} @ slot $minSlot → $root")
            Fetched(f.base, minSlot, root)
        }

        val distinct = resolved.mapNotNull { it.root }.toSet()
        if (distinct.size != 1) {
            val detail = resolved.joinToString("\n  ") { "${it.base} → ${it.root}" }
            throw GradleException(
                "Cross-validation FAILED at slot $minSlot. Endpoints disagreed:\n  $detail\n" +
                "Aborting; NetworkConfig.java not modified.")
        }

        val finalRoot = distinct.single().removePrefix("0x")
        val period = minSlot / 8192
        // Shared with BeaconChainSpec.MAINNET_GENESIS_TIME via gradle.properties
        val genesis = (project.property("ethp2p.mainnet.genesisTime") as String).toLong()
        val ts = Instant.ofEpochSecond(genesis + minSlot * 12)
        val date = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC).format(ts)

        val file = project(":networking").projectDir.resolve(
            "src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java")
        val original = file.readText()
        val beginMarker = "// @checkpoint:mainnet:begin"
        val endMarker = "// @checkpoint:mainnet:end"
        val beginIdx = original.indexOf(beginMarker)
        val endIdx = original.indexOf(endMarker)
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw GradleException("Could not find @checkpoint:mainnet:begin/end markers in NetworkConfig.java")
        }
        // Preserve whatever line ending the source file uses so we don't mix CRLF/LF
        // when running on Windows.
        val eol = if (original.contains("\r\n")) "\r\n" else "\n"
        val beginLineStart = original.lastIndexOf('\n', beginIdx) + 1
        // Stop the replaced region at the end of the end-marker text itself (not at the
        // following newline), so the original line terminator is preserved verbatim.
        val endMarkerEnd = endIdx + endMarker.length
        val indent = original.substring(beginLineStart, beginIdx)

        val replacement = buildString {
            append(indent).append("// @checkpoint:mainnet:begin — managed by `./gradlew refreshMainnetCheckpoint`").append(eol)
            append(indent).append("// trusted checkpoint: recent finalized mainnet block root (slot $minSlot, $date, period $period)").append(eol)
            append(indent).append("Bytes.fromHexString(\"$finalRoot\").toArrayUnsafe(),").append(eol)
            append(indent).append("// @checkpoint:mainnet:end")
        }
        val updated = original.substring(0, beginLineStart) + replacement + original.substring(endMarkerEnd)

        if (original == updated) {
            logger.lifecycle("[refresh] NetworkConfig.java already up to date (slot $minSlot, root 0x$finalRoot). No change.")
            return@doLast
        }

        val matchedHosts = probed.map { URI(it.base).host }
        if (dryRun) {
            logger.lifecycle("[refresh] -Pdry set; preview only (no write):")
            original.substring(beginLineStart, endMarkerEnd).lines().forEach { logger.lifecycle("- $it") }
            replacement.lines().forEach { logger.lifecycle("+ $it") }
            logger.lifecycle("[refresh] consensus: slot=$minSlot date=$date period=$period")
            logger.lifecycle("[refresh] matched ${probed.size}/${endpoints.size} endpoints: $matchedHosts")
        } else {
            val tmp = File(file.absolutePath + ".tmp")
            tmp.writeText(updated)
            Files.move(
                tmp.toPath(), file.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
            logger.lifecycle("[refresh] NetworkConfig.java updated.")
            logger.lifecycle("[refresh]   slot=$minSlot period=$period date=$date")
            logger.lifecycle("[refresh]   root=0x$finalRoot")
            logger.lifecycle("[refresh]   matched ${probed.size}/${endpoints.size} endpoints: $matchedHosts")
        }
    }
}
