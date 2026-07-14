package io.myotis.ui

import java.nio.file.Files
import java.nio.file.Path

// The JVM-backed hosts (Android + Desktop) share these actuals verbatim —
// plain java.nio, available on both (minSdk 29 covers java.nio.file).

internal actual fun statCacheFile(path: String): CacheFileIdentity? = try {
    val p = Path.of(path)
    if (Files.isRegularFile(p)) {
        CacheFileIdentity(Files.getLastModifiedTime(p).toMillis(), Files.size(p))
    } else {
        null
    }
} catch (e: Exception) {
    null
}

internal actual fun readCacheFileLines(path: String): List<String>? = try {
    Files.readAllLines(Path.of(path))
} catch (e: Exception) {
    null
}
