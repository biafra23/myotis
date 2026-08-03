package io.myotis.ui

import java.nio.file.Files
import java.nio.file.Paths

// The JVM-backed hosts (Android + Desktop) share these actuals verbatim —
// plain java.nio, available on both. Paths.get, NOT Path.of: Path.of is
// API 34 on Android (minSdk here is 29) and isn't desugared, so it would
// NoSuchMethodError at runtime while compiling clean against SDK 35.

internal actual fun statCacheFile(path: String): CacheFileStat = try {
    val p = Paths.get(path)
    if (Files.isRegularFile(p)) {
        CacheFileStat.Present(Files.getLastModifiedTime(p).toMillis(), Files.size(p))
    } else {
        CacheFileStat.Missing
    }
} catch (e: Exception) {
    CacheFileStat.Unreadable
}

internal actual fun readCacheFileLines(path: String): List<String>? = try {
    Files.readAllLines(Paths.get(path))
} catch (e: Exception) {
    null
}
