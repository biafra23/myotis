@file:OptIn(ExperimentalForeignApi::class)

package io.myotis.ui

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.readBytes
import platform.Foundation.NSData
import platform.Foundation.NSDate
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileModificationDate
import platform.Foundation.NSFileSize
import platform.Foundation.NSFileType
import platform.Foundation.NSFileTypeRegular
import platform.Foundation.NSNumber
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.timeIntervalSince1970

internal actual fun statCacheFile(path: String): CacheFileStat {
    val fm = NSFileManager.defaultManager
    val attrs = fm.attributesOfItemAtPath(path, null)
        // attributesOfItemAtPath conflates "no such file" with "stat failed";
        // disambiguate so a transient failure keeps last-known counts while a
        // genuinely purged cache reads as empty.
        ?: return if (fm.fileExistsAtPath(path)) CacheFileStat.Unreadable else CacheFileStat.Missing
    if (attrs[NSFileType] as? String != NSFileTypeRegular) return CacheFileStat.Missing
    val mtime = (attrs[NSFileModificationDate] as? NSDate) ?: return CacheFileStat.Unreadable
    val size = (attrs[NSFileSize] as? NSNumber) ?: return CacheFileStat.Unreadable
    return CacheFileStat.Present(
        (mtime.timeIntervalSince1970 * 1000).toLong(),
        size.longLongValue,
    )
}

internal actual fun readCacheFileLines(path: String): List<String>? {
    val data = NSData.dataWithContentsOfFile(path) ?: return null
    // Peer caches are a few KB; anything approaching this bound is corrupt.
    // The check also keeps the NSUInteger→Int conversion below from ever
    // truncating/going negative on a pathologically large file.
    if (data.length > MAX_CACHE_FILE_BYTES) return null
    val length = data.length.toInt()
    if (length == 0) return emptyList()
    val bytes = data.bytes?.readBytes(length) ?: return null
    return bytes.decodeToString().lines()
}

private const val MAX_CACHE_FILE_BYTES: ULong = 67_108_864uL // 64 MiB
