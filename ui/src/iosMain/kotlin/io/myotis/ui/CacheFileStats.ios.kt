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

internal actual fun statCacheFile(path: String): CacheFileIdentity? {
    val attrs = NSFileManager.defaultManager.attributesOfItemAtPath(path, null) ?: return null
    if (attrs[NSFileType] as? String != NSFileTypeRegular) return null
    val mtime = (attrs[NSFileModificationDate] as? NSDate) ?: return null
    val size = (attrs[NSFileSize] as? NSNumber) ?: return null
    return CacheFileIdentity(
        (mtime.timeIntervalSince1970 * 1000).toLong(),
        size.longLongValue,
    )
}

internal actual fun readCacheFileLines(path: String): List<String>? {
    val data = NSData.dataWithContentsOfFile(path) ?: return null
    val length = data.length.toInt()
    if (length == 0) return emptyList()
    val bytes = data.bytes?.readBytes(length) ?: return null
    return bytes.decodeToString().lines()
}
