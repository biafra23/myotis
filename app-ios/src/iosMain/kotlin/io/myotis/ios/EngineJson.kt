package io.myotis.ios

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/** The one Json instance + null-safe accessors for the engine's JSON (the
 *  minimal-json getString/getLong/getBoolean twins: absent or JSON-null reads
 *  as the default). Shared by every file in this module so the semantics can't
 *  drift between call sites. */
internal val engineJson = Json { ignoreUnknownKeys = true }

internal fun JsonObject.engineString(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

internal fun JsonObject.engineBoolean(key: String): Boolean =
    (this[key] as? JsonPrimitive)?.booleanOrNull ?: false

internal fun JsonObject.engineLong(key: String, default: Long = 0L): Long =
    (this[key] as? JsonPrimitive)?.longOrNull ?: default

internal fun JsonObject.engineInt(key: String): Int =
    (this[key] as? JsonPrimitive)?.intOrNull ?: 0
