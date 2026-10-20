package io.myotis.engine.ios

/**
 * The C ABI calls the typed API makes, one per `myotis_*` function, strings in and the
 * engine's JSON out: [RustEngine] behind it on a device, a fake in the tests. Keeping
 * the typed API on this seam lets its JSON decoding and its lifecycle rules be tested
 * without the engine, as the JVM side tests its decoders without JNI.
 */
internal interface NativeEngine {
    /** A new reentrant lock: the typed API serializes each handle's lifecycle, and the
     *  engine's create/stop, on these, as the C ABI requires (rust/include/myotis_engine.h). */
    fun newLock(): EngineLock

    fun availableNetworksJson(): String
    fun canonicalNetworkName(nameOrAlias: String): String?

    /** A handle id (>= 1), or a negative sentinel (see [RustEngine.create]). */
    fun create(network: String, dataDir: String): Long
    fun start(handle: Long): Boolean
    fun stop(handle: Long)
    fun pause(handle: Long): Boolean
    fun resume(handle: Long): Boolean
    fun setWsBoundPeriods(handle: Long, periods: Long): Boolean
    fun acceptStaleAnchor(handle: Long): Boolean
    fun statusJson(handle: Long): String
    /** `myotis_set_network_metering` (0 unknown, 1 unmetered, 2 metered); false for another code. */
    fun setNetworkMetering(code: Int): Boolean
    /** `myotis_network_metering`. */
    fun networkMetering(): Int

    fun requestAccountJson(handle: Long, address: String, block: String): String
    fun getStorageProofJson(handle: Long, address: String, slot: Long, holder: String?): String
    fun getCodeJson(handle: Long, address: String, block: String): String
    fun getStorageAtJson(handle: Long, address: String, position32Hex: String, block: String): String
    fun ethCallJson(handle: Long, from: String, to: String, data: String, valueDecimal: String, block: String): String
    fun ethCallOverridesJson(
        handle: Long,
        from: String,
        to: String,
        data: String,
        valueDecimal: String,
        block: String,
        stateOverrides: String,
    ): String
    fun estimateGasJson(handle: Long, from: String, to: String, data: String, valueDecimal: String): String
    fun pendingNonceOverlay(handle: Long, address: String, minedNonce: Long): Long
    fun feeHistoryJson(handle: Long, blockCount: Long, newestBlockTag: String, percentilesJson: String): String
    fun getTransactionReceiptJson(handle: Long, txHash32Hex: String): String
    fun checkRawTransactionJson(rawTxHex: String): String
    fun sendRawTransactionJson(handle: Long, rawTxHex: String): String
    fun ensRecordJson(handle: Long, paramsJson: String): String
    fun setLogIndexConfig(handle: Long, configJson: String): Boolean
    fun logIndexStatusJson(handle: Long): String
    /** Null: the engine answered nothing (an unknown handle). */
    fun getLogsJson(handle: Long, filterJson: String): String?
}

/** A reentrant lock, from the platform ([NativeEngine.newLock]). */
internal interface EngineLock {
    fun lock()
    fun unlock()
}

internal inline fun <T> EngineLock.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
