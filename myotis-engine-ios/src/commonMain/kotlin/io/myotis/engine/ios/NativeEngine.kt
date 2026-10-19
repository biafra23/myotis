package io.myotis.engine.ios

/**
 * The C ABI calls the typed API makes, one per `myotis_*` function, strings in and the
 * engine's JSON out: [RustEngine] behind it on a device, a fake in the tests. Keeping
 * the typed API on this seam lets its JSON decoding and its lifecycle rules be tested
 * without the engine, as the JVM side tests its decoders without JNI.
 */
internal interface NativeEngine {
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
}
