package io.myotis.engine.ios

import platform.Foundation.NSRecursiveLock

/**
 * The iOS engine library's entry point, the twin of `io.myotis.engine.Myotis` on the
 * JVM: [newEngine] is the Rust engine behind the typed API, linked into the app from
 * this module's cinterop klib, with nothing listening on a port.
 */
object Myotis {

    /** A new engine. The first call makes the ABI handshake, which throws when the
     *  linked engine is not the one this module was built against. */
    fun newEngine(): MyotisEngine {
        RustEngine.requireAbi()
        return MyotisEngine(RustNativeEngine)
    }

    /** Up to [max] of the engine's buffered log lines, oldest first, newline-joined;
     *  empty when there are none. Process-wide: the host pumps them into its own log. */
    fun drainLogs(max: Int): String = RustEngine.drainLogs(max)
}

/** [NativeEngine] over the C ABI: each call is the [RustEngine] function of its name. */
internal object RustNativeEngine : NativeEngine {
    override fun newLock(): EngineLock = object : EngineLock {
        private val lock = NSRecursiveLock()
        override fun lock() = lock.lock()
        override fun unlock() = lock.unlock()
    }

    override fun availableNetworksJson() = RustEngine.availableNetworksJson()
    override fun canonicalNetworkName(nameOrAlias: String) = RustEngine.canonicalNetworkName(nameOrAlias)
    override fun create(network: String, dataDir: String) = RustEngine.create(network, dataDir)
    override fun start(handle: Long) = RustEngine.start(handle)
    override fun stop(handle: Long) = RustEngine.stop(handle)
    override fun pause(handle: Long) = RustEngine.pause(handle)
    override fun resume(handle: Long) = RustEngine.resume(handle)
    override fun setWsBoundPeriods(handle: Long, periods: Long) = RustEngine.setWsBoundPeriods(handle, periods)
    override fun acceptStaleAnchor(handle: Long) = RustEngine.acceptStaleAnchor(handle)
    override fun statusJson(handle: Long) = RustEngine.statusJson(handle)
    override fun setNetworkMetering(code: Int) = RustEngine.setNetworkMetering(code)
    override fun networkMetering() = RustEngine.networkMetering()

    override fun requestAccountJson(handle: Long, address: String, block: String) =
        RustEngine.requestAccountJson(handle, address, block)

    override fun getStorageProofJson(handle: Long, address: String, slot: Long, holder: String?) =
        RustEngine.getStorageProofJson(handle, address, slot, holder)

    override fun getCodeJson(handle: Long, address: String, block: String) =
        RustEngine.getCodeJson(handle, address, block)

    override fun getStorageAtJson(handle: Long, address: String, position32Hex: String, block: String) =
        RustEngine.getStorageAtJson(handle, address, position32Hex, block)

    override fun ethCallJson(handle: Long, from: String, to: String, data: String, valueDecimal: String, block: String) =
        RustEngine.ethCallJson(handle, from, to, data, valueDecimal, block)

    override fun ethCallOverridesJson(
        handle: Long,
        from: String,
        to: String,
        data: String,
        valueDecimal: String,
        block: String,
        stateOverrides: String,
    ) = RustEngine.ethCallOverridesJson(handle, from, to, data, valueDecimal, block, stateOverrides)

    override fun estimateGasJson(handle: Long, from: String, to: String, data: String, valueDecimal: String) =
        RustEngine.estimateGasJson(handle, from, to, data, valueDecimal)

    override fun pendingNonceOverlay(handle: Long, address: String, minedNonce: Long) =
        RustEngine.pendingNonceOverlay(handle, address, minedNonce)

    override fun feeHistoryJson(handle: Long, blockCount: Long, newestBlockTag: String, percentilesJson: String) =
        RustEngine.feeHistoryJson(handle, blockCount, newestBlockTag, percentilesJson)

    override fun getTransactionReceiptJson(handle: Long, txHash32Hex: String) =
        RustEngine.getTransactionReceiptJson(handle, txHash32Hex)

    override fun checkRawTransactionJson(rawTxHex: String) = RustEngine.checkRawTransactionJson(rawTxHex)

    override fun sendRawTransactionJson(handle: Long, rawTxHex: String) =
        RustEngine.sendRawTransactionJson(handle, rawTxHex)

    override fun ensRecordJson(handle: Long, paramsJson: String) = RustEngine.ensRecordJson(handle, paramsJson)
}
