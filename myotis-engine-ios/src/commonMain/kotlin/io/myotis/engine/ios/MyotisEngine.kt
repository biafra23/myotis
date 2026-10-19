package io.myotis.engine.ios

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The Rust engine for an iOS host, typed: the Kotlin twin of `io.myotis.api.MyotisEngine`
 * as the JVM side's `RustMyotisEngine` implements it, over the same C ABI
 * ([RustEngine]). `Myotis.newEngine()` makes one; a process needs only one, which
 * hosts each network at most once.
 *
 * Every call BLOCKS (a verified read for up to ~90 s, a start while the runtime comes
 * up): callers stay off the main thread, as on every other host.
 */
@OptIn(ExperimentalAtomicApi::class)
class MyotisEngine internal constructor(private val native: NativeEngine) {

    private val hosted = AtomicReference<Map<String, ChainHandle>>(emptyMap())

    /** The networks the engine knows, from its embedded catalog. */
    fun availableNetworks(): List<NetworkInfo> = EngineDecoding.networks(native.availableNetworksJson())

    /** The catalog's name for [nameOrAlias]; an unknown one throws [EngineException]. */
    fun canonicalNetworkName(nameOrAlias: String): String =
        native.canonicalNetworkName(nameOrAlias)
            ?: throw EngineException("Unknown network: $nameOrAlias. Supported: mainnet, sepolia, gnosis")

    /**
     * A not-yet-started handle for [config]'s network, its state under [EngineConfig.dataDir].
     * Throws [EngineException] for an unknown network, one this engine does not host, a
     * network already hosted by this engine, a directory bound to a caller-supplied
     * checkpoint (which this API cannot resume), or a runtime that would not come up.
     */
    fun create(config: EngineConfig): ChainHandle {
        val canonical = canonicalNetworkName(config.networkName)
        val network = availableNetworks().firstOrNull { it.name == canonical }
            ?: throw EngineException("unknown network: ${config.networkName}")
        if (canonical in hosted.load()) throw EngineException("network already hosted: $canonical")
        val id = native.create(canonical, config.dataDir)
        when {
            id == UNSUPPORTED_NETWORK -> throw EngineException("the Rust engine does not host $canonical yet")
            id == ANCHOR_MISMATCH -> throw EngineException(
                "dataDir ${config.dataDir} is bound to a caller-supplied checkpoint; " +
                    "this host cannot resume it, use a fresh dataDir",
            )
            id < 0 -> throw EngineException(
                "the Rust engine could not initialize the runtime or create the dataDir for $canonical",
            )
        }
        val handle = ChainHandle(native, id, canonical, network.chainId, network.hasEns)
        // Claim the network atomically; a create that lost a race releases its native handle.
        while (true) {
            val current = hosted.load()
            if (canonical in current) {
                native.stop(id)
                throw EngineException("network already hosted: $canonical")
            }
            if (hosted.compareAndSet(current, current + (canonical to handle))) return handle
        }
    }

    /** The handle hosting [networkName] (its canonical name), or null. */
    fun get(networkName: String): ChainHandle? = hosted.load()[networkName]

    /** The canonical names of the networks this engine hosts. */
    fun hostedNetworks(): List<String> = hosted.load().keys.toList()

    /** Stops [networkName]'s handle and releases it; the network can then be created again. */
    fun stop(networkName: String) {
        while (true) {
            val current = hosted.load()
            val handle = current[networkName] ?: return
            if (hosted.compareAndSet(current, current - networkName)) {
                handle.stop()
                return
            }
        }
    }

    /** Stops every hosted network. */
    fun shutdownAll() {
        hostedNetworks().forEach(::stop)
    }

    private companion object {
        /** `myotis_create`'s sentinels (rust/include/myotis_engine.h). */
        const val UNSUPPORTED_NETWORK = -2L
        const val ANCHOR_MISMATCH = -3L
    }
}
