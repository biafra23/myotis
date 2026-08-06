package io.myotis.ios

import io.myotis.ui.Settings
import kotlinx.serialization.Serializable
import platform.Foundation.NSUserDefaults

/** The slice of the engine's NetworkInfo catalog the Settings seam needs. */
@Serializable
internal data class IosNetworkInfo(
    val name: String,
    val displayName: String,
    val chainId: Long,
    val hasEns: Boolean,
    val defaultRpcPort: Int,
)


/**
 * The iOS [Settings] actual: NSUserDefaults-backed (the platform's
 * SharedPreferences twin), with the same clamps as DesktopSettings so live and
 * reloaded values always agree. Network metadata comes from the Rust engine's
 * embedded catalog — the only engine on this host.
 *
 * The BLS and engine toggles are inert here: blst is compiled INTO the engine
 * static lib and the Rust engine is the only engine, so nativeBls/rustEngine
 * read as fixed `true` and the setters drop the write.
 */
class IosSettings : Settings {

    private val defaults = NSUserDefaults.standardUserDefaults
    private val networks: List<IosNetworkInfo> =
        engineJson.decodeFromString<List<IosNetworkInfo>>(RustEngine.availableNetworksJson())

    private fun info(network: String): IosNetworkInfo? = networks.firstOrNull { it.name == network }

    // objectForKey as the presence probe: integerForKey/boolForKey return 0/false
    // for ABSENT keys, which would silently shadow the defaults.
    private fun getInt(key: String, default: Int): Int =
        if (defaults.objectForKey(key) != null) defaults.integerForKey(key).toInt() else default

    private fun getBool(key: String, default: Boolean): Boolean =
        if (defaults.objectForKey(key) != null) defaults.boolForKey(key) else default

    override fun enabledNetworks(): List<String> {
        val csv = defaults.stringForKey(K_ENABLED) ?: return listOf("mainnet")
        // Key present = the user's explicit set (possibly empty); unknown names are
        // dropped so a stale entry can't feed startNetwork() a bad name.
        return csv.split(',').map(String::trim).filter { it.isNotEmpty() && info(it) != null }
    }

    override fun primaryNetwork(): String = enabledNetworks().firstOrNull() ?: "mainnet"

    override fun allNetworks(): List<String> = networks.map { it.name }

    override fun isNetworkEnabled(name: String): Boolean = name in enabledNetworks()

    override fun setNetworkEnabled(name: String, enabled: Boolean) {
        val set = enabledNetworks().toMutableList()
        if (enabled) {
            if (name !in set) set.add(name)
        } else {
            set.remove(name)
        }
        defaults.setObject(set.joinToString(","), K_ENABLED)
    }

    override fun rpcPortFor(network: String): Int =
        getInt("$K_RPC_PORT_PREFIX$network", defaultRpcPort(network))

    override fun setRpcPort(network: String, port: Int) {
        val clamped = if (port in 1024..65535) port else defaultRpcPort(network)
        defaults.setInteger(clamped.toLong(), "$K_RPC_PORT_PREFIX$network")
    }

    override fun snapTarget(): Int = getInt(K_SNAP, 32)
    override fun setSnapTarget(v: Int) = defaults.setInteger(v.coerceIn(1, 128).toLong(), K_SNAP)

    override fun servedBlockWindow(): Int = getInt(K_SERVED_WINDOW, 32)
    override fun setServedBlockWindow(v: Int) =
        defaults.setInteger(v.coerceIn(1, 4096).toLong(), K_SERVED_WINDOW)

    override fun displayName(network: String): String = info(network)?.displayName ?: network
    override fun defaultRpcPort(network: String): Int = info(network)?.defaultRpcPort ?: 8545
    override fun hasEns(network: String): Boolean = info(network)?.hasEns ?: false

    override fun deepPoolThreshold(): Int = getInt(K_DEEP, 16)
    override fun setDeepPool(v: Int) = defaults.setInteger(v.coerceIn(1, 128).toLong(), K_DEEP)

    override fun strictStateFreshness(): Boolean = getBool(K_STRICT, true)
    override fun setStrictStateFreshness(v: Boolean) = defaults.setBool(v, K_STRICT)

    override fun logIndexEnabled(network: String): Boolean =
        getBool("$K_LOG_INDEX_PREFIX$network", false)
    override fun setLogIndexEnabled(network: String, on: Boolean) =
        defaults.setBool(on, "$K_LOG_INDEX_PREFIX$network")
    override fun logIndexMaxSpeed(network: String): Boolean =
        getBool("$K_LOG_INDEX_SPEED_PREFIX$network", false)
    override fun setLogIndexMaxSpeed(network: String, on: Boolean) =
        defaults.setBool(on, "$K_LOG_INDEX_SPEED_PREFIX$network")

    // blst is statically linked into the engine — there is nothing to toggle.
    override fun nativeBlsEnabled(): Boolean = true
    override fun setNativeBlsEnabled(v: Boolean) {}

    // The Rust engine is the only engine on iOS.
    override fun rustEngineEnabled(): Boolean = true
    override fun setRustEngineEnabled(v: Boolean) {}

    private companion object {
        const val K_ENABLED = "networks.enabled"
        const val K_RPC_PORT_PREFIX = "rpcPort."
        const val K_LOG_INDEX_PREFIX = "logIndex."
        const val K_LOG_INDEX_SPEED_PREFIX = "logIndex.maxSpeed."
        const val K_SNAP = "snapTarget"
        const val K_SERVED_WINDOW = "servedBlockWindow"
        const val K_DEEP = "deepPool"
        const val K_STRICT = "strictStateFreshness"
    }
}
