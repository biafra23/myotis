package io.myotis.ui

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/**
 * Shared no-op fakes for the [NodeScreen] seams, used by the desktop UI tests
 * (LogsFilterPersistenceTest, LogsTailFollowTest). Kept in one place so a
 * NodeController/Settings interface change breaks exactly one fixture.
 */
internal class FakeController : NodeController {
    override val running: Boolean = false
    override fun snapshots(): Flow<Map<String, NodeSnapshot>> = flowOf(emptyMap())
    override fun enableNetwork(name: String) {}
    override fun disableNetwork(name: String) {}
    override fun startNetwork(name: String) {}
    override fun stopNetwork(name: String) {}
    override fun rebootNetwork(name: String) {}
    override fun shutdown() {}
    override fun setTargetSnapPeers(target: Int) {}
    override fun setServedBlockWindow(blocks: Int) {}
    override fun applyBlsBackend() {}
    override fun applyEngineChoice() {}
    override fun clearCaches(network: String) {}
    override fun resetSyncState(network: String) {}
    override suspend fun requestAccount(network: String, address: String): AccountResult =
        error("not used in UI tests")
    override suspend fun resolveEns(network: String, name: String): EnsResult =
        error("not used in UI tests")
}

internal class FakeSettings : Settings {
    override fun enabledNetworks(): List<String> = listOf("mainnet")
    override fun primaryNetwork(): String = "mainnet"
    override fun allNetworks(): List<String> = listOf("mainnet")
    override fun isNetworkEnabled(name: String): Boolean = name == "mainnet"
    override fun setNetworkEnabled(name: String, enabled: Boolean) {}
    override fun rpcPortFor(network: String): Int = 8545
    override fun setRpcPort(network: String, port: Int) {}
    override fun snapTarget(): Int = 3
    override fun setSnapTarget(v: Int) {}
    override fun servedBlockWindow(): Int = 32
    override fun setServedBlockWindow(v: Int) {}
    override fun displayName(network: String): String = network
    override fun defaultRpcPort(network: String): Int = 8545
    override fun hasEns(network: String): Boolean = true
    override fun deepPoolThreshold(): Int = 0
    override fun setDeepPool(v: Int) {}
    override fun strictStateFreshness(): Boolean = false
    override fun setStrictStateFreshness(v: Boolean) {}
    override fun nativeBlsEnabled(): Boolean = false
    override fun setNativeBlsEnabled(v: Boolean) {}
    override fun rustEngineEnabled(): Boolean = false
    override fun setRustEngineEnabled(v: Boolean) {}
}
