package io.myotis.ui

import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/**
 * Shared no-op fakes for the [NodeScreen] seams, used by the desktop UI tests
 * (LogsFilterPersistenceTest, LogsTailFollowTest, TxScanUiTest — which subclasses
 * FakeController to script specific seams). Kept in one place so a
 * NodeController/Settings interface change breaks exactly one fixture.
 */
internal open class FakeController : NodeController {
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

/** [expert] = Expert mode on: the Logs/Index tabs, the full Status rows, the tuning knobs. */
internal class FakeSettings(
    private var expert: Boolean = false,
    /** The one enabled chain, and so the one the screen selects. */
    private val network: String = "mainnet",
) : Settings {
    override fun expertMode(): Boolean = expert
    override fun setExpertMode(v: Boolean) { expert = v }
    override fun enabledNetworks(): List<String> = listOf(network)
    override fun primaryNetwork(): String = network
    override fun allNetworks(): List<String> = listOf(network)
    override fun isNetworkEnabled(name: String): Boolean = name == network
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
}

/**
 * Click the switch sitting beside [label] (scrolling it into view first). Every
 * switch in a tab is a semantics SIBLING of every label (the Rows aren't semantic
 * boundaries), so the pairing goes by vertical overlap.
 */
internal fun ComposeContentTestRule.toggleSwitchBeside(label: String) {
    val labelBounds = onNodeWithText(label).performScrollTo().fetchSemanticsNode().boundsInRoot
    val switches = onAllNodes(isToggleable())
    val beside = switches.fetchSemanticsNodes().indexOfFirst {
        it.boundsInRoot.top < labelBounds.bottom && it.boundsInRoot.bottom > labelBounds.top
    }
    check(beside >= 0) { "no switch beside '$label'" }
    switches[beside].performClick()
}
