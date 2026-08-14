package io.myotis.ui

import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * The shipped watch-list preset behind the "Log index (Kohaku contracts)"
 * toggle: the privacy contracts the Kohaku wallet libraries cold-sync from
 * (tornado-cash registries, the railgun proxy, the privacy-pools entrypoint),
 * with their deployment blocks. Data lives host-side by design — the engine
 * only ever sees the generic config JSON (docs/eth-getlogs-design.md §5).
 *
 * Instance-level tornado pools are announced via registry events and are NOT
 * pre-listed here; if wallet syncs query them directly the scoped index
 * answers with the honest unwatched-address error, which is the signal to
 * grow this preset (or make it dynamic) rather than a silent gap.
 */
object KohakuPreset {

    data class Watch(val address: String, val fromBlock: Long, val label: String)

    val byNetwork: Map<String, List<Watch>> = mapOf(
        "mainnet" to listOf(
            Watch("0xB20c66C4DE72433F3cE747b58B86830c459CA911", 14_173_395, "Tornado instance registry"), // tornado instance registry
            Watch("0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2", 14_173_129, "Tornado relayer registry"), // tornado relayer registry
            Watch("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9", 14_693_013, "Railgun proxy"), // railgun proxy
            Watch("0x6818809EefCe719E480a7526D76bD3e561526b46", 22_153_713, "Privacy Pools entrypoint"), // privacy-pools entrypoint
        ),
        "sepolia" to listOf(
            Watch("0x4e69fD587118dFb64957d18654E3894118E9B1BF", 5_594_611, "Tornado instance registry"), // tornado instance registry
            Watch("0xD6663593E71e4916eCb6f6606e1A6FbfA1634ffA", 5_594_660, "Tornado relayer registry"), // tornado relayer registry
            Watch("0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea", 5_784_774, "Railgun proxy"), // railgun proxy
            Watch("0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB", 8_461_453, "Privacy Pools entrypoint"), // privacy-pools entrypoint
            // The POOL contracts, not just the entrypoint: a wallet rebuilding
            // its Privacy Pools state scans the pools themselves (that is where
            // the commitment events live), and refusing them left it unable to
            // reconstruct balances or withdraw. Captured from a live Kohaku
            // session on 2026-08-07: 24 eth_getLogs for the ETH pool and 18
            // each for the two stable pools, none of which this node indexed.
            // The stable pools are commented out in Kohaku's own
            // privacyPools/config.ts yet still queried, so they are here too.
            //
            // fromBlock DELIBERATELY UNDERSHOOTS. Kohaku's config gives
            // deploymentBlock 8,587,019 for all three, but a from_block is a
            // TRUST ASSERTION, not a hint: `LogIndex::query` clamps its
            // coverage requirement to it (`need_from = max(filter.from, entry
            // .from)`), so a value LATER than the real deployment makes the
            // index answer without the earlier part being covered — events
            // vanish with no error, and a wallet reads that as "no events".
            // Undershooting cannot lie (no logs exist below deployment) and is
            // nearly free: the backfill already descends to 5,594,611 for the
            // tornado registries, so an earlier from_block adds no blocks to
            // the walk, only bloom probes. Anchored on the entrypoint's own
            // block, which these pools belong to.
            Watch("0x644d5A2554d36e27509254F32ccfeBe8cd58861f", 8_461_453, "Privacy Pools ETH pool"),
            Watch("0x6709277E170DEe3E54101cDb73a450E392ADfF54", 8_461_453, "Privacy Pools USDT pool"),
            Watch("0x0b062Fe33c4f1592D8EA63f9a0177FcA44374C0f", 8_461_453, "Privacy Pools USDC pool"),
        ),
    )

    /**
     * The engine config JSON for [network], or null when the preset has no
     * entries for it (the caller then skips the push entirely — an engine
     * without a config keeps eth_getLogs in its honest not-configured state).
     */
    @JvmStatic
    @JvmOverloads
    fun configJson(network: String, enabled: Boolean, maxSpeed: Boolean = false): String? {
        val watch = byNetwork[network] ?: return null
        val entries = watch.joinToString(",") {
            // Labels ride along as the entry's display name (they are fixed
            // ASCII literals above — nothing to escape). The engine keeps
            // names out of the config fingerprint, so they never invalidate
            // accumulated coverage.
            """{"address":"${it.address}","fromBlock":${it.fromBlock},"name":"${it.label}"}"""
        }
        return """{"enabled":$enabled,"maxSpeed":$maxSpeed,"watch":[$entries]}"""
    }
}
