package io.myotis.ui

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
            """{"address":"${it.address}","fromBlock":${it.fromBlock}}"""
        }
        return """{"enabled":$enabled,"maxSpeed":$maxSpeed,"watch":[$entries]}"""
    }
}
