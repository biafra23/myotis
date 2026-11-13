package io.myotis.logindex

import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * The log index's predefined contracts: for each protocol a wallet may want to
 * read history for — RAILGUN, Swarm, Privacy Pools and Tornado Cash — the
 * contracts its client reads logs from on each network, each from its CREATION
 * block. Adding a preset is the same as typing its contracts into the Index tab:
 * the engine walks down from the head to each `fromBlock` over devp2p and keeps
 * only logs it verified against the block's `receiptsRoot` — nothing here is a
 * seed, and nothing is trusted to anyone but the chain.
 *
 * A `fromBlock` is a TRUST ASSERTION (see the UI's `LogIndexWatch`): the index
 * answers `[]` below it without consulting coverage, so a value above the real
 * deployment would silently hide history. Every value here is therefore the
 * block in which the contract's code first appears (eth_getCode bisection,
 * `scripts/logindex_preset_census.py`, 2026-11-10), never a later "start
 * scanning" block a client config may carry — with one documented exception
 * below that is exactly the contract's first log. Undershooting only walks
 * further; it cannot lie.
 *
 * The [Census] figures are what the download and disk ESTIMATES
 * ([LogIndexDownloads.estimate]) are computed from. They are measurements of
 * public chain data taken once when the catalog was written, not a promise:
 * the walk's real cost depends on the peers and on how the chain grew since.
 */
object LogIndexPresets {

    /** A protocol a preset belongs to; several presets (one per network) share one. */
    enum class Protocol(val displayName: String) {
        RAILGUN("RAILGUN"),
        SWARM("Swarm"),
        PRIVACY_POOLS("Privacy Pools"),
        TORNADO_CASH("Tornado Cash"),
    }

    /** One watched contract: [fromBlock] is its creation block (see the class doc). */
    data class Contract(val address: String, val fromBlock: Long, val label: String)

    /**
     * What the estimates are computed from, measured at block [atBlock]:
     * [logs] the preset's contracts had emitted since their creation;
     * [candidateShare] — the share of blocks whose header bloom matches ANY of
     * the preset's contracts, i.e. whose receipts the walk has to download to
     * look (sampled); [receiptBytesPerCandidate] — the size of one such block's
     * receipts in eth/69 form, sampled over the preset's own range (it differs
     * several-fold between 2019's blocks and today's, and candidates lean toward
     * full blocks, whose blooms match more); [bytesPerLog] — what one stored log
     * costs on disk (measured from built indexes where one exists, see [ALL]).
     */
    data class Census(
        val atBlock: Long,
        val logs: Long,
        val candidateShare: Double,
        val receiptBytesPerCandidate: Int,
        val bytesPerLog: Int,
    )

    /** One protocol on one network. [id] is stable and is what an embedding app names. */
    data class Preset(
        val id: String,
        val protocol: Protocol,
        val network: String,
        /** One line: what the history is for. */
        val summary: String,
        val contracts: List<Contract>,
        val census: Census,
    ) {
        /** The lowest creation block — how far down the walk goes for this preset. */
        val fromBlock: Long get() = contracts.minOf { it.fromBlock }
        val title: String get() = protocol.displayName
    }

    /**
     * Per-network wire costs of the walk beside the receipts (which are per
     * preset, [Census.receiptBytesPerCandidate]): one header ([headerBytes]) and
     * the body of a block that holds a watched log ([bodyBytes], the only bodies
     * the walk fetches).
     */
    data class ChainCost(
        val headerBytes: Int,
        val bodyBytes: Int,
    )

    private val CHAIN_COSTS = mapOf(
        // Header ~0.6 KB, body ~100 KB (docs/how-it-works/disk-and-network-usage.md).
        "mainnet" to ChainCost(headerBytes = 600, bodyBytes = 100_000),
        "sepolia" to ChainCost(headerBytes = 600, bodyBytes = 60_000),
        // ~0.55 KB headers (docs/ideas/logindex-verified-bundle-design.md).
        "gnosis" to ChainCost(headerBytes = 550, bodyBytes = 40_000),
    )

    /** [network]'s walk costs, or null for a network no preset covers. */
    @JvmStatic
    fun chainCost(network: String): ChainCost? = CHAIN_COSTS[network]

    /** Every preset, in display order (protocol, then network). */
    @JvmField
    val ALL: List<Preset> = listOf(
        // RAILGUN: one watch entry per network covers what the wallet reads
        // (docs/guides/railgun-poc.md, *What is in it*). Mainnet's entry is the
        // documented exception to "creation block": the proxy was created at
        // 14,693,013 but its first log is at 14,737,691 and a sweep from
        // genesis found none below it (zbox, 2026-09-22); the seeds and the
        // RAILGUN PoC use 14,737,691, and a watch entry here must agree with them
        // (a different fromBlock for the same address is a different index
        // fingerprint). Storage: ~600 B/log, from the built ~261 MB mainnet index
        // of ~438,000 logs.
        Preset(
            id = "railgun-mainnet",
            protocol = Protocol.RAILGUN,
            network = "mainnet",
            summary = "Private balances of a RAILGUN wallet (the smart-wallet proxy's history).",
            contracts = listOf(
                Contract("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9", 14_737_691, "RailgunSmartWallet proxy"),
            ),
            census = Census(atBlock = RAILGUN_MAINNET_AT, logs = RAILGUN_MAINNET_LOGS, candidateShare = RAILGUN_MAINNET_SHARE, receiptBytesPerCandidate = RAILGUN_MAINNET_RCPT, bytesPerLog = 600),
        ),
        Preset(
            id = "railgun-sepolia",
            protocol = Protocol.RAILGUN,
            network = "sepolia",
            summary = "Private balances of a RAILGUN wallet on the Sepolia testnet.",
            contracts = listOf(
                Contract("0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea", 5_784_774, "RailgunSmartWallet proxy"),
            ),
            census = Census(atBlock = 12_103_338, logs = 17_393, candidateShare = 0.02, receiptBytesPerCandidate = 89_829, bytesPerLog = 600),
        ),
        // Swarm: the four system contracts of Bee's Gnosis chain config
        // (ethersphere/go-storage-incentives-abi; docs/guides/bee-rpc-service.md).
        // A light Bee node reads PostageStamp only; it dominates the cost
        // anyway (10 % of blocks are its candidates, 11 % for all four). Creation
        // blocks: census, identical to the guide's table. Storage: ~200 B/log, from
        // the built ~247 MB four-contract index. The census's ~298 KB per candidate
        // at an 11 % share is ~33 KB per walked block — what the measured zbox
        // rebuild implies too (docs/guides/bee-rpc-service.md, *Timings*).
        Preset(
            id = "swarm-gnosis",
            protocol = Protocol.SWARM,
            network = "gnosis",
            summary = "Postage-stamp batches, price oracle, staking and redistribution for a Bee node.",
            contracts = listOf(
                Contract("0x45a1502382541Cd610CC9068e88727426b696293", 31_305_656, "PostageStamp"),
                Contract("0x47EeF336e7fE5bED98499A4696bce8f28c1B0a8b", 37_339_168, "PriceOracle"),
                Contract("0xda2a16EE889E7F04980A8d597b48c8D51B9518F4", 40_430_237, "Staking"),
                Contract("0x5069cdfB3D9E56d23B1cAeE83CE6109A7E4fd62d", 41_105_199, "Redistribution"),
            ),
            census = Census(atBlock = 49_204_136, logs = 1_316_831, candidateShare = 0.1133, receiptBytesPerCandidate = 297_896, bytesPerLog = 200),
        ),
        // Privacy Pools (0xbow, v1): the entrypoint (kohaku
        // packages/privacy-pools/src/config.ts) and the pools a kohaku client
        // syncs (its paymaster map names the mainnet ones). A pool registered
        // later is not here; reading one the index does not watch is REFUSED
        // (-32000), never answered empty. Storage per log is an estimate
        // (Deposited/Withdrawn/LeafInserted carry a few words each).
        Preset(
            id = "privacy-pools-mainnet",
            protocol = Protocol.PRIVACY_POOLS,
            network = "mainnet",
            summary = "Deposits, withdrawals and the commitment tree of the 0xbow Privacy Pools.",
            contracts = listOf(
                Contract("0x6818809EefCe719E480a7526D76bD3e561526b46", 22_153_713, "Entrypoint"),
                Contract("0xF241d57C6DebAe225c0F2e6eA1529373C9A9C9fB", 22_153_714, "ETH pool"),
                Contract("0xE859c0BD25f260BaEE534Fb52E307D3B64D24572", 22_988_421, "USDT pool"),
                Contract("0xB419C2867aB3CBC78921660cB95150d95A94CE86", 22_988_431, "USDC pool"),
            ),
            census = Census(atBlock = PP_MAINNET_AT, logs = PP_MAINNET_LOGS, candidateShare = PP_MAINNET_SHARE, receiptBytesPerCandidate = PP_MAINNET_RCPT, bytesPerLog = 250),
        ),
        Preset(
            id = "privacy-pools-sepolia",
            protocol = Protocol.PRIVACY_POOLS,
            network = "sepolia",
            summary = "The 0xbow Privacy Pools on the Sepolia testnet.",
            contracts = listOf(
                Contract("0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB", 8_461_453, "Entrypoint"),
                Contract("0x644d5A2554d36e27509254F32ccfeBe8cd58861f", 8_461_454, "ETH pool"),
                Contract("0x6709277E170DEe3E54101cDb73a450E392ADfF54", 8_587_114, "USDT pool"),
                Contract("0x0b062Fe33c4f1592D8EA63f9a0177FcA44374C0f", 8_587_064, "USDC pool"),
            ),
            census = Census(atBlock = 12_103_343, logs = 6_547, candidateShare = 0.1967, receiptBytesPerCandidate = 155_778, bytesPerLog = 250),
        ),
        // Tornado Cash: the instance and relayer registries kohaku reads
        // (packages/tornado-cash/src/config.ts) and every instance of its static
        // catalog (src/instances.ts), whose Deposit/Withdrawal logs rebuild the
        // trees. kohaku syncs each pool from its own creation block, which is
        // what is here. Note that on Sepolia kohaku's config has the two
        // registries' deployment blocks swapped (the instance registry was
        // created at 5,594,660, the relayer registry at 5,594,611); the values
        // here are the chain's.
        Preset(
            id = "tornado-cash-mainnet",
            protocol = Protocol.TORNADO_CASH,
            network = "mainnet",
            summary = "Deposits and withdrawals of every Tornado Cash pool, and its registries.",
            contracts = listOf(
                Contract("0xB20c66C4DE72433F3cE747b58B86830c459CA911", 14_173_395, "Instance registry"),
                Contract("0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2", 14_173_129, "Relayer registry"),
                Contract("0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc", 9_116_966, "0.1 ETH"),
                Contract("0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936", 9_117_609, "1 ETH"),
                Contract("0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF", 9_117_720, "10 ETH"),
                Contract("0xA160cdAB225685dA1d56aa342Ad8841c3b53f291", 9_161_895, "100 ETH"),
                Contract("0x199112eb461ea7eec1d75b33343542e1d069b41c", 26_198_980, "0.01 ETH"),
                Contract("0x398971a7ae0fed4ae435f353ef00d3d4e4c18fd4", 26_198_980, "0.03 ETH"),
                Contract("0xf22487b84a618192aa68c0e1da24e9bbd892f774", 26_198_980, "0.3 ETH"),
                Contract("0x74185a3f30b873c0ce1f4257298d1cda61be2f9f", 26_198_980, "3 ETH"),
                Contract("0xc11197f71c7730c8b5db7c84191e07575f1db896", 26_198_983, "30 ETH"),
                Contract("0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3", 9_117_612, "100 DAI"),
                Contract("0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144", 9_161_917, "1,000 DAI"),
                Contract("0x07687e702b410Fa43f4cB4Af7FA097918ffD2730", 12_066_007, "10,000 DAI"),
                Contract("0x23773E65ed146A459791799d01336DB287f25334", 12_066_048, "100,000 DAI"),
                Contract("0x22aaA7720ddd5388A3c0A3333430953C68f1849b", 9_161_938, "5,000 cDAI"),
                Contract("0x03893a7c7463AE47D46bc7f091665f1893656003", 12_069_037, "50,000 cDAI"),
                Contract("0x2717c5e28cf931547B621a5dddb772Ab6A35B701", 12_067_606, "500,000 cDAI"),
                Contract("0xD21be7248e0197Ee08E0c20D4a96DEBdaC3D20Af", 12_066_053, "5,000,000 cDAI"),
                Contract("0xd96f2B1c14Db8458374d9Aca76E26c3D18364307", 9_161_958, "100 USDC"),
                Contract("0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBa9D", 9_161_965, "1,000 USDC"),
                Contract("0x169AD27A470D064DEDE56a2D3ff727986b15D52B", 9_162_005, "100 USDT"),
                Contract("0x0836222F2B2B24A3F36f98668Ed8F0B38D1a872f", 9_162_012, "1,000 USDT"),
                Contract("0x178169B423a011fff22B9e3F3abeA13414dDD0F1", 12_067_529, "0.1 WBTC"),
                Contract("0x610B717796ad172B316836AC95a2ffad065CeaB4", 12_066_652, "1 WBTC"),
                Contract("0xbB93e510BbCD0B7beb5A853875f9eC60275CF498", 12_067_591, "10 WBTC"),
            ),
            census = Census(atBlock = 26_383_196, logs = 791_516, candidateShare = 0.71, receiptBytesPerCandidate = 85_885, bytesPerLog = 220),
        ),
        Preset(
            id = "tornado-cash-sepolia",
            protocol = Protocol.TORNADO_CASH,
            network = "sepolia",
            summary = "The Tornado Cash pools and registries on the Sepolia testnet.",
            contracts = listOf(
                Contract("0x4e69fD587118dFb64957d18654E3894118E9B1BF", 5_594_660, "Instance registry"),
                Contract("0xD6663593E71e4916eCb6f6606e1A6FbfA1634ffA", 5_594_611, "Relayer registry"),
                Contract("0x8C4A04d872a6C1BE37964A21ba3a138525dFF50b", 5_594_400, "0.1 ETH"),
                Contract("0x8cc930096B4Df705A007c4A039BDFA1320Ed2508", 5_594_401, "1 ETH"),
                Contract("0x8d10d506d29fc62abb8a290b99f66db27fc43585", 5_594_402, "10 ETH"),
                Contract("0x6921fd1a97441dd603a997ED6DDF388658daf754", 5_594_406, "100 DAI"),
                Contract("0x0E999C5285141ccB6dFaE68A0921F37ABd3e6A87", 11_949_077, "0.01 ETH"),
                Contract("0x9480Be3964642efcD6CeBdb3570db8dC0f788908", 11_949_078, "0.03 ETH"),
                Contract("0x83091415b54d764E215153Ff54B36cCd44122e6e", 11_949_080, "0.3 ETH"),
                Contract("0x7eE90edc51c3739Af3ee277e09ADE3F3d6bad4AF", 11_949_081, "3 ETH"),
                Contract("0x3d1C943dfb2C8d9905B0Da0AFD18615915fF343A", 11_949_082, "30 ETH"),
            ),
            census = Census(atBlock = 12_103_350, logs = 6_881, candidateShare = 0.2933, receiptBytesPerCandidate = 125_902, bytesPerLog = 220),
        ),
    )

    /** The presets available on [network], in display order (empty for one without any). */
    @JvmStatic
    fun forNetwork(network: String): List<Preset> = ALL.filter { it.network == network }

    /** The preset with [id], or null. */
    @JvmStatic
    fun byId(id: String): Preset? = ALL.firstOrNull { it.id == id }
}

// ---- Mainnet census (scripts/logindex_preset_census.py, 2026-11-10) ----
private const val RAILGUN_MAINNET_AT = 26_383_396L
private const val RAILGUN_MAINNET_LOGS = 486_880L
private const val RAILGUN_MAINNET_SHARE = 0.1867
private const val RAILGUN_MAINNET_RCPT = 204_947
private const val PP_MAINNET_AT = 26_383_384L
private const val PP_MAINNET_LOGS = 60_591L
private const val PP_MAINNET_SHARE = 0.6067
private const val PP_MAINNET_RCPT = 147_749
