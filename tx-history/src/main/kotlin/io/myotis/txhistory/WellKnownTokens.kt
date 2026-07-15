package io.myotis.txhistory

/**
 * A small, hardcoded registry of well-known mainnet ERC-20 tokens so transfer rows can
 * show "1250.00 USDC" instead of a raw uint256 and a contract address. Deliberately
 * static: no symbol()/decimals() calls, no external token list at runtime — unknown
 * tokens simply render as generic contract calls.
 *
 * Addresses verified against the Uniswap default token list (stETH/wstETH against
 * Lido's registry) — mainnet (chainId 1) only.
 */
object WellKnownTokens {

    data class Token(val symbol: String, val decimals: Int)

    /** Lowercase 0x-prefixed token contract address → token metadata. Mainnet only. */
    val MAINNET: Map<String, Token> = mapOf(
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" to Token("USDC", 6),
        "0xdac17f958d2ee523a2206206994597c13d831ec7" to Token("USDT", 6),
        "0x6b175474e89094c44da98b954eedeac495271d0f" to Token("DAI", 18),
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" to Token("WETH", 18),
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" to Token("WBTC", 8),
        "0x514910771af9ca656af840dff83e8264ecf986ca" to Token("LINK", 18),
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984" to Token("UNI", 18),
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84" to Token("stETH", 18),
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0" to Token("wstETH", 18),
        "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9" to Token("AAVE", 18),
        "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2" to Token("MKR", 18),
        "0xd533a949740bb3306d119cc777fa900ba034cd52" to Token("CRV", 18),
        "0x5a98fcbea516cf06857215779fd812ca3bef1b32" to Token("LDO", 18),
        "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce" to Token("SHIB", 18),
        "0x6982508145454ce325ddbe47a25d4ec3d2311933" to Token("PEPE", 18),
        "0xc18360217d8f7ab5e7c516566761ea12ce7f9d72" to Token("ENS", 18),
        "0xc944e90c64b2c07662a292be6244bdf05cda44a7" to Token("GRT", 18),
        "0x4d224452801aced8b2f0aebe155379bb5d594381" to Token("APE", 18),
        "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0" to Token("MATIC", 18),
        "0xb50721bcf8d664c30412cfbc6cf7a15145234ad1" to Token("ARB", 18),
        "0xc00e94cb662c3520282e6f5717214004a7f26888" to Token("COMP", 18),
        "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f" to Token("SNX", 18),
        "0x111111111117dc0aa78b770fa6a738034120c302" to Token("1INCH", 18),
    )

    fun lookup(lowercaseAddress: String?): Token? = lowercaseAddress?.let { MAINNET[it] }
}
