package io.myotis.txhistory

import com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder
import org.apache.tuweni.bytes.Bytes
import org.apache.tuweni.crypto.Hash
import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode

enum class TxKind { ETH_TRANSFER, ERC20_TRANSFER, CONTRACT_CALL, CONTRACT_CREATION }

/**
 * Succinct summary of one mined transaction. Display strings ([ethDisplay],
 * [tokenAmount]) are pre-formatted here so consumers (the Compose UI's commonMain,
 * the IPC JSON writer) never need BigInteger/BigDecimal.
 */
data class TxSummary(
    val blockNumber: Long,
    val txIndex: Int,
    val hash: String,             // 0x-hex keccak256(rawTx)
    val from: String?,            // 0x-hex recovered sender, null if recovery failed
    val to: String?,              // 0x-hex, null for contract creation
    val kind: TxKind,
    val ethWei: String,           // decimal wei carried by the tx (always present)
    val ethDisplay: String,       // "1.25" — ETH, 6 dp truncated, trailing zeros trimmed
    val tokenSymbol: String?,     // ERC20_TRANSFER only
    val tokenAmount: String?,     // decimals-adjusted decimal string, ERC20_TRANSFER only
    val tokenRecipient: String?,  // decoded transfer destination, ERC20_TRANSFER only
    val calldataBytes: Int,       // input size (0 for plain transfers)
    val selector: String?,        // "0xa9059cbb"-style 4-byte selector, null if input < 4 bytes
)

/**
 * Pure classification of raw transaction bytes into a [TxSummary] via
 * [EthTxDecoder] (which recovers the sender from the signature). No I/O, no trust:
 * the caller decides how verified the bytes are.
 */
object TxClassifier {

    private const val TRANSFER_SELECTOR = "a9059cbb"       // transfer(address,uint256)
    private const val TRANSFER_FROM_SELECTOR = "23b872dd"  // transferFrom(address,address,uint256)

    /** Classify raw tx bytes; null when the tx is undecodable (unknown type / malformed). */
    fun classify(blockNumber: Long, txIndex: Int, rawTx: Bytes): TxSummary? {
        val tx = EthTxDecoder.decode(rawTx) ?: return null
        val hash = "0x" + Hash.keccak256(rawTx).toUnprefixedHexString()
        val from = tx.from()?.let { "0x" + it.toUnprefixedHexString() }
        val to = tx.to()?.takeIf { !it.isEmpty }?.let { "0x" + it.toUnprefixedHexString() }
        val input = tx.input() ?: Bytes.EMPTY
        val value = tx.value() ?: BigInteger.ZERO
        val selector =
            if (input.size() >= 4) "0x" + input.slice(0, 4).toUnprefixedHexString() else null

        val kind: TxKind
        var tokenSymbol: String? = null
        var tokenAmount: String? = null
        var tokenRecipient: String? = null

        val token = WellKnownTokens.lookup(to)
        if (to == null) {
            kind = TxKind.CONTRACT_CREATION
        } else if (input.isEmpty) {
            kind = TxKind.ETH_TRANSFER
        } else if (token != null && isErc20Transfer(input)) {
            kind = TxKind.ERC20_TRANSFER
            tokenSymbol = token.symbol
            when (selector) {
                "0x$TRANSFER_SELECTOR" -> {
                    tokenRecipient = wordAsAddress(input, 0)
                    tokenAmount = formatUnits(wordAsUint(input, 1), token.decimals)
                }
                "0x$TRANSFER_FROM_SELECTOR" -> {
                    tokenRecipient = wordAsAddress(input, 1)
                    tokenAmount = formatUnits(wordAsUint(input, 2), token.decimals)
                }
            }
        } else {
            kind = TxKind.CONTRACT_CALL
        }

        return TxSummary(
            blockNumber = blockNumber,
            txIndex = txIndex,
            hash = hash,
            from = from,
            to = to,
            kind = kind,
            ethWei = value.toString(),
            ethDisplay = formatEth(value),
            tokenSymbol = tokenSymbol,
            tokenAmount = tokenAmount,
            tokenRecipient = tokenRecipient,
            calldataBytes = input.size(),
            selector = selector,
        )
    }

    /** Exact-length check: a truncated or extended payload is NOT a plain transfer. */
    private fun isErc20Transfer(input: Bytes): Boolean {
        if (input.size() < 4) return false
        return when (input.slice(0, 4).toUnprefixedHexString()) {
            TRANSFER_SELECTOR -> input.size() == 4 + 32 + 32
            TRANSFER_FROM_SELECTOR -> input.size() == 4 + 32 + 32 + 32
            else -> false
        }
    }

    /** 32-byte ABI word [i] read as an address (last 20 bytes). */
    private fun wordAsAddress(input: Bytes, i: Int): String =
        "0x" + input.slice(4 + i * 32 + 12, 20).toUnprefixedHexString()

    /** 32-byte ABI word [i] read as an unsigned integer. */
    private fun wordAsUint(input: Bytes, i: Int): BigInteger =
        BigInteger(1, input.slice(4 + i * 32, 32).toArrayUnsafe())

    /** Wei → ETH, 6 dp truncated (matches the UI's formatEth). */
    fun formatEth(wei: BigInteger): String = formatUnits(wei, 18, scale = 6)

    /**
     * Integer token units → human decimal string, truncated. Full [decimals] precision
     * would print USDC dust as 0.000001-noise; 6 fractional digits is plenty for a
     * succinct row, and trailing zeros beyond two are trimmed.
     */
    fun formatUnits(amount: BigInteger, decimals: Int, scale: Int = 6): String {
        val value = BigDecimal(amount, decimals)
        val truncated = value.setScale(minOf(decimals, scale), RoundingMode.DOWN)
        // Keep at least 2 fractional digits ("1250.00"), trim the rest ("0.100000" → "0.10").
        val plain = truncated.toPlainString()
        if (!plain.contains('.')) return plain
        return plain.trimEnd('0').let {
            val frac = it.substringAfter('.').length
            when {
                it.endsWith('.') -> it + "00"
                frac < 2 -> it + "0".repeat(2 - frac)
                else -> it
            }
        }
    }
}
