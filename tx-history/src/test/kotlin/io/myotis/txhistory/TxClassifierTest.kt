package io.myotis.txhistory

import org.apache.tuweni.bytes.Bytes
import org.apache.tuweni.crypto.Hash
import org.apache.tuweni.crypto.SECP256K1
import org.apache.tuweni.rlp.RLP
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * Classification matrix over synthesized signed EIP-1559 transactions (same sign→decode
 * round-trip technique as networking's EthTxDecoderTest, so sender recovery is exercised
 * for real instead of stubbed).
 */
class TxClassifierTest {

    companion object {
        init {
            java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }

        private val KP = SECP256K1.KeyPair.random()
        private val EXPECTED_FROM = "0x" +
            Hash.keccak256(KP.publicKey().bytes()).slice(12, 20).toUnprefixedHexString()

        private const val USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        private val RECIPIENT = Bytes.fromHexString("0x308686553a1eac2fe721ac8b814de638975a276e")

        /** Signed type-2 raw tx with the given to (empty = creation), value, and calldata. */
        fun signed1559(to: Bytes, value: BigInteger, input: Bytes): Bytes {
            val signing = Bytes.concatenate(Bytes.of(2), RLP.encodeList { w ->
                w.writeLong(1); w.writeLong(7)
                w.writeBigInteger(BigInteger.valueOf(1_000_000_000L))
                w.writeBigInteger(BigInteger.valueOf(30_000_000_000L))
                w.writeLong(120_000); w.writeValue(to)
                w.writeBigInteger(value); w.writeValue(input)
                w.writeList { }
            })
            val sig = SECP256K1.signHashed(Hash.keccak256(signing), KP)
            return Bytes.concatenate(Bytes.of(2), RLP.encodeList { w ->
                w.writeLong(1); w.writeLong(7)
                w.writeBigInteger(BigInteger.valueOf(1_000_000_000L))
                w.writeBigInteger(BigInteger.valueOf(30_000_000_000L))
                w.writeLong(120_000); w.writeValue(to)
                w.writeBigInteger(value); w.writeValue(input)
                w.writeList { }
                w.writeInt(sig.v().toInt())
                w.writeBigInteger(sig.r()); w.writeBigInteger(sig.s())
            })
        }

        /** A value left-padded to a 32-byte ABI word. */
        fun word(b: Bytes): Bytes = org.apache.tuweni.bytes.Bytes32.leftPad(b)

        fun word(v: BigInteger): Bytes = word(Bytes.wrap(v.toByteArray()).trimLeadingZeros())

        /** transfer(address,uint256) calldata. */
        fun transferCalldata(recipient: Bytes, amount: BigInteger): Bytes = Bytes.concatenate(
            Bytes.fromHexString("0xa9059cbb"), word(recipient), word(amount))
    }

    @Test
    fun plainEthTransfer() {
        val oneEth25 = BigInteger("1250000000000000000") // 1.25 ETH
        val raw = signed1559(RECIPIENT, oneEth25, Bytes.EMPTY)
        val s = TxClassifier.classify(21_000_000, 3, raw)
        assertNotNull(s)
        assertEquals(TxKind.ETH_TRANSFER, s!!.kind)
        assertEquals(EXPECTED_FROM, s.from)
        assertEquals("0x" + RECIPIENT.toUnprefixedHexString(), s.to)
        assertEquals("1250000000000000000", s.ethWei)
        assertEquals("1.25", s.ethDisplay)
        assertEquals(0, s.calldataBytes)
        assertNull(s.selector)
        assertNull(s.tokenSymbol)
        assertEquals(21_000_000, s.blockNumber)
        assertEquals(3, s.txIndex)
        assertEquals("0x" + Hash.keccak256(raw).toUnprefixedHexString(), s.hash)
    }

    @Test
    fun usdcTransferDecodesRecipientAndSixDecimalAmount() {
        val amount = BigInteger.valueOf(1_250_500_000L) // 1250.50 USDC (6 dp)
        val raw = signed1559(
            Bytes.fromHexString(USDC), BigInteger.ZERO, transferCalldata(RECIPIENT, amount))
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.ERC20_TRANSFER, s.kind)
        assertEquals("USDC", s.tokenSymbol)
        assertEquals("1250.50", s.tokenAmount)
        assertEquals("0x" + RECIPIENT.toUnprefixedHexString(), s.tokenRecipient)
        assertEquals(USDC, s.to)
        assertEquals("0xa9059cbb", s.selector)
    }

    @Test
    fun usdcTransferFromDecodesSecondArgAsRecipient() {
        val amount = BigInteger.valueOf(5_000_000L) // 5 USDC
        val holder = Bytes.fromHexString("0x1a5f9352af8af974bfc03399e3767df6370d82e4")
        val calldata = Bytes.concatenate(
            Bytes.fromHexString("0x23b872dd"), word(holder), word(RECIPIENT), word(amount))
        val raw = signed1559(Bytes.fromHexString(USDC), BigInteger.ZERO, calldata)
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.ERC20_TRANSFER, s.kind)
        assertEquals("USDC", s.tokenSymbol)
        assertEquals("5.00", s.tokenAmount)
        assertEquals("0x" + RECIPIENT.toUnprefixedHexString(), s.tokenRecipient)
    }

    @Test
    fun transferToUnknownTokenStaysContractCall() {
        val unknownToken = Bytes.fromHexString("0x1111111111111111111111111111111111111111")
        val raw = signed1559(
            unknownToken, BigInteger.ZERO, transferCalldata(RECIPIENT, BigInteger.TEN))
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.CONTRACT_CALL, s.kind)
        assertNull(s.tokenSymbol)
        assertEquals(68, s.calldataBytes)
        assertEquals("0xa9059cbb", s.selector)
    }

    @Test
    fun truncatedTransferCalldataStaysContractCallNotCrash() {
        val truncated = transferCalldata(RECIPIENT, BigInteger.TEN).slice(0, 67)
        val raw = signed1559(Bytes.fromHexString(USDC), BigInteger.ZERO, truncated)
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.CONTRACT_CALL, s.kind)
        assertNull(s.tokenAmount)
        assertEquals(67, s.calldataBytes)
    }

    @Test
    fun contractCreationHasNullTo() {
        val raw = signed1559(Bytes.EMPTY, BigInteger.ZERO, Bytes.fromHexString("0x60806040"))
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.CONTRACT_CREATION, s.kind)
        assertNull(s.to)
        assertEquals(4, s.calldataBytes)
    }

    @Test
    fun genericCallReportsCalldataSizeAndSelector() {
        val calldata = Bytes.concatenate(
            Bytes.fromHexString("0x38ed1739"), Bytes.wrap(ByteArray(128)))
        val raw = signed1559(RECIPIENT, BigInteger.ZERO, calldata)
        val s = TxClassifier.classify(1, 0, raw)!!
        assertEquals(TxKind.CONTRACT_CALL, s.kind)
        assertEquals(132, s.calldataBytes)
        assertEquals("0x38ed1739", s.selector)
    }

    @Test
    fun undecodableBytesReturnNull() {
        assertNull(TxClassifier.classify(1, 0, Bytes.fromHexString("0x05deadbeef")))
    }

    @Test
    fun zeroValueFormatsAsZero() {
        assertEquals("0.00", TxClassifier.formatEth(BigInteger.ZERO))
    }

    @Test
    fun formatUnitsTruncatesAndTrims() {
        // 0.1234567 truncated to 6 dp = 0.123456
        assertEquals("0.123456", TxClassifier.formatUnits(BigInteger("123456700000000000"), 18))
        // whole-number amounts keep two decimals
        assertEquals("100.00", TxClassifier.formatUnits(BigInteger("100000000"), 6))
        // tiny USDC dust survives (6 dp token, scale 6)
        assertEquals("0.000001", TxClassifier.formatUnits(BigInteger.ONE, 6))
    }
}
