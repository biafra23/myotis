package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;

/**
 * The fee-relevant fields of an Ethereum transaction (EIP-2718 typed or legacy),
 * decoded from the raw tx bytes carried in an eth BlockBodies response.
 *
 * <p>Wire layouts (only the prefix up to the fee fields matters here):
 * <ul>
 *   <li>legacy:   {@code rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])}</li>
 *   <li>type 1 (EIP-2930): {@code 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, ...])}</li>
 *   <li>type 2 (EIP-1559): {@code 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, ...])}</li>
 *   <li>type 3 (EIP-4844): same fee prefix as type 2</li>
 *   <li>type 4 (EIP-7702): same fee prefix as type 2</li>
 * </ul>
 *
 * <p>Pure decoder over bytes the caller has ALREADY verified against a trusted
 * {@code transactionsRoot} (see OrderedTrieRoot) — it does no verification itself.
 */
public record TxFeeFields(int type,
                          BigInteger gasPrice,             // legacy / type-1, else null
                          BigInteger maxPriorityFeePerGas, // type >= 2, else null
                          BigInteger maxFeePerGas) {       // type >= 2, else null

    /**
     * The priority fee per gas this tx actually pays on a block with {@code baseFee}:
     * {@code min(maxPriorityFeePerGas, maxFeePerGas - baseFee)} for 1559-style txs,
     * {@code gasPrice - baseFee} for legacy/2930. Floored at zero (a legacy tx whose
     * gasPrice sits below baseFee can't be included, but guard against bad data).
     */
    public BigInteger effectiveTip(BigInteger baseFee) {
        BigInteger tip;
        if (type >= 2) {
            tip = maxFeePerGas.subtract(baseFee).min(maxPriorityFeePerGas);
        } else {
            tip = gasPrice.subtract(baseFee);
        }
        return tip.max(BigInteger.ZERO);
    }

    /** Decode the fee fields from raw tx bytes, or null if the tx can't be parsed. */
    public static TxFeeFields decode(Bytes raw) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            int first = raw.get(0) & 0xFF;
            if (first >= 0xc0) {                       // RLP list → legacy tx
                return RLP.decodeList(raw, r -> {
                    r.readValue();                     // nonce
                    BigInteger gasPrice = toBigInt(r.readValue());
                    return new TxFeeFields(0, gasPrice, null, null);
                });
            }
            int type = first;
            Bytes payload = raw.slice(1);
            if (type == 1) {                           // EIP-2930: gasPrice model
                return RLP.decodeList(payload, r -> {
                    r.readValue();                     // chainId
                    r.readValue();                     // nonce
                    BigInteger gasPrice = toBigInt(r.readValue());
                    return new TxFeeFields(1, gasPrice, null, null);
                });
            }
            if (type >= 2 && type <= 4) {              // 1559 / 4844 / 7702: same prefix
                final int t = type;
                return RLP.decodeList(payload, r -> {
                    r.readValue();                     // chainId
                    r.readValue();                     // nonce
                    BigInteger maxPriority = toBigInt(r.readValue());
                    BigInteger maxFee = toBigInt(r.readValue());
                    return new TxFeeFields(t, null, maxPriority, maxFee);
                });
            }
            return null;                               // unknown future type
        } catch (Exception e) {
            return null;
        }
    }

    private static BigInteger toBigInt(Bytes b) {
        return b.isEmpty() ? BigInteger.ZERO : b.toUnsignedBigInteger();
    }
}
