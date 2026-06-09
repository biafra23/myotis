package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/Transactions (message code 0x12) — mempool broadcast.
 *
 * <p>Wire format (eth/66–69): {@code [tx_1, tx_2, ...]}. Each {@code tx_i} is a
 * <em>complete signed transaction</em> exactly as a wallet hands it to
 * {@code eth_sendRawTransaction}:
 * <ul>
 *   <li><b>legacy</b> — the raw bytes are already an RLP list
 *       {@code [nonce, gasPrice, ...]}; they nest into the outer list verbatim
 *       (inserted as pre-encoded RLP, not re-wrapped).</li>
 *   <li><b>typed (EIP-2718)</b> — the raw bytes are {@code type || payload}
 *       (first byte ≤ 0x7f); per EIP-2718 they ride inside the outer list as an
 *       RLP <em>byte string</em>.</li>
 * </ul>
 *
 * <p>We only ever <em>send</em> this (to gossip a user's signed tx); inbound
 * Transactions from peers are mempool noise we ignore.
 */
public final class TransactionsMessage {

    public static final int CODE = 0x12;

    private TransactionsMessage() {}

    /** Encode one or more raw signed transactions into a Transactions message. */
    public static byte[] encode(byte[]... rawTxs) {
        return RLP.encodeList(writer -> {
            for (byte[] rawTx : rawTxs) {
                Bytes tx = Bytes.wrap(rawTx);
                if (isTyped(rawTx)) {
                    // EIP-2718 typed tx: carried as an RLP byte string.
                    writer.writeValue(tx);
                } else {
                    // Legacy tx: already an RLP list — embed its bytes directly.
                    writer.writeRLP(tx);
                }
            }
        }).toArrayUnsafe();
    }

    /**
     * A transaction is EIP-2718 "typed" when its first byte is a transaction-type
     * id in {@code [0x00, 0x7f]}; a legacy transaction starts with an RLP list
     * header ({@code >= 0xc0}). (0x80–0xbf — an RLP string header — is never a
     * valid first byte of a transaction.)
     */
    private static boolean isTyped(byte[] rawTx) {
        return rawTx.length > 0 && (rawTx[0] & 0xff) <= 0x7f;
    }
}
