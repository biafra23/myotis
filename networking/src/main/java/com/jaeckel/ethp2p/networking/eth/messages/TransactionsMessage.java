package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;

import java.util.ArrayList;
import java.util.List;

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

    /** Encode one or more raw signed transactions into a Transactions message.
     *  Null/empty elements (and a null vararg) are skipped, yielding an empty list. */
    public static byte[] encode(byte[]... rawTxs) {
        return RLP.encodeList(writer -> {
            if (rawTxs == null) return;
            for (byte[] rawTx : rawTxs) {
                if (rawTx == null || rawTx.length == 0) continue;
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
        return rawTx != null && rawTx.length > 0 && (rawTx[0] & 0xff) <= 0x7f;
    }

    /**
     * Decode the {@code keccak256} hash of each transaction in an inbound Transactions
     * message, without fully decoding the tx fields. A tx's hash is keccak over its
     * <em>canonical</em> bytes: for a legacy tx that's the RLP list itself; for a typed
     * (EIP-2718) tx it's the {@code type || payload} byte string carried inside the
     * outer list. Used only to match the firehose against our own broadcast hashes, so
     * it caps at {@code max} hashes and treats any malformed input as "no hashes"
     * (gossip is best-effort — a bad peer message must never throw on the event loop).
     */
    public static List<Bytes32> hashes(byte[] payload, int max) {
        List<Bytes32> out = new ArrayList<>();
        if (payload == null || payload.length == 0 || max <= 0) return out;
        try {
            RLP.decodeList(Bytes.wrap(payload), reader -> {
                while (!reader.isComplete() && out.size() < max) {
                    if (reader.nextIsList()) {
                        // legacy tx: hash its canonical RLP-list encoding
                        out.add(Hash.keccak256(rawList(reader)));
                    } else {
                        // typed tx: byte string of type||payload — hash the inner bytes
                        out.add(Hash.keccak256(reader.readValue()));
                    }
                }
                return null;
            });
        } catch (Exception e) {
            // Best-effort: return whatever we decoded before the malformed element.
        }
        return out;
    }

    /** Re-encode the canonical RLP of the (possibly nested) list at the reader head so
     *  it can be hashed. Mirrors the helper in {@code EthTxDecoder}. */
    private static Bytes rawList(RLPReader reader) {
        List<Bytes> children = new ArrayList<>();
        reader.readList(inner -> {
            while (!inner.isComplete()) {
                if (inner.nextIsList()) children.add(rawList(inner));
                else children.add(RLP.encodeValue(inner.readValue()));
            }
            return null;
        });
        return RLP.encodeList(w -> children.forEach(w::writeRLP));
    }
}
