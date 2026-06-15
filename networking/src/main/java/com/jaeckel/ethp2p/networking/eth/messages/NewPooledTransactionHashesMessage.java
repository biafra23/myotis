package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * eth/NewPooledTransactionHashes (message code 0x18) — a peer announcing tx hashes it
 * has in its pool, so we can request the bodies we don't yet hold.
 *
 * <p>We never request bodies (a light wallet keeps no mempool). We decode this only to
 * match the announced hashes against our <em>own</em> just-broadcast transactions — to
 * see them propagating back across the network.
 *
 * <p>The wire format changed at eth/68 (EIP-5793):
 * <ul>
 *   <li><b>eth/66, eth/67</b> — a flat list {@code [hash_0, hash_1, ...]}.</li>
 *   <li><b>eth/68+</b> — {@code [types, sizes, hashes]}: a byte string of one type
 *       per tx, a list of sizes, then the list of 32-byte hashes.</li>
 * </ul>
 */
public final class NewPooledTransactionHashesMessage {

    public static final int CODE = 0x18;

    private NewPooledTransactionHashesMessage() {}

    /**
     * Decode the announced 32-byte tx hashes, picking the wire layout from {@code
     * ethVersion}. Caps at {@code max} hashes and returns whatever decoded before any
     * malformed element — gossip is best-effort and must never throw on the event loop.
     */
    public static List<Bytes32> hashes(byte[] payload, int ethVersion, int max) {
        List<Bytes32> out = new ArrayList<>();
        if (payload == null || payload.length == 0 || max <= 0) return out;
        try {
            Bytes b = Bytes.wrap(payload);
            if (ethVersion >= 68) {
                RLP.decodeList(b, reader -> {
                    reader.readValue();                 // types — one byte per tx, skip
                    reader.readList(sz -> {             // sizes — skip
                        while (!sz.isComplete()) sz.readValue();
                        return null;
                    });
                    reader.readList(hr -> {             // hashes
                        while (!hr.isComplete()) {
                            Bytes h = hr.readValue();
                            if (out.size() < max && h.size() == 32) out.add(Bytes32.wrap(h));
                        }
                        return null;
                    });
                    return null;
                });
            } else {
                RLP.decodeList(b, reader -> {           // flat [hash, ...]
                    while (!reader.isComplete()) {
                        Bytes h = reader.readValue();
                        if (out.size() < max && h.size() == 32) out.add(Bytes32.wrap(h));
                    }
                    return null;
                });
            }
        } catch (Exception e) {
            // Best-effort: return whatever decoded before the malformed element.
        }
        return out;
    }
}
