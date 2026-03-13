package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 StorageRanges response.
 *
 * Wire format:
 *   [reqId, [[slotHash, slotValue], ...], [proofNode, ...]]
 *
 * The slots list is actually nested: [[slots-for-account-0], [slots-for-account-1], ...]
 * Since we always query a single account, we read the first (and only) inner list.
 *
 * Each slot pair: [slotHash (32B), slotRlpValue (variable)]
 */
public final class StorageRangesMessage {

    private StorageRangesMessage() {}

    public record StorageData(Bytes32 slotHash, Bytes slotValue) {}

    public record DecodeResult(long requestId, List<StorageData> slots, List<Bytes> proof,
                               Bytes32 storageRoot) {

        public DecodeResult(long requestId, List<StorageData> slots, List<Bytes> proof) {
            this(requestId, slots, proof, null);
        }

        public DecodeResult withStorageRoot(Bytes32 root) {
            return new DecodeResult(requestId, slots, proof, root);
        }
    }

    /**
     * Extract just the request ID from the raw RLP without fully decoding.
     */
    public static long extractRequestId(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> reader.readLong());
    }

    /**
     * Encode an empty StorageRanges response.
     */
    public static byte[] encodeEmpty(long requestId) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(slots -> {});  // empty slots list
            w.writeList(proof -> {});  // empty proof list
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<StorageData> slots = new ArrayList<>();
        List<Bytes> proof = new ArrayList<>();
        long[] reqIdHolder = {0L};

        RLP.decodeList(Bytes.wrap(rlp), outerReader -> {
            reqIdHolder[0] = outerReader.readLong();

            // Slots field: [[slot-pairs-for-account-0], ...]
            if (!outerReader.isComplete() && outerReader.nextIsList()) {
                outerReader.readList(accountSlotsReader -> {
                    // Read slots for the first (and typically only) account
                    if (!accountSlotsReader.isComplete() && accountSlotsReader.nextIsList()) {
                        accountSlotsReader.readList(slotsReader -> {
                            while (!slotsReader.isComplete()) {
                                slotsReader.readList(pairReader -> {
                                    Bytes32 hash = Bytes32.wrap(pairReader.readValue());
                                    // The trie stores rlp(uint256); the snap wire wraps
                                    // that in another RLP bytes item.  readValue() strips
                                    // the outer layer, leaving rlp(uint256).  Strip the
                                    // inner RLP header so slotValue is the raw integer.
                                    Bytes raw = pairReader.readValue();
                                    Bytes value = stripRlpIntegerHeader(raw);
                                    slots.add(new StorageData(hash, value));
                                    return null;
                                });
                            }
                            return null;
                        });
                    }
                    // Skip remaining accounts (we only query one)
                    while (!accountSlotsReader.isComplete()) {
                        if (accountSlotsReader.nextIsList()) {
                            accountSlotsReader.readList(skip -> {
                                while (!skip.isComplete()) skip.readValue();
                                return null;
                            });
                        } else {
                            accountSlotsReader.readValue();
                        }
                    }
                    return null;
                });
            } else if (!outerReader.isComplete()) {
                outerReader.readValue(); // empty slots
            }

            // Proof list
            if (!outerReader.isComplete()) {
                if (outerReader.nextIsList()) {
                    outerReader.readList(proofReader -> {
                        while (!proofReader.isComplete()) {
                            proof.add(proofReader.readValue());
                        }
                        return null;
                    });
                } else {
                    outerReader.readValue(); // empty proof
                }
            }
            return null;
        });

        return new DecodeResult(reqIdHolder[0], slots, proof);
    }

    /**
     * Strip the RLP header from an RLP-encoded integer/bytes value.
     * Storage trie values are stored as {@code rlp(trimmed_uint256)}.
     * This returns the raw payload bytes without the RLP length prefix.
     */
    private static Bytes stripRlpIntegerHeader(Bytes raw) {
        if (raw.isEmpty()) return raw;
        int first = raw.get(0) & 0xFF;
        if (first < 0x80) {
            // Single byte value — the byte IS the value
            return raw;
        } else if (first <= 0xB7) {
            // Short string: payload length = first - 0x80, starts at offset 1
            int len = first - 0x80;
            if (len == 0) return Bytes.EMPTY;
            return raw.slice(1, len);
        } else {
            // Long string (> 55 bytes) — unlikely for uint256 but handle anyway
            int lenLen = first - 0xB7;
            return raw.slice(1 + lenLen);
        }
    }
}
