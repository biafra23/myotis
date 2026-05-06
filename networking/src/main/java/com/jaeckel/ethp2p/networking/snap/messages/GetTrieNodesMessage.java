package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 GetTrieNodes request (absolute message code 0x26).
 *
 * <p>Wire format:
 * {@code [reqId, stateRoot, [[accountPath, storagePath, storagePath, ...], ...], responseBytes]}
 *
 * <p>Each {@link PathSet} requests one or more trie nodes belonging to a
 * single account. The first byte string in a set is the path to a node in
 * the world state trie (typically the {@code keccak256(address)} of the
 * account being queried, in raw 32-byte form for a leaf request); each
 * subsequent byte string is a path inside that account's storage trie.
 *
 * <p>For the per-account / per-slot fetches Phase 1 issues, paths are
 * always full 32-byte keccak256 hashes — leaf requests. Internal-node
 * requests would use shorter byte strings, but we don't need them.
 */
public final class GetTrieNodesMessage {

    private GetTrieNodesMessage() {}

    /**
     * One account's path request. {@code accountPath} is required;
     * {@code storagePaths} may be empty (account-only fetch) or carry one
     * or more storage trie paths within that account.
     */
    public record PathSet(Bytes accountPath, List<Bytes> storagePaths) {

        /** Convenience: build a leaf-account-only request from a 32-byte address hash. */
        public static PathSet account(Bytes32 accountHash) {
            return new PathSet(accountHash, List.of());
        }

        /** Convenience: build a single-storage-slot request. */
        public static PathSet storageSlot(Bytes32 accountHash, Bytes32 slotHash) {
            return new PathSet(accountHash, List.of(slotHash));
        }
    }

    public record DecodeResult(long requestId, Bytes32 stateRoot, List<PathSet> paths, long responseBytes) {}

    /** Encode a GetTrieNodes request. */
    public static byte[] encode(long requestId, Bytes32 stateRoot,
                                List<PathSet> paths, long responseBytes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeValue(stateRoot);
            w.writeList(setListWriter -> {
                for (PathSet set : paths) {
                    setListWriter.writeList(setWriter -> {
                        setWriter.writeValue(set.accountPath());
                        for (Bytes p : set.storagePaths()) setWriter.writeValue(p);
                    });
                }
            });
            w.writeLong(responseBytes);
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<PathSet> paths = new ArrayList<>();
        long[] reqId = {0L};
        Bytes32[] root = {Bytes32.ZERO};
        long[] respBytes = {0L};

        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            root[0] = Bytes32.wrap(reader.readValue());
            reader.readList(setListReader -> {
                while (!setListReader.isComplete()) {
                    setListReader.readList(setReader -> {
                        Bytes accountPath = setReader.readValue();
                        List<Bytes> storagePaths = new ArrayList<>();
                        while (!setReader.isComplete()) {
                            storagePaths.add(setReader.readValue());
                        }
                        paths.add(new PathSet(accountPath, storagePaths));
                        return null;
                    });
                }
                return null;
            });
            respBytes[0] = reader.readLong();
            return null;
        });

        return new DecodeResult(reqId[0], root[0], paths, respBytes[0]);
    }
}
