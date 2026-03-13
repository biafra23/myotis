package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 AccountRange response (absolute message code 0x22).
 *
 * Wire format:
 *   [reqId, [[accountHash(32B), slimAccountBody], ...], [proofNode, ...]]
 *
 * slimAccountBody is either:
 *   - a raw-bytes value containing the RLP encoding of [nonce, balance, storageRoot, codeHash]
 *     (go-ethereum style: AccountData.Body is []byte)
 *   - a nested RLP list [nonce, balance, storageRoot, codeHash]
 *     (some clients encode the struct directly)
 *
 * In the "slim" encoding, storageRoot and codeHash may be empty (nil) when they
 * equal the default values (emptyRoot / emptyCodeHash).
 *
 * The proof list is parsed but discarded — sufficient for balance/nonce lookups.
 */
public final class AccountRangeMessage {

    private AccountRangeMessage() {}

    /** Default empty trie root: keccak256(RLP("")) */
    private static final Bytes32 EMPTY_ROOT = Bytes32.fromHexString(
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

    /** Default empty code hash: keccak256("") */
    private static final Bytes32 EMPTY_CODE_HASH = Bytes32.fromHexString(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    public record AccountData(
        Bytes32 accountHash,
        long nonce,
        BigInteger balance,
        Bytes32 storageRoot,
        Bytes32 codeHash
    ) {}

    public record DecodeResult(long requestId, List<AccountData> accounts, List<Bytes> proof,
                                   Bytes32 stateRoot, long blockNumber) {

        /** Create a DecodeResult without a state root (decoded from wire). */
        public DecodeResult(long requestId, List<AccountData> accounts, List<Bytes> proof) {
            this(requestId, accounts, proof, null, 0);
        }

        /** Return a copy with the given state root and block number attached. */
        public DecodeResult withStateRoot(Bytes32 root, long blockNum) {
            return new DecodeResult(requestId, accounts, proof, root, blockNum);
        }
    }

    /**
     * Extract just the request ID from the raw RLP without fully decoding.
     * Used to complete pending futures even when full decode fails.
     */
    public static long extractRequestId(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> reader.readLong());
    }

    /**
     * Encode an empty AccountRange response (no accounts, no proof).
     * This is the proper way to decline serving snap data.
     */
    public static byte[] encodeEmpty(long requestId) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(accounts -> {});  // empty accounts list
            w.writeList(proof -> {});      // empty proof list
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<AccountData> accounts = new ArrayList<>();
        List<Bytes> proof = new ArrayList<>();
        long[] reqIdHolder = {0L};

        RLP.decodeList(Bytes.wrap(rlp), outerReader -> {
            reqIdHolder[0] = outerReader.readLong();

            // Accounts field: either a list [[hash, body], ...] or a value (empty bytes for no accounts)
            if (!outerReader.isComplete() && outerReader.nextIsList()) {
                outerReader.readList(accountsReader -> {
                    while (!accountsReader.isComplete()) {
                        accountsReader.readList(pairReader -> {
                            Bytes32 hash = Bytes32.wrap(pairReader.readValue());
                            decodeAccountBody(pairReader, hash, accounts);
                            return null;
                        });
                    }
                    return null;
                });
            } else if (!outerReader.isComplete()) {
                // Empty accounts encoded as a value (e.g. 0x80) — skip it
                outerReader.readValue();
            }

            // Proof list: Merkle-Patricia trie nodes proving inclusion in the state trie
            if (!outerReader.isComplete()) {
                if (outerReader.nextIsList()) {
                    outerReader.readList(proofReader -> {
                        while (!proofReader.isComplete()) {
                            proof.add(proofReader.readValue());
                        }
                        return null;
                    });
                } else {
                    outerReader.readValue(); // empty proof encoded as value
                }
            }
            return null;
        });

        return new DecodeResult(reqIdHolder[0], accounts, proof);
    }

    /**
     * Decode the account body from the pair reader.
     * Handles both formats:
     *   - value (bytes containing RLP of [nonce, balance, root, codeHash])
     *   - nested list [nonce, balance, root, codeHash]
     */
    private static void decodeAccountBody(org.apache.tuweni.rlp.RLPReader pairReader,
                                           Bytes32 hash, List<AccountData> accounts) {
        long[] nonce = {0L};
        BigInteger[] balance = {BigInteger.ZERO};
        Bytes32[] storageRoot = {EMPTY_ROOT};
        Bytes32[] codeHash = {EMPTY_CODE_HASH};

        if (pairReader.nextIsList()) {
            // Inline list format: [nonce, balance, root, codeHash]
            pairReader.readList(ar -> {
                decodeSlimAccountFields(ar, nonce, balance, storageRoot, codeHash);
                return null;
            });
        } else {
            // Bytes format: value containing RLP of [nonce, balance, root, codeHash]
            Bytes accountRlpBytes = pairReader.readValue();
            RLP.decodeList(accountRlpBytes, ar -> {
                decodeSlimAccountFields(ar, nonce, balance, storageRoot, codeHash);
                return null;
            });
        }

        accounts.add(new AccountData(hash, nonce[0], balance[0], storageRoot[0], codeHash[0]));
    }

    /**
     * Decode slim account fields: [nonce, balance, storageRoot?, codeHash?]
     * In the "slim" encoding, storageRoot and codeHash may be empty/nil
     * when they equal the defaults (emptyRoot / emptyCodeHash).
     */
    private static void decodeSlimAccountFields(org.apache.tuweni.rlp.RLPReader ar,
                                                 long[] nonce, BigInteger[] balance,
                                                 Bytes32[] storageRoot, Bytes32[] codeHash) {
        if (!ar.isComplete()) nonce[0] = ar.readLong();
        if (!ar.isComplete()) balance[0] = ar.readBigInteger();
        if (!ar.isComplete()) {
            Bytes root = ar.readValue();
            storageRoot[0] = root.isEmpty() ? EMPTY_ROOT : Bytes32.wrap(root);
        }
        if (!ar.isComplete()) {
            Bytes code = ar.readValue();
            codeHash[0] = code.isEmpty() ? EMPTY_CODE_HASH : Bytes32.wrap(code);
        }
    }
}
