package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;

/**
 * Decodes a raw Ethereum transaction (EIP-2718 typed or legacy) into the fields an
 * {@code eth_getTransactionByHash} JSON response needs, including the sender address
 * recovered from the signature. Pure decoder over bytes the caller has either signed-
 * and-broadcast itself or verified against a block's {@code transactionsRoot}; it does
 * no verification of its own (the sender recovery is just ECDSA over the signing hash —
 * a malformed signature yields a null {@code from}, not a trust hole).
 *
 * <p>Supports legacy (incl. EIP-155), EIP-2930 (type 1), EIP-1559 (type 2),
 * EIP-4844 (type 3), and EIP-7702 (type 4). Unknown types decode to null.
 */
public final class EthTxDecoder {

    private EthTxDecoder() {}

    public record DecodedTx(
            int type,                       // 0 legacy, 1 2930, 2 1559, 3 4844, 4 7702
            Long chainId,                   // null for pre-155 legacy
            long nonce,
            BigInteger gasPrice,            // legacy / 2930; null for 1559+
            BigInteger maxPriorityFeePerGas,// 1559+; null otherwise
            BigInteger maxFeePerGas,        // 1559+; null otherwise
            long gas,
            Bytes to,                       // 20 bytes, or empty for contract creation
            BigInteger value,
            Bytes input,
            BigInteger v, BigInteger r, BigInteger s,
            Bytes from) {                   // recovered sender (20 bytes), or null
    }

    /** Decode raw tx bytes; null if the type is unknown or decoding fails. */
    public static DecodedTx decode(Bytes raw) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            int first = raw.get(0) & 0xFF;
            if (first >= 0xc0) return decodeLegacy(raw);
            return switch (first) {
                case 1 -> decode2930(raw);
                case 2 -> decode1559(raw);
                case 3 -> decode4844(raw);
                case 4 -> decode7702(raw);
                default -> null;
            };
        } catch (Exception e) {
            return null;
        }
    }

    // legacy: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
    private static DecodedTx decodeLegacy(Bytes raw) {
        return RLP.decodeList(raw, r -> {
            long nonce = toLong(r.readValue());
            BigInteger gasPrice = toBig(r.readValue());
            long gas = toLong(r.readValue());
            Bytes to = r.readValue();
            BigInteger value = toBig(r.readValue());
            Bytes input = r.readValue();
            BigInteger v = toBig(r.readValue());
            BigInteger sigR = toBig(r.readValue());
            BigInteger sigS = toBig(r.readValue());

            // v as a long, not int: legacy v = 2*chainId + 35, and real chain ids
            // exceed 2^31 (an intValueExact here would fail the whole decode). A v
            // beyond long is malformed → whole decode fails (the Rust decoder's
            // u64 bound, mirrored).
            long vl = v.longValueExact();
            Long chainId = null;
            Bytes signing = null;
            int recId = -1;
            if (vl == 27 || vl == 28) {
                recId = (int) (vl - 27);        // pre-155: sign over the 6 tx fields
                signing = RLP.encodeList(w -> {
                    w.writeLong(nonce); w.writeBigInteger(gasPrice); w.writeLong(gas);
                    w.writeValue(to); w.writeBigInteger(value); w.writeValue(input);
                });
            } else if (vl >= 35) {
                long cid = (vl - 35) / 2;       // EIP-155
                chainId = cid;
                recId = (int) ((vl - 35) % 2);
                final long fcid = cid;
                signing = RLP.encodeList(w -> {
                    w.writeLong(nonce); w.writeBigInteger(gasPrice); w.writeLong(gas);
                    w.writeValue(to); w.writeBigInteger(value); w.writeValue(input);
                    w.writeLong(fcid); w.writeInt(0); w.writeInt(0);
                });
            }
            // Any other v (< 27 or 29..34) can't map to a recovery id: keep the
            // decoded summary but drop the sender — never a fabricated (negative)
            // chainId (the Rust decoder's rule, mirrored for wire parity).
            Bytes from = signing == null ? null : recover(Hash.keccak256(signing), sigR, sigS, recId);
            return new DecodedTx(0, chainId, nonce, gasPrice, null, null, gas, to, value,
                    input, v, sigR, sigS, from);
        });
    }

    // 0x01 || rlp([chainId, nonce, gasPrice, gas, to, value, data, accessList, yParity, r, s])
    private static DecodedTx decode2930(Bytes raw) {
        Bytes body = raw.slice(1);
        return RLP.decodeList(body, r -> {
            long chainId = toLong(r.readValue());
            long nonce = toLong(r.readValue());
            BigInteger gasPrice = toBig(r.readValue());
            long gas = toLong(r.readValue());
            Bytes to = r.readValue();
            BigInteger value = toBig(r.readValue());
            Bytes input = r.readValue();
            Bytes accessList = rawList(r);
            BigInteger yParity = toBig(r.readValue());
            BigInteger sigR = toBig(r.readValue());
            BigInteger sigS = toBig(r.readValue());
            Bytes signing = Bytes.concatenate(Bytes.of(1), RLP.encodeList(w -> {
                w.writeLong(chainId); w.writeLong(nonce); w.writeBigInteger(gasPrice);
                w.writeLong(gas); w.writeValue(to); w.writeBigInteger(value);
                w.writeValue(input); w.writeRLP(accessList);
            }));
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, yParity.intValueExact());
            return new DecodedTx(1, chainId, nonce, gasPrice, null, null, gas, to, value,
                    input, yParity, sigR, sigS, from);
        });
    }

    // 0x02 || rlp([chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList, yParity, r, s])
    private static DecodedTx decode1559(Bytes raw) {
        Bytes body = raw.slice(1);
        return RLP.decodeList(body, r -> {
            long chainId = toLong(r.readValue());
            long nonce = toLong(r.readValue());
            BigInteger maxPriority = toBig(r.readValue());
            BigInteger maxFee = toBig(r.readValue());
            long gas = toLong(r.readValue());
            Bytes to = r.readValue();
            BigInteger value = toBig(r.readValue());
            Bytes input = r.readValue();
            Bytes accessList = rawList(r);
            BigInteger yParity = toBig(r.readValue());
            BigInteger sigR = toBig(r.readValue());
            BigInteger sigS = toBig(r.readValue());
            Bytes signing = Bytes.concatenate(Bytes.of(2), RLP.encodeList(w -> {
                w.writeLong(chainId); w.writeLong(nonce); w.writeBigInteger(maxPriority);
                w.writeBigInteger(maxFee); w.writeLong(gas); w.writeValue(to);
                w.writeBigInteger(value); w.writeValue(input); w.writeRLP(accessList);
            }));
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, yParity.intValueExact());
            return new DecodedTx(2, chainId, nonce, null, maxPriority, maxFee, gas, to, value,
                    input, yParity, sigR, sigS, from);
        });
    }

    // 0x03 || rlp([chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList,
    //              maxFeePerBlobGas, blobVersionedHashes, yParity, r, s])
    private static DecodedTx decode4844(Bytes raw) {
        Bytes body = raw.slice(1);
        return RLP.decodeList(body, r -> {
            long chainId = toLong(r.readValue());
            long nonce = toLong(r.readValue());
            BigInteger maxPriority = toBig(r.readValue());
            BigInteger maxFee = toBig(r.readValue());
            long gas = toLong(r.readValue());
            Bytes to = r.readValue();
            BigInteger value = toBig(r.readValue());
            Bytes input = r.readValue();
            Bytes accessList = rawList(r);
            BigInteger maxFeePerBlobGas = toBig(r.readValue());
            Bytes blobHashes = rawList(r);
            BigInteger yParity = toBig(r.readValue());
            BigInteger sigR = toBig(r.readValue());
            BigInteger sigS = toBig(r.readValue());
            Bytes signing = Bytes.concatenate(Bytes.of(3), RLP.encodeList(w -> {
                w.writeLong(chainId); w.writeLong(nonce); w.writeBigInteger(maxPriority);
                w.writeBigInteger(maxFee); w.writeLong(gas); w.writeValue(to);
                w.writeBigInteger(value); w.writeValue(input); w.writeRLP(accessList);
                w.writeBigInteger(maxFeePerBlobGas); w.writeRLP(blobHashes);
            }));
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, yParity.intValueExact());
            return new DecodedTx(3, chainId, nonce, null, maxPriority, maxFee, gas, to, value,
                    input, yParity, sigR, sigS, from);
        });
    }

    // 0x04 || rlp([chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList,
    //              authorizationList, yParity, r, s]) — EIP-7702. Same fee model as 1559,
    //              with an authorizationList (signed delegation tuples) before the sig.
    private static DecodedTx decode7702(Bytes raw) {
        Bytes body = raw.slice(1);
        return RLP.decodeList(body, r -> {
            long chainId = toLong(r.readValue());
            long nonce = toLong(r.readValue());
            BigInteger maxPriority = toBig(r.readValue());
            BigInteger maxFee = toBig(r.readValue());
            long gas = toLong(r.readValue());
            Bytes to = r.readValue();
            BigInteger value = toBig(r.readValue());
            Bytes input = r.readValue();
            Bytes accessList = rawList(r);
            Bytes authList = rawList(r);
            BigInteger yParity = toBig(r.readValue());
            BigInteger sigR = toBig(r.readValue());
            BigInteger sigS = toBig(r.readValue());
            Bytes signing = Bytes.concatenate(Bytes.of(4), RLP.encodeList(w -> {
                w.writeLong(chainId); w.writeLong(nonce); w.writeBigInteger(maxPriority);
                w.writeBigInteger(maxFee); w.writeLong(gas); w.writeValue(to);
                w.writeBigInteger(value); w.writeValue(input); w.writeRLP(accessList);
                w.writeRLP(authList);
            }));
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, yParity.intValueExact());
            return new DecodedTx(4, chainId, nonce, null, maxPriority, maxFee, gas, to, value,
                    input, yParity, sigR, sigS, from);
        });
    }

    /** Capture the raw canonical RLP of the (possibly nested) list at the reader head. */
    private static Bytes rawList(org.apache.tuweni.rlp.RLPReader reader) {
        java.util.List<Bytes> children = new java.util.ArrayList<>();
        reader.readList(inner -> {
            while (!inner.isComplete()) {
                if (inner.nextIsList()) children.add(rawList(inner));
                else children.add(RLP.encodeValue(inner.readValue()));
            }
            return null;
        });
        return RLP.encodeList(w -> children.forEach(w::writeRLP));
    }

    /** Recover the 20-byte sender address, or null if the signature is unrecoverable. */
    private static Bytes recover(Bytes32 signingHash, BigInteger r, BigInteger s, int recId) {
        try {
            SECP256K1.Signature sig = SECP256K1.Signature.create((byte) recId, r, s);
            SECP256K1.PublicKey pub = SECP256K1.PublicKey.recoverFromHashAndSignature(signingHash, sig);
            if (pub == null) return null;
            // address = last 20 bytes of keccak256(uncompressed pubkey, 64 bytes x||y)
            return Hash.keccak256(pub.bytes()).slice(12, 20);
        } catch (Exception e) {
            return null;
        }
    }

    private static long toLong(Bytes b) {
        return b.isEmpty() ? 0L : b.toLong();
    }

    private static BigInteger toBig(Bytes b) {
        return b.isEmpty() ? BigInteger.ZERO : b.toUnsignedBigInteger();
    }
}
