package com.jaeckel.ethp2p.networking.eth.messages;

import com.jaeckel.ethp2p.core.math.BigIntegers;
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

    // ---------------------------------------------------------------------
    // The eth_sendRawTransaction gate (#360): only a transaction is relayed.
    // Twin of the Rust tx::decode_sendable — same rules, same words.
    // ---------------------------------------------------------------------

    /**
     * The refusal of a blob transaction (type 0x3) — the words the transaction-object
     * refusals use ({@code RpcTransactionArgs}, the Rust {@code myotis_evm::tx}). Its
     * network form wraps the blobs around the transaction, and the eth protocol forbids
     * pushing one in a {@code Transactions} message: geth drops the peer that does.
     */
    public static final String BLOB_SEND_REFUSAL =
            "blob transactions (type 0x3) are not supported by this node";

    /** secp256k1's group order n: a signature's r lies in [1, n). */
    private static final BigInteger SECP256K1_N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /** floor(n / 2): the ceiling EIP-2 puts on a transaction signature's s. */
    private static final BigInteger SECP256K1_HALF_N = SECP256K1_N.shiftRight(1);

    /**
     * Raw bytes checked for relaying: the decoded transaction, or why the bytes are
     * not one this node relays. Exactly one of the two is non-null.
     */
    public record SendCheck(DecodedTx tx, String refusal) {
        static SendCheck refused(String why) {
            return new SendCheck(null, why);
        }
    }

    /**
     * Whether the bytes posted to {@code eth_sendRawTransaction} are a transaction this
     * node relays (#360): the decoded transaction, or why not, in words the hosts serve
     * under the permanent -32602 — no retry changes the bytes.
     * <ul>
     *   <li>A legacy RLP list, or an EIP-2718 type this node relays (0x1, 0x2, 0x4); a
     *       blob transaction is refused ({@link #BLOB_SEND_REFUSAL}).</li>
     *   <li>Its type's exact field layout, strictly encoded: canonical RLP with nothing
     *       trailing, integers without a leading zero byte and no wider than the
     *       decoders read them (8 bytes for chain id, nonce, gas and v, 16 for a fee,
     *       32 for value, r and s), {@code to} empty or an address — and a set-code
     *       transaction's an address —, and the access list (and a set-code
     *       transaction's authorization list) entries as geth decodes them
     *       ({@link #accessListWellFormed}, {@link #authorizationListWellFormed}): an
     *       entry geth cannot read fails the whole {@code Transactions} packet, and
     *       geth drops the peer that sent it. Strict, so {@code keccak256(raw)} is the
     *       hash of the transaction decoded — the one its peers compute — and never a
     *       hash of whatever bytes were posted.</li>
     *   <li>Signature values a peer accepts (geth's {@code ValidateSignatureValues}): v
     *       27, 28 or EIP-155 for a legacy transaction, yParity 0 or 1 for a typed one,
     *       0 &lt; r &lt; n, and 0 &lt; s &le; n/2 (EIP-2).</li>
     *   <li>A sender the signature recovers.</li>
     * </ul>
     * Whether the transaction can be mined — fees, nonce, balance, chain — is not
     * judged here: the chain is {@link #chainRefusal}'s, against the node's own, and the
     * rest a pre-broadcast check's on verified state, and otherwise the peers'.
     */
    public static SendCheck checkSendable(Bytes raw) {
        if (raw == null || raw.isEmpty()) return SendCheck.refused("invalid raw transaction: empty");
        int first = raw.get(0) & 0xFF;
        Layout layout;
        if (first >= 0xc0) {
            layout = Layout.LEGACY;
        } else if (first == 1) {
            layout = Layout.TYPE_1;
        } else if (first == 2) {
            layout = Layout.TYPE_2;
        } else if (first == 4) {
            layout = Layout.TYPE_4;
        } else if (first == 3) {
            return SendCheck.refused(BLOB_SEND_REFUSAL);
        } else if (first <= 0x7f) {
            // geth's words (ErrTxTypeNotSupported), then which type.
            return SendCheck.refused("invalid raw transaction: transaction type not supported (0x"
                    + Integer.toHexString(first) + ")");
        } else {
            return SendCheck.refused(
                    "invalid raw transaction: neither an RLP list nor an EIP-2718 typed transaction");
        }
        String malformed = "invalid raw transaction: malformed " + layout.kind + " transaction";
        java.util.List<Field> fields = strictFields(layout == Layout.LEGACY ? raw : raw.slice(1));
        if (fields == null || !layout.admits(fields)) return SendCheck.refused(malformed);
        if (layout == Layout.TYPE_4 && fields.get(layout.to).bytes().isEmpty()) {
            return SendCheck.refused(
                    "invalid raw transaction: a type 0x4 transaction cannot create a contract");
        }
        // Read from the fields BEFORE decoding: decode() takes a typed yParity through
        // an int, so one past it would fail there as malformed, where the Rust gate (a
        // u64) calls it an invalid signature value.
        int n = fields.size();
        BigInteger v = toBig(fields.get(n - 3).bytes());
        BigInteger r = toBig(fields.get(n - 2).bytes());
        BigInteger s = toBig(fields.get(n - 1).bytes());
        boolean vValid = layout == Layout.LEGACY
                ? v.equals(BigInteger.valueOf(27)) || v.equals(BigInteger.valueOf(28))
                        || v.compareTo(BigInteger.valueOf(35)) >= 0
                : v.compareTo(BigInteger.ONE) <= 0;
        boolean rValid = r.signum() > 0 && r.compareTo(SECP256K1_N) < 0;
        boolean sValid = s.signum() > 0 && s.compareTo(SECP256K1_HALF_N) <= 0;
        if (!(vValid && rValid && sValid)) {
            return SendCheck.refused("invalid transaction v, r, s values");
        }
        DecodedTx tx = decode(raw);
        if (tx == null) return SendCheck.refused(malformed);
        if (tx.from() == null) {
            return SendCheck.refused("invalid sender: the signature recovers no address");
        }
        return new SendCheck(tx, null);
    }

    /**
     * Why a transaction {@link #checkSendable} passed was not signed for {@code chainId}
     * (#665), or null when it was: the refusal in geth's words (its txpool's
     * {@code ErrInvalidSender} around the signer's {@code ErrInvalidChainId}). No peer
     * here would ever include it, so broadcasting it and answering its hash would show a
     * wallet "sent" for a transaction that can never confirm. Unlike the pre-broadcast
     * check's verdicts this one rests on the signed bytes alone — no state, no head to be
     * stale — so it never fails open. A pre-EIP-155 legacy transaction names no chain and
     * passes, as geth's signer recovers it without one. Twin of the Rust
     * {@code tx::check_chain} — same rule, same words.
     */
    public static String chainRefusal(DecodedTx tx, long chainId) {
        Long signed = tx.chainId();
        if (signed == null || signed == chainId) return null;
        return "invalid sender: invalid chain id for signer: have " + Long.toUnsignedString(signed)
                + " want " + Long.toUnsignedString(chainId);
    }

    /** One top-level field of a transaction's RLP list: a list (kept as its encoding) or bytes. */
    private record Field(boolean list, Bytes bytes) {}

    /** How deep an RLP item may sit (the top-level list at 0) — the Rust decoder's
     *  bound ({@code myotis_core::rlp} MAX_DEPTH), so both gates refuse the same nests,
     *  and the walk below never recurses past it. */
    private static final int MAX_RLP_DEPTH = 32;

    /**
     * The top-level fields of {@code payload} when it is ONE canonically encoded RLP list
     * with nothing trailing, else null. Canonical by construction: the fields are
     * re-encoded (nested lists through {@link #strictList}, which re-encodes them too) and
     * must give back {@code payload} byte for byte — whatever the reader tolerated.
     */
    private static java.util.List<Field> strictFields(Bytes payload) {
        try {
            if (payload.isEmpty() || (payload.get(0) & 0xFF) < 0xc0) return null;
            java.util.List<Field> fields = RLP.decodeList(payload, r -> {
                java.util.List<Field> out = new java.util.ArrayList<>();
                while (!r.isComplete()) {
                    out.add(r.nextIsList() ? new Field(true, strictList(r, 2)) : new Field(false, r.readValue()));
                }
                return out;
            });
            Bytes reencoded = RLP.encodeList(w -> fields.forEach(f -> {
                if (f.list()) w.writeRLP(f.bytes());
                else w.writeValue(f.bytes());
            }));
            return reencoded.equals(payload) ? fields : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** {@link #rawList} with the nesting bounded: the canonical encoding of the list at the
     *  reader head, whose items sit at {@code depth}; one past {@link #MAX_RLP_DEPTH} throws. */
    private static Bytes strictList(org.apache.tuweni.rlp.RLPReader reader, int depth) {
        java.util.List<Bytes> children = new java.util.ArrayList<>();
        reader.readList(inner -> {
            while (!inner.isComplete()) {
                if (depth > MAX_RLP_DEPTH) throw new IllegalArgumentException("RLP: nesting too deep");
                children.add(inner.nextIsList()
                        ? strictList(inner, depth + 1)
                        : RLP.encodeValue(inner.readValue()));
            }
            return null;
        });
        return RLP.encodeList(w -> children.forEach(w::writeRLP));
    }

    /** An access list as geth decodes one ({@code []AccessTuple}): every entry is
     *  {@code [address, [storage key, …]]}, a 20-byte and 32-byte strings. */
    private static boolean accessListWellFormed(Bytes encodedList) {
        java.util.List<Object> entries = itemsOrNull(encodedList);
        if (entries == null) return false;
        for (Object entry : entries) {
            if (!(entry instanceof java.util.List<?> tuple) || tuple.size() != 2) return false;
            if (!(tuple.get(0) instanceof Bytes address) || address.size() != 20) return false;
            if (!(tuple.get(1) instanceof java.util.List<?> keys)) return false;
            for (Object key : keys) {
                if (!(key instanceof Bytes k) || k.size() != 32) return false;
            }
        }
        return true;
    }

    /** The widths geth reads an EIP-7702 authorization's integers at
     *  ({@code SetCodeAuthorization}): chainId, -, nonce, yParity, r, s. */
    private static final int[] AUTHORIZATION_WIDTHS = {32, 20, 8, 1, 32, 32};

    /** An EIP-7702 authorization list as geth decodes one
     *  ({@code []SetCodeAuthorization}): every entry is {@code [chainId, address, nonce,
     *  yParity, r, s]}, the address 20 bytes and the integers canonical and no wider than
     *  geth reads them. Whether an authorization is valid is not judged — geth skips an
     *  invalid one and the transaction stands. */
    private static boolean authorizationListWellFormed(Bytes encodedList) {
        java.util.List<Object> entries = itemsOrNull(encodedList);
        if (entries == null) return false;
        for (Object entry : entries) {
            if (!(entry instanceof java.util.List<?> auth) || auth.size() != 6) return false;
            for (int i = 0; i < 6; i++) {
                if (!(auth.get(i) instanceof Bytes b)) return false;
                boolean ok = i == 1
                        ? b.size() == 20
                        : b.size() <= AUTHORIZATION_WIDTHS[i] && (b.isEmpty() || b.get(0) != 0);
                if (!ok) return false;
            }
        }
        return true;
    }

    /** The items of an encoded RLP list — a value as its {@link Bytes}, a nested list as
     *  a {@link java.util.List} — or null when it does not read. Only for lists
     *  {@link #strictFields} already walked, so the nesting is bounded. */
    private static java.util.List<Object> itemsOrNull(Bytes encodedList) {
        try {
            return RLP.decodeList(encodedList, EthTxDecoder::readItems);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static java.util.List<Object> readItems(org.apache.tuweni.rlp.RLPReader r) {
        java.util.List<Object> out = new java.util.ArrayList<>();
        while (!r.isComplete()) out.add(r.nextIsList() ? r.readList(EthTxDecoder::readItems) : r.readValue());
        return out;
    }

    /** A relayed type's field layout, as {@link #checkSendable} holds a transaction to it. */
    private enum Layout {
        // [nonce, gasPrice, gas, to, value, data, v, r, s]
        LEGACY("legacy", 3, new int[] {1}, new int[] {}),
        // [chainId, nonce, gasPrice, gas, to, value, data, accessList, yParity, r, s]
        TYPE_1("type 0x1", 4, new int[] {2}, new int[] {7}),
        // [chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList, yParity, r, s]
        TYPE_2("type 0x2", 5, new int[] {2, 3}, new int[] {8}),
        // TYPE_2's layout + [authorizationList] before the signature
        TYPE_4("type 0x4", 5, new int[] {2, 3}, new int[] {8, 9});

        final String kind;
        /** Where {@code to} sits; value follows it, then data. */
        final int to;
        final int[] fees;
        final int[] lists;

        Layout(String kind, int to, int[] fees, int[] lists) {
            this.kind = kind;
            this.to = to;
            this.fees = fees;
            this.lists = lists;
        }

        /** The exact field count, lists where the layout has them, {@code to} empty or an
         *  address, and every integer canonical and no wider than the decoders read it. */
        boolean admits(java.util.List<Field> fields) {
            // Every field but the lists is bytes; all but to, value and data are scalars,
            // plus the trailing [v, r, s].
            int count = to + 3 + lists.length + 3;
            if (fields.size() != count) return false;
            for (int i = 0; i < count; i++) {
                Field f = fields.get(i);
                boolean isList = contains(lists, i);
                if (f.list() != isList) return false;
                if (isList) {
                    // lists[0] is the access list; a set-code transaction's
                    // authorization list follows it.
                    boolean entries = i == lists[0]
                            ? accessListWellFormed(f.bytes())
                            : authorizationListWellFormed(f.bytes());
                    if (!entries) return false;
                    continue;
                }
                Bytes b = f.bytes();
                if (i == to) {
                    if (b.size() != 0 && b.size() != 20) return false;
                    continue;
                }
                if (i == to + 2) continue; // data: free-form bytes
                if (!b.isEmpty() && b.get(0) == 0) return false; // integer with a leading zero
                int width = i >= count - 2 || i == to + 1 ? 32 : contains(fees, i) ? 16 : 8;
                if (b.size() > width) return false;
            }
            return true;
        }

        private static boolean contains(int[] xs, int x) {
            for (int y : xs) if (y == x) return true;
            return false;
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

            // Legacy v = 2*chainId + 35: real chain ids exceed 2^31, so no int math.
            // The Rust decoder reads v as a u64, so the bound is u64 — a wider v is
            // malformed → whole decode fails (parity). BigInteger arithmetic below
            // because v itself may not fit a SIGNED long ([2^63, 2^64)), while
            // chainId = (v - 35) / 2 always does for v < 2^64.
            if (v.signum() < 0 || v.bitLength() > 64) {
                throw new ArithmeticException("legacy v out of u64 range");
            }
            Long chainId = null;
            Bytes signing = null;
            int recId = -1;
            if (v.equals(BigInteger.valueOf(27)) || v.equals(BigInteger.valueOf(28))) {
                recId = BigIntegers.intValueExact(v) - 27; // pre-155: sign over the 6 tx fields
                signing = RLP.encodeList(w -> {
                    w.writeLong(nonce); w.writeBigInteger(gasPrice); w.writeLong(gas);
                    w.writeValue(to); w.writeBigInteger(value); w.writeValue(input);
                });
            } else if (v.compareTo(BigInteger.valueOf(35)) >= 0) {
                BigInteger vMinus35 = v.subtract(BigInteger.valueOf(35));
                long cid = BigIntegers.longValueExact(vMinus35.shiftRight(1)); // EIP-155; < 2^63
                chainId = cid;
                recId = vMinus35.testBit(0) ? 1 : 0;
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
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, BigIntegers.intValueExact(yParity));
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
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, BigIntegers.intValueExact(yParity));
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
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, BigIntegers.intValueExact(yParity));
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
            Bytes from = recover(Hash.keccak256(signing), sigR, sigS, BigIntegers.intValueExact(yParity));
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
