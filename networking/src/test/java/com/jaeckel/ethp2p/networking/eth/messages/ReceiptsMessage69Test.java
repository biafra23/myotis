package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * eth/69 (EIP-7642) Receipts decoding: the wire form is bloomless and
 * envelope-flattened ({@code [txType, status, cumGas, logs]}); decode69 must
 * recompute the logs bloom and reproduce the exact canonical consensus bytes
 * (what the receipts trie commits to).
 */
class ReceiptsMessage69Test {

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final Bytes ADDRESS = Bytes.fromHexString("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    private static final Bytes TOPIC = Bytes.fromHexString(
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

    /** Independent M3:2048 bloom (BigInteger bit-twiddling, different code path than impl). */
    private static Bytes referenceBloom(List<Bytes> items) {
        BigInteger acc = BigInteger.ZERO;
        for (Bytes item : items) {
            byte[] h = Hash.keccak256(item).toArray();
            for (int i = 0; i < 6; i += 2) {
                int bit = (((h[i] & 0xFF) << 8) | (h[i + 1] & 0xFF)) % 2048;
                acc = acc.setBit(bit);
            }
        }
        byte[] out = new byte[256];
        byte[] mag = acc.toByteArray();
        int len = Math.min(mag.length, 256);
        System.arraycopy(mag, mag.length - len, out, 256 - len, len);
        return Bytes.wrap(out);
    }

    /** eth/69 wire message with one block holding one receipt. */
    private static byte[] wire69(int txType, Bytes status, Bytes cumGas, boolean withLog) {
        return RLP.encodeList(w -> {
            w.writeLong(99);                                  // requestId
            w.writeList(blocks -> blocks.writeList(receipts -> receipts.writeList(r -> {
                r.writeInt(txType);
                r.writeValue(status);
                r.writeValue(cumGas);
                r.writeList(logs -> {
                    if (withLog) {
                        logs.writeList(log -> {
                            log.writeValue(ADDRESS);
                            log.writeList(t -> t.writeValue(TOPIC));
                            log.writeValue(Bytes.fromHexString("0xdeadbeef"));
                        });
                    }
                });
            })));
        }).toArray();
    }

    /** Canonical consensus receipt: rlp([status, cumGas, bloom, logs]), typed → prefixed. */
    private static Bytes canonical(int txType, Bytes status, Bytes cumGas, Bytes bloom, boolean withLog) {
        Bytes payload = RLP.encodeList(w -> {
            w.writeValue(status);
            w.writeValue(cumGas);
            w.writeValue(bloom);
            w.writeList(logs -> {
                if (withLog) {
                    logs.writeList(log -> {
                        log.writeValue(ADDRESS);
                        log.writeList(t -> t.writeValue(TOPIC));
                        log.writeValue(Bytes.fromHexString("0xdeadbeef"));
                    });
                }
            });
        });
        return txType == 0 ? payload : Bytes.concatenate(Bytes.of((byte) txType), payload);
    }

    @Test
    void typedReceiptWithLog_recanonicalizedWithRecomputedBloom() {
        Bytes status = Bytes.fromHexString("0x01");
        Bytes cumGas = Bytes.fromHexString("0x5208");
        ReceiptsMessage.DecodeResult res = ReceiptsMessage.decode69(wire69(2, status, cumGas, true));
        assertEquals(99, res.requestId());
        Bytes expectBloom = referenceBloom(List.of(ADDRESS, TOPIC));
        assertEquals(canonical(2, status, cumGas, expectBloom, true),
                res.perBlockReceipts().get(0).get(0));
        // The canonicalized receipt also decodes through the standard Receipt decoder.
        Receipt rcpt = Receipt.decode(res.perBlockReceipts().get(0).get(0));
        assertEquals(2, rcpt.type());
        assertEquals(0x5208, rcpt.cumulativeGasUsed());
        assertEquals(expectBloom, rcpt.logsBloom());
        assertEquals(1, rcpt.logs().size());
    }

    @Test
    void legacyReceiptNoLogs_zeroBloom_noEnvelope() {
        Bytes status = Bytes.fromHexString("0x01");
        Bytes cumGas = Bytes.fromHexString("0x9c40");
        ReceiptsMessage.DecodeResult res = ReceiptsMessage.decode69(wire69(0, status, cumGas, false));
        Bytes zeroBloom = Bytes.repeat((byte) 0, 256);
        assertEquals(canonical(0, status, cumGas, zeroBloom, false),
                res.perBlockReceipts().get(0).get(0));
        assertEquals(0, Receipt.decode(res.perBlockReceipts().get(0).get(0)).type());
    }
}
