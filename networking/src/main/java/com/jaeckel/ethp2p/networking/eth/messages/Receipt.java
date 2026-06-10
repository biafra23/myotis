package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * A decoded Ethereum transaction receipt (EIP-2718 typed or legacy).
 *
 * <p>Consensus encoding:
 * <ul>
 *   <li>legacy: {@code rlp([status|stateRoot, cumulativeGasUsed, logsBloom, logs])}</li>
 *   <li>typed:  {@code type || rlp([status, cumulativeGasUsed, logsBloom, logs])}</li>
 * </ul>
 * where each log is {@code [address, [topic, ...], data]}. Post-Byzantium the first
 * field is a 0/1 status byte; the rare pre-Byzantium form carries a 32-byte intermediate
 * stateRoot instead, in which case {@link #hasStatus()} is false.
 *
 * <p>This is a pure decoder over bytes the caller has ALREADY verified against a trusted
 * {@code receiptsRoot} (see OrderedTrieRoot) — it does no verification itself.
 */
public record Receipt(int type,
                      boolean hasStatus,
                      boolean success,
                      long cumulativeGasUsed,
                      Bytes logsBloom,
                      List<Log> logs) {

    /** A single log entry. */
    public record Log(Bytes address, List<Bytes> topics, Bytes data) {}

    /** Decode a receipt from its raw consensus bytes (as carried in eth Receipts). */
    public static Receipt decode(Bytes raw) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException("receipt bytes are null/empty");
        }
        int first = raw.get(0) & 0xFF;
        int type;
        Bytes payload;
        if (first >= 0xc0) {            // RLP list → legacy receipt
            type = 0;
            payload = raw;
        } else {                        // EIP-2718 envelope: type byte + RLP payload
            type = first;
            payload = raw.slice(1);
        }

        boolean[] hasStatus = {true};
        boolean[] success = {false};
        long[] cumGas = {0};
        Bytes[] bloom = {Bytes.EMPTY};
        List<Log> logs = new ArrayList<>();

        RLP.decodeList(payload, reader -> {
            Bytes statusOrRoot = reader.readValue();
            if (statusOrRoot.size() <= 1) {
                hasStatus[0] = true;
                success[0] = !statusOrRoot.isEmpty() && statusOrRoot.get(statusOrRoot.size() - 1) != 0;
            } else {
                hasStatus[0] = false; // pre-Byzantium intermediate stateRoot, not a status
            }
            cumGas[0] = reader.readValue().toLong();
            bloom[0] = reader.readValue();
            reader.readList(logsReader -> {
                while (!logsReader.isComplete()) {
                    logsReader.readList(logReader -> {
                        Bytes address = logReader.readValue();
                        List<Bytes> topics = new ArrayList<>();
                        logReader.readList(topicsReader -> {
                            while (!topicsReader.isComplete()) topics.add(topicsReader.readValue());
                            return null;
                        });
                        Bytes data = logReader.readValue();
                        logs.add(new Log(address, topics, data));
                        return null;
                    });
                }
                return null;
            });
            return null;
        });

        return new Receipt(type, hasStatus[0], success[0], cumGas[0], bloom[0], logs);
    }
}
