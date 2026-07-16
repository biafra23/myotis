package com.jaeckel.ethp2p.app;

import io.myotis.txhistory.TxHistoryEvent;
import io.myotis.txhistory.TxHistoryService;
import io.myotis.txhistory.TxKind;
import io.myotis.txhistory.TxSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;

/**
 * DEBUG-ONLY IPC commands that deliberately sit OUTSIDE the engine API boundary.
 *
 * <p>{@code get-transactions} streams address appearances from the TrueBlocks/IPFS
 * index — an explorer/debugging aid that is UNVERIFIED on this path (each returned
 * tx says {@code "verified":false}) and depends on engine internals (the raw
 * RLPxConnector inside {@link TxHistoryService}). It is a documented exemption from
 * the "hosts consume only {@code io.myotis.api}" rule (see docs/reimplementation):
 * not part of the engine contract, not required of a re-implementation, and
 * constructed at the composition root where the internals are still in reach.
 *
 * <p>The scan/parse logic lives in {@code :tx-history} (shared with the desktop
 * Query tab); this class only maps events to succinct JSON-Lines.
 */
final class DebugCommands {

    private static final Logger log = LoggerFactory.getLogger(DebugCommands.class);

    /** Only every Nth chunk emits a progress heartbeat line — a full mainnet scan
     *  visits thousands of chunks and the CLI doesn't need one line per chunk. */
    private static final int PROGRESS_EVERY_CHUNKS = 250;

    /** Index lag beyond this (~14 days of mainnet blocks) marks the Started line
     *  stale + warns. Matches the UI's TX_INDEX_STALE_BLOCKS threshold. */
    private static final long STALE_LAG_BLOCKS = 100_000L;

    private final TxHistoryService service;

    DebugCommands(TxHistoryService service) {
        this.service = service;
    }

    void handleGetTransactions(String jsonLine, BufferedWriter writer) throws IOException {
        String addr = CommandHandler.extractString(jsonLine, "address");
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            writeLine(writer, jsonError("address must be a 20-byte hex string (40 hex chars)"));
            return;
        }

        try {
            // An IOException from the sink (client hung up) propagates out of the
            // collect and cancels the scan — no orphaned scans on disconnect.
            service.scanBlocking("0x" + hex.toLowerCase(), event -> {
                String line = toJsonLine(event);
                if (line != null) writeLine(writer, line);
            });
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            writeLine(writer, jsonError("get-transactions failed: " + msg));
        }
    }

    /** One succinct JSON line per event; null = suppressed (sampled progress). */
    private static String toJsonLine(TxHistoryEvent event) {
        if (event instanceof TxHistoryEvent.Started s) {
            StringBuilder b = new StringBuilder(256);
            b.append("{\"ok\":true,\"manifestCid\":\"").append(escapeJson(s.getManifestCid()))
                    .append("\",\"cidSource\":\"").append(s.getCidSource())
                    .append("\",\"chunks\":").append(s.getTotalChunks())
                    .append(",\"latestIndexedBlock\":").append(s.getLatestIndexedBlock());
            if (s.getHeadBlock() != null) {
                // Clamp: a still-syncing node's head can trail the index tip; a negative
                // "age" in the stream would just be confusing.
                long lag = Math.max(0L, s.getHeadBlock() - s.getLatestIndexedBlock());
                long ageDays = lag * 12 / 86_400;
                b.append(",\"headBlock\":").append(s.getHeadBlock())
                        .append(",\"indexLagBlocks\":").append(lag)
                        .append(",\"indexAgeDays\":").append(ageDays);
                // Make an out-of-date index impossible to miss in the stream: beyond
                // ~14 days of lag, say explicitly that recent history is absent.
                if (lag > STALE_LAG_BLOCKS) {
                    b.append(",\"stale\":true,\"warning\":\"index is ~").append(ageDays)
                            .append(" days behind the head — transactions after block ")
                            .append(s.getLatestIndexedBlock())
                            .append(" will NOT appear (newest index the publisher has released)\"");
                }
            }
            return b.append('}').toString();
        }
        if (event instanceof TxHistoryEvent.Progress p) {
            if (p.getChunksScanned() % PROGRESS_EVERY_CHUNKS != 0) return null;
            return "{\"ok\":true,\"progress\":{\"chunksScanned\":" + p.getChunksScanned()
                    + ",\"totalChunks\":" + p.getTotalChunks()
                    + ",\"range\":\"" + escapeJson(p.getCurrentRange())
                    + "\",\"hits\":" + p.getHits()
                    + ",\"bytesDownloaded\":" + p.getBytesDownloaded() + "}}";
        }
        if (event instanceof TxHistoryEvent.Hit) {
            // The CLI stream stays line-per-result; placeholder hits are a UI affordance.
            return null;
        }
        if (event instanceof TxHistoryEvent.Tx tx) {
            return txJson(tx.getSummary());
        }
        if (event instanceof TxHistoryEvent.TxFailed f) {
            return "{\"ok\":false,\"blockNumber\":" + f.getBlockNumber()
                    + ",\"transactionIndex\":" + f.getTxIndex()
                    + ",\"error\":\"" + escapeJson(f.getError()) + "\"}";
        }
        if (event instanceof TxHistoryEvent.Done d) {
            return "{\"ok\":true,\"done\":true,\"totalTransactions\":" + d.getTxCount() + "}";
        }
        return null;
    }

    private static String txJson(TxSummary s) {
        StringBuilder b = new StringBuilder(256);
        b.append("{\"ok\":true,\"blockNumber\":").append(s.getBlockNumber());
        b.append(",\"transactionIndex\":").append(s.getTxIndex());
        b.append(",\"hash\":\"").append(s.getHash()).append('"');
        if (s.getFrom() != null) b.append(",\"from\":\"").append(s.getFrom()).append('"');
        if (s.getTo() != null) b.append(",\"to\":\"").append(s.getTo()).append('"');
        TxKind kind = s.getKind();
        switch (kind) {
            case ETH_TRANSFER -> b.append(",\"kind\":\"eth\",\"eth\":\"")
                    .append(s.getEthDisplay()).append("\",\"wei\":\"")
                    .append(s.getEthWei()).append('"');
            case ERC20_TRANSFER -> {
                b.append(",\"kind\":\"erc20\",\"token\":\"").append(s.getTokenSymbol()).append('"');
                if (s.getTokenAmount() != null) {
                    b.append(",\"amount\":\"").append(s.getTokenAmount()).append('"');
                }
                if (s.getTokenRecipient() != null) {
                    b.append(",\"recipient\":\"").append(s.getTokenRecipient()).append('"');
                }
            }
            case CONTRACT_CREATION -> b.append(",\"kind\":\"create\",\"calldataBytes\":")
                    .append(s.getCalldataBytes());
            case CONTRACT_CALL -> {
                b.append(",\"kind\":\"call\",\"calldataBytes\":").append(s.getCalldataBytes());
                if (s.getSelector() != null) {
                    b.append(",\"selector\":\"").append(s.getSelector()).append('"');
                }
                if (!"0".equals(s.getEthWei())) {
                    b.append(",\"eth\":\"").append(s.getEthDisplay()).append('"');
                }
            }
        }
        b.append(",\"verified\":false}");
        return b.toString();
    }

    private static void writeLine(BufferedWriter writer, String line) throws IOException {
        writer.write(line);
        writer.newLine();
        writer.flush();
    }

    private static String jsonError(String message) {
        return "{\"ok\":false,\"error\":\"" + escapeJson(message) + "\"}";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> b.append("\\\\");
                case '"' -> b.append("\\\"");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    // Escape the remaining C0 controls (e.g. from an exception message)
                    // as a JSON \\uXXXX sequence so the IPC line stays valid JSON.
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.toString();
    }
}
