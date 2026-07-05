package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.trueblocks.AppearanceRecord;
import com.jaeckel.trueblocks.Bloom;
import com.jaeckel.trueblocks.Chunk;
import com.jaeckel.trueblocks.IndexParser;
import com.jaeckel.trueblocks.IpfsHttpClient;
import com.jaeckel.trueblocks.ManifestResponse;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * DEBUG-ONLY IPC commands that deliberately sit OUTSIDE the engine API boundary.
 *
 * <p>{@code get-transactions} streams address appearances from the TrueBlocks/IPFS
 * index — an explorer/debugging aid that is UNVERIFIED on this path (each returned
 * tx says {@code "verified":false}) and depends on engine internals
 * ({@link RLPxConnector} header/body fetches). It is a documented exemption from the
 * "hosts consume only {@code io.myotis.api}" rule (see docs/reimplementation): not
 * part of the engine contract, not required of a re-implementation, and constructed
 * at the composition root where the internals are still in reach.
 */
final class DebugCommands {

    private static final Logger log = LoggerFactory.getLogger(DebugCommands.class);

    private final RLPxConnector connector;

    DebugCommands(RLPxConnector connector) {
        this.connector = connector;
    }

    private static String jsonError(String message) {
        return "{\"ok\":false,\"error\":\"" + escapeJson(message) + "\"}";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    /** Reflective access to Kotlin UInt-typed getters on AppearanceRecord. */
    private static final Method GET_BLOCK_NUMBER;
    private static final Method GET_TX_INDEX;
    static {
        try {
            GET_BLOCK_NUMBER = AppearanceRecord.class.getMethod("getBlockNumber-pVg5ArA");
            GET_TX_INDEX = AppearanceRecord.class.getMethod("getTxIndex-pVg5ArA");
        } catch (NoSuchMethodException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static int appearanceBlockNumber(AppearanceRecord rec) {
        try { return (int) GET_BLOCK_NUMBER.invoke(rec); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private static int appearanceTxIndex(AppearanceRecord rec) {
        try { return (int) GET_TX_INDEX.invoke(rec); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    void handleGetTransactions(String jsonLine, BufferedWriter writer) throws IOException {
        String addr = CommandHandler.extractString(jsonLine, "address");
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            writer.write(jsonError("address must be a 20-byte hex string (40 hex chars)"));
            writer.newLine();
            writer.flush();
            return;
        }
        String checksumAddr = "0x" + hex.toLowerCase();

        try {
            IpfsHttpClient ipfs = new IpfsHttpClient();
            String manifestCID = "QmUBS83qjRmXmSgEvZADVv2ch47137jkgNbqfVVxQep5Y1";

            log.info("[get-transactions] Fetching manifest for address {}", checksumAddr);
            ManifestResponse manifest = ipfs.fetchAndParseManifestUrl(manifestCID);

            // Construct kethereum Address via reflection (avoids compile-time dependency
            // on kethereum multiplatform module)
            Class<?> addressClass = Class.forName("org.kethereum.model.Address");
            Constructor<?> addressCtor = addressClass.getConstructor(String.class);
            Object tbAddress = addressCtor.newInstance(checksumAddr);
            Method isMemberBytes = Bloom.class.getMethod("isMemberBytes", addressClass);
            List<Chunk> chunks = manifest.getChunks();
            int totalChunks = chunks.size();
            int successCount = 0;

            // Scan from highest block number to lowest so recent txs appear first.
            // Stream results per-chunk: fetch tx data immediately when appearances are found.
            for (int ci = totalChunks - 1; ci >= 0; ci--) {
                Chunk chunk = chunks.get(ci);
                try {
                    Bloom bloom = ipfs.fetchBloom(chunk.getBloomHash(), chunk.getRange());
                    if ((boolean) isMemberBytes.invoke(bloom, tbAddress)) {
                        log.debug("[get-transactions] Bloom hit for chunk {} ({}/{})",
                                chunk.getRange(), totalChunks - ci, totalChunks);
                        IndexParser index = ipfs.fetchIndex(chunk.getIndexHash(), false);
                        List<AppearanceRecord> appearances = index.findAppearances(checksumAddr);
                        if (appearances.isEmpty()) continue;

                        log.info("[get-transactions] Found {} appearances in chunk {}",
                                appearances.size(), chunk.getRange());

                        // Sort appearances within chunk descending by block number
                        appearances.sort(Comparator.comparingInt(
                                DebugCommands::appearanceBlockNumber).reversed());

                        // Fetch and stream each transaction immediately
                        for (AppearanceRecord appearance : appearances) {
                            long blockNumber = Integer.toUnsignedLong(appearanceBlockNumber(appearance));
                            int txIndex = appearanceTxIndex(appearance);
                            try {
                                List<BlockHeadersMessage.VerifiedHeader> headers =
                                        connector.requestBlockHeadersBatched(blockNumber, 1)
                                                .get(30, TimeUnit.SECONDS);
                                if (headers.isEmpty()) {
                                    writer.write("{\"ok\":false,\"blockNumber\":" + blockNumber
                                            + ",\"error\":\"No header returned\"}");
                                    writer.newLine();
                                    writer.flush();
                                    continue;
                                }
                                BlockHeadersMessage.VerifiedHeader vh = headers.get(0);
                                Bytes32 blockHash = vh.hash();

                                List<BlockBodiesMessage.BlockBody> bodies =
                                        connector.requestBlockBodies(blockHash)
                                                .get(30, TimeUnit.SECONDS);
                                if (bodies.isEmpty()) {
                                    writer.write("{\"ok\":false,\"blockNumber\":" + blockNumber
                                            + ",\"error\":\"No body returned\"}");
                                    writer.newLine();
                                    writer.flush();
                                    continue;
                                }
                                BlockBodiesMessage.BlockBody body = bodies.get(0);

                                List<Bytes> txList = body.transactions();
                                if (txIndex >= txList.size()) {
                                    writer.write("{\"ok\":false,\"blockNumber\":" + blockNumber
                                            + ",\"transactionIndex\":" + txIndex
                                            + ",\"error\":\"Transaction index out of range\"}");
                                    writer.newLine();
                                    writer.flush();
                                    continue;
                                }
                                Bytes rawTx = txList.get(txIndex);
                                String parsedFields = parseTxToJson(rawTx);

                                StringBuilder txJson = new StringBuilder();
                                txJson.append("{\"ok\":true,\"blockNumber\":").append(blockNumber);
                                txJson.append(",\"transactionIndex\":").append(txIndex);
                                if (!parsedFields.isEmpty()) {
                                    txJson.append(",").append(parsedFields);
                                }
                                txJson.append(",\"rawTx\":\"0x").append(rawTx.toUnprefixedHexString()).append("\"");
                                txJson.append(",\"verified\":false}");
                                writer.write(txJson.toString());
                                writer.newLine();
                                writer.flush();
                                successCount++;

                            } catch (Exception e) {
                                // The blocking .get() calls above can throw InterruptedException
                                // directly (not wrapped) — restore the flag so a cancelled stream
                                // stops promptly instead of swallowing the interrupt per-tx.
                                if (e instanceof InterruptedException) Thread.currentThread().interrupt();
                                Throwable cause = e.getCause() != null ? e.getCause() : e;
                                String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
                                writer.write("{\"ok\":false,\"blockNumber\":" + blockNumber
                                        + ",\"transactionIndex\":" + txIndex
                                        + ",\"error\":\"" + escapeJson(msg) + "\"}");
                                writer.newLine();
                                writer.flush();
                            }
                        }
                    }
                } catch (Exception e) {
                    log.warn("[get-transactions] Error processing chunk {}: {}",
                            chunk.getRange(), e.getMessage());
                }
            }

            log.info("[get-transactions] Scan complete. {} transactions streamed for {}",
                    successCount, checksumAddr);
            writer.write("{\"ok\":true,\"done\":true,\"totalTransactions\":" + successCount + "}");
            writer.newLine();
            writer.flush();

        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            writer.write(jsonError("get-transactions failed: " + msg));
            writer.newLine();
            writer.flush();
        }
    }

    // -------------------------------------------------------------------------
    // Transaction parsing
    // -------------------------------------------------------------------------

    /**
     * Parse raw transaction bytes into JSON fields.
     * Supports legacy, EIP-2930 (type 1), EIP-1559 (type 2), and EIP-4844 (type 3).
     */
    private static String parseTxToJson(Bytes rawTx) {
        if (rawTx == null || rawTx.isEmpty()) return "";
        try {
            int firstByte = rawTx.get(0) & 0xFF;
            if (firstByte >= 0xc0) {
                // Legacy transaction (RLP list)
                return parseLegacyTx(rawTx);
            } else if (firstByte <= 0x03) {
                // Typed transaction (EIP-2718): type byte + RLP payload
                int type = firstByte;
                Bytes payload = rawTx.slice(1);
                return switch (type) {
                    case 1 -> parseEip2930Tx(payload);
                    case 2 -> parseEip1559Tx(payload);
                    case 3 -> parseEip4844Tx(payload);
                    default -> "\"type\":" + type;
                };
            }
            return "";
        } catch (Exception e) {
            return "\"parseError\":\"" + escapeJson(e.getMessage()) + "\"";
        }
    }

    /** Legacy tx: [nonce, gasPrice, gasLimit, to, value, data, v, r, s] */
    private static String parseLegacyTx(Bytes rlp) {
        StringBuilder sb = new StringBuilder();
        RLP.decodeList(rlp, reader -> {
            Bytes nonce = reader.readValue();
            Bytes gasPrice = reader.readValue();
            Bytes gasLimit = reader.readValue();
            Bytes to = reader.readValue();
            Bytes value = reader.readValue();
            Bytes data = reader.readValue();
            sb.append("\"type\":0");
            sb.append(",\"nonce\":").append(toLong(nonce));
            sb.append(",\"gasPrice\":\"0x").append(toMinHex(gasPrice)).append("\"");
            sb.append(",\"gasLimit\":").append(toLong(gasLimit));
            if (!to.isEmpty()) {
                sb.append(",\"to\":\"0x").append(to.toUnprefixedHexString()).append("\"");
            }
            sb.append(",\"value\":\"0x").append(toMinHex(value)).append("\"");
            if (!data.isEmpty()) {
                sb.append(",\"data\":\"0x").append(data.toUnprefixedHexString()).append("\"");
            }
            return null;
        });
        return sb.toString();
    }

    /** EIP-2930 tx: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s] */
    private static String parseEip2930Tx(Bytes rlp) {
        StringBuilder sb = new StringBuilder();
        RLP.decodeList(rlp, reader -> {
            Bytes chainId = reader.readValue();
            Bytes nonce = reader.readValue();
            Bytes gasPrice = reader.readValue();
            Bytes gasLimit = reader.readValue();
            Bytes to = reader.readValue();
            Bytes value = reader.readValue();
            Bytes data = reader.readValue();
            sb.append("\"type\":1");
            sb.append(",\"chainId\":").append(toLong(chainId));
            sb.append(",\"nonce\":").append(toLong(nonce));
            sb.append(",\"gasPrice\":\"0x").append(toMinHex(gasPrice)).append("\"");
            sb.append(",\"gasLimit\":").append(toLong(gasLimit));
            if (!to.isEmpty()) {
                sb.append(",\"to\":\"0x").append(to.toUnprefixedHexString()).append("\"");
            }
            sb.append(",\"value\":\"0x").append(toMinHex(value)).append("\"");
            if (!data.isEmpty()) {
                sb.append(",\"data\":\"0x").append(data.toUnprefixedHexString()).append("\"");
            }
            return null;
        });
        return sb.toString();
    }

    /** EIP-1559 tx: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s] */
    private static String parseEip1559Tx(Bytes rlp) {
        StringBuilder sb = new StringBuilder();
        RLP.decodeList(rlp, reader -> {
            Bytes chainId = reader.readValue();
            Bytes nonce = reader.readValue();
            Bytes maxPriorityFee = reader.readValue();
            Bytes maxFee = reader.readValue();
            Bytes gasLimit = reader.readValue();
            Bytes to = reader.readValue();
            Bytes value = reader.readValue();
            Bytes data = reader.readValue();
            sb.append("\"type\":2");
            sb.append(",\"chainId\":").append(toLong(chainId));
            sb.append(",\"nonce\":").append(toLong(nonce));
            sb.append(",\"maxPriorityFeePerGas\":\"0x").append(toMinHex(maxPriorityFee)).append("\"");
            sb.append(",\"maxFeePerGas\":\"0x").append(toMinHex(maxFee)).append("\"");
            sb.append(",\"gasLimit\":").append(toLong(gasLimit));
            if (!to.isEmpty()) {
                sb.append(",\"to\":\"0x").append(to.toUnprefixedHexString()).append("\"");
            }
            sb.append(",\"value\":\"0x").append(toMinHex(value)).append("\"");
            if (!data.isEmpty()) {
                sb.append(",\"data\":\"0x").append(data.toUnprefixedHexString()).append("\"");
            }
            return null;
        });
        return sb.toString();
    }

    /** EIP-4844 tx: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, yParity, r, s] */
    private static String parseEip4844Tx(Bytes rlp) {
        StringBuilder sb = new StringBuilder();
        RLP.decodeList(rlp, reader -> {
            Bytes chainId = reader.readValue();
            Bytes nonce = reader.readValue();
            Bytes maxPriorityFee = reader.readValue();
            Bytes maxFee = reader.readValue();
            Bytes gasLimit = reader.readValue();
            Bytes to = reader.readValue();
            Bytes value = reader.readValue();
            Bytes data = reader.readValue();
            reader.readList(r -> { r.readRemaining(); return null; }); // accessList
            Bytes maxFeePerBlobGas = reader.readValue();
            sb.append("\"type\":3");
            sb.append(",\"chainId\":").append(toLong(chainId));
            sb.append(",\"nonce\":").append(toLong(nonce));
            sb.append(",\"maxPriorityFeePerGas\":\"0x").append(toMinHex(maxPriorityFee)).append("\"");
            sb.append(",\"maxFeePerGas\":\"0x").append(toMinHex(maxFee)).append("\"");
            sb.append(",\"gasLimit\":").append(toLong(gasLimit));
            if (!to.isEmpty()) {
                sb.append(",\"to\":\"0x").append(to.toUnprefixedHexString()).append("\"");
            }
            sb.append(",\"value\":\"0x").append(toMinHex(value)).append("\"");
            sb.append(",\"maxFeePerBlobGas\":\"0x").append(toMinHex(maxFeePerBlobGas)).append("\"");
            if (!data.isEmpty()) {
                sb.append(",\"data\":\"0x").append(data.toUnprefixedHexString()).append("\"");
            }
            return null;
        });
        return sb.toString();
    }

    /** Convert RLP-encoded integer bytes to long. Empty bytes = 0. */
    private static long toLong(Bytes b) {
        if (b.isEmpty()) return 0;
        return b.toLong();
    }

    /** Minimal hex representation (no leading zeros), or "0" for empty/zero. */
    private static String toMinHex(Bytes b) {
        if (b.isEmpty()) return "0";
        String hex = b.toUnprefixedHexString().replaceFirst("^0+", "");
        return hex.isEmpty() ? "0" : hex;
    }
}
