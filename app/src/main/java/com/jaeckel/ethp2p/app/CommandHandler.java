package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.consensus.BeaconLightClient;
import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService;
import com.jaeckel.ethp2p.consensus.lightclient.BeaconChainSpec;
import com.jaeckel.ethp2p.consensus.proof.MerklePatriciaVerifier;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.discv4.KademliaTable;
import com.jaeckel.ethp2p.networking.discv5.DiscV5Service;
import com.jaeckel.ethp2p.networking.eth.messages.BlockBodiesMessage;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.StorageRangesMessage;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.jaeckel.trueblocks.AppearanceRecord;
import com.jaeckel.trueblocks.Bloom;
import com.jaeckel.trueblocks.Chunk;
import com.jaeckel.trueblocks.IndexParser;
import com.jaeckel.trueblocks.IpfsHttpClient;
import com.jaeckel.trueblocks.ManifestResponse;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handles JSON-Lines IPC commands dispatched by DaemonServer.
 * Holds references to live P2P services and produces JSON responses.
 */
public class CommandHandler {

    private static final Logger log = LoggerFactory.getLogger(CommandHandler.class);

    private final DiscV4Service discV4;
    private final DiscV5Service discV5; // nullable
    private final RLPxConnector connector;
    private final long startTimeMs;
    private final CountDownLatch stopLatch;
    private final Map<String, Long> backoff;
    private final Set<String> blacklistedNodeIds;
    private final BeaconSyncState beaconSyncState;
    private final BeaconLightClient beaconLightClient; // nullable
    private final long clGenesisTime; // beacon chain genesis time (seconds since epoch)

    // Shared across every ENS resolution: a single bytecode cache amortizes
    // Registry + Universal Resolver fetches across requests and between the
    // oracle and executor in the same request. (Peer selection is done
    // per-call by prepareEnsCall, which pins one peer for the whole call.)
    private final io.myotis.evm.world.BytecodeCache ensBytecodeCache =
            io.myotis.evm.world.BytecodeCache.inMemory();

    public CommandHandler(DiscV4Service discV4, RLPxConnector connector,
                          CountDownLatch stopLatch, Map<String, Long> backoff,
                          Set<String> blacklistedNodeIds, BeaconSyncState beaconSyncState) {
        this(discV4, null, connector, stopLatch, backoff, blacklistedNodeIds, beaconSyncState,
                null, BeaconChainSpec.MAINNET_GENESIS_TIME);
    }

    public CommandHandler(DiscV4Service discV4, RLPxConnector connector,
                          CountDownLatch stopLatch, Map<String, Long> backoff,
                          Set<String> blacklistedNodeIds, BeaconSyncState beaconSyncState,
                          BeaconLightClient beaconLightClient) {
        this(discV4, null, connector, stopLatch, backoff, blacklistedNodeIds, beaconSyncState,
                beaconLightClient, BeaconChainSpec.MAINNET_GENESIS_TIME);
    }

    public CommandHandler(DiscV4Service discV4, RLPxConnector connector,
                          CountDownLatch stopLatch, Map<String, Long> backoff,
                          Set<String> blacklistedNodeIds, BeaconSyncState beaconSyncState,
                          BeaconLightClient beaconLightClient, long clGenesisTime) {
        this(discV4, null, connector, stopLatch, backoff, blacklistedNodeIds, beaconSyncState,
                beaconLightClient, clGenesisTime);
    }

    public CommandHandler(DiscV4Service discV4, DiscV5Service discV5,
                          RLPxConnector connector,
                          CountDownLatch stopLatch, Map<String, Long> backoff,
                          Set<String> blacklistedNodeIds, BeaconSyncState beaconSyncState,
                          BeaconLightClient beaconLightClient, long clGenesisTime) {
        this.discV4 = discV4;
        this.discV5 = discV5;
        this.connector = connector;
        this.startTimeMs = System.currentTimeMillis();
        this.stopLatch = stopLatch;
        this.backoff = backoff;
        this.blacklistedNodeIds = blacklistedNodeIds;
        this.beaconSyncState = beaconSyncState;
        this.beaconLightClient = beaconLightClient;
        this.clGenesisTime = clGenesisTime;
    }

    /** Parse and dispatch one JSON-Lines request; returns a JSON-Lines response. */
    public String handle(String jsonLine) {
        try {
            String cmd = extractString(jsonLine, "cmd");
            return switch (cmd) {
                case "status"                  -> handleStatus();
                case "peers"                   -> handlePeers();
                case "get-headers"             -> handleGetHeaders(jsonLine);
                case "get-block"               -> handleGetBlock(jsonLine);
                case "get-account"             -> handleGetAccount(jsonLine);
                case "get-storage"             -> handleGetStorage(jsonLine);
                case "resolve-ens"             -> handleResolveEns(jsonLine);
                case "resolve-ens-text"        -> handleResolveEnsText(jsonLine);
                case "resolve-ens-contenthash" -> handleResolveEnsContenthash(jsonLine);
                case "resolve-ens-addr-coin"   -> handleResolveEnsAddrCoin(jsonLine);
                case "resolve-ens-pubkey"      -> handleResolveEnsPubkey(jsonLine);
                case "resolve-ens-abi"         -> handleResolveEnsAbi(jsonLine);
                case "resolve-ens-dns"         -> handleResolveEnsDns(jsonLine);
                case "resolve-ens-interface"   -> handleResolveEnsInterface(jsonLine);
                case "dial"                    -> handleDial(jsonLine);
                case "stop"                    -> handleStop();
                case "beacon-status"           -> handleBeaconStatus();
                default                        -> jsonError("Unknown command: " + cmd);
            };
        } catch (Exception e) {
            log.warn("[ipc] Error handling command '{}': {}", jsonLine, e.getMessage());
            return jsonError(e.getMessage());
        }
    }

    /**
     * Try to handle a command that streams multiple JSON lines back to the client.
     * Returns true if the command was handled (streaming), false if it should fall back to single-response.
     */
    public boolean handleStreaming(String jsonLine, BufferedWriter writer) {
        try {
            String cmd = extractString(jsonLine, "cmd");
            if ("get-transactions".equals(cmd)) {
                handleGetTransactions(jsonLine, writer);
                return true;
            }
        } catch (Exception e) {
            try {
                writer.write(jsonError(e.getMessage()));
                writer.newLine();
                writer.flush();
            } catch (IOException ignored) {}
            return true;
        }
        return false;
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

    private void handleGetTransactions(String jsonLine, BufferedWriter writer) throws IOException {
        String addr = extractString(jsonLine, "address");
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
                                CommandHandler::appearanceBlockNumber).reversed());

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
    // Command implementations
    // -------------------------------------------------------------------------

    private String handleStatus() {
        long uptimeSec = (System.currentTimeMillis() - startTimeMs) / 1000;
        int discovered = discV4.table().size();
        List<RLPxConnector.PeerInfo> peers = connector.getActivePeers();
        int connectedPeers = peers.size();
        long readyPeers = peers.stream()
                .filter(p -> "READY".equals(p.state()))
                .count();
        long snapPeers = peers.stream()
                .filter(p -> "READY".equals(p.state()) && p.snapSupported())
                .count();
        long now = System.currentTimeMillis();
        backoff.values().removeIf(exp -> now >= exp);
        long backedOffPeers = backoff.size();
        long blacklistedPeers = blacklistedNodeIds.size();
        return "{\"ok\":true,\"state\":\"RUNNING\",\"uptimeSeconds\":" + uptimeSec
                + ",\"discoveredPeers\":" + discovered
                + ",\"connectedPeers\":" + connectedPeers
                + ",\"readyPeers\":" + readyPeers
                + ",\"snapPeers\":" + snapPeers
                + ",\"backedOffPeers\":" + backedOffPeers
                + ",\"blacklistedPeers\":" + blacklistedPeers + "}";
    }

    private String handlePeers() {
        List<KademliaTable.Entry> peers = discV4.table().allPeers();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"count\":").append(peers.size()).append(",\"peers\":[");
        boolean first = true;
        for (KademliaTable.Entry e : peers) {
            if (!first) sb.append(",");
            first = false;
            String shortId = e.nodeId().size() >= 8
                    ? e.nodeId().slice(0, 8).toHexString() + "..."
                    : e.nodeId().toHexString();
            sb.append("{\"ip\":\"").append(e.udpAddr().getAddress().getHostAddress()).append("\"")
              .append(",\"udpPort\":").append(e.udpAddr().getPort())
              .append(",\"tcpPort\":").append(e.tcpPort())
              .append(",\"nodeId\":\"").append(shortId).append("\"")
              .append("}");
        }
        sb.append("],\"connected\":[");
        List<RLPxConnector.PeerInfo> connected = connector.getActivePeers();
        first = true;
        for (RLPxConnector.PeerInfo p : connected) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"remoteAddress\":\"").append(escapeJson(p.remoteAddress())).append("\"")
              .append(",\"state\":\"").append(p.state()).append("\"")
              .append(",\"snap\":").append(p.snapSupported());
            if (p.clientId() != null) {
                sb.append(",\"clientId\":\"").append(escapeJson(p.clientId())).append("\"");
            }
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String handleGetHeaders(String jsonLine) {
        long blockNumber = extractLong(jsonLine, "blockNumber");
        int count = (int) extractLong(jsonLine, "count");

        try {
            List<BlockHeadersMessage.VerifiedHeader> headers =
                    connector.requestBlockHeaders(blockNumber, count)
                             .get(30, TimeUnit.SECONDS);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"ok\":true,\"count\":").append(headers.size()).append(",\"headers\":[");
            boolean first = true;
            for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                if (!first) sb.append(",");
                first = false;
                BlockHeader h = vh.header();
                sb.append("{\"number\":").append(h.number)
                  .append(",\"hash\":\"").append(vh.hash().toHexString()).append("\"")
                  .append(",\"parentHash\":\"").append(h.parentHash.toHexString()).append("\"")
                  .append(",\"stateRoot\":\"").append(h.stateRoot.toHexString()).append("\"")
                  .append(",\"transactionsRoot\":\"").append(h.transactionsRoot.toHexString()).append("\"")
                  .append(",\"timestamp\":").append(h.timestamp)
                  .append(",\"gasUsed\":").append(h.gasUsed)
                  .append(",\"gasLimit\":").append(h.gasLimit);
                if (h.baseFeePerGas != null) {
                    sb.append(",\"baseFeePerGas\":\"").append(h.baseFeePerGas).append("\"");
                }
                sb.append("}");
            }
            sb.append("]}");
            return sb.toString();
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            return jsonError(msg);
        }
    }

    private String handleGetBlock(String jsonLine) {
        long blockNumber = extractLong(jsonLine, "blockNumber");

        try {
            // Step 1: fetch the header (use batched path which retries across peers)
            List<BlockHeadersMessage.VerifiedHeader> headers =
                    connector.requestBlockHeadersBatched(blockNumber, 1)
                             .get(30, TimeUnit.SECONDS);
            if (headers.isEmpty()) {
                return jsonError("No header returned for block " + blockNumber);
            }
            BlockHeadersMessage.VerifiedHeader vh = headers.get(0);
            BlockHeader h = vh.header();

            // Step 2: fetch the body using the block hash
            org.apache.tuweni.bytes.Bytes32 blockHash = vh.hash();
            List<BlockBodiesMessage.BlockBody> bodies =
                    connector.requestBlockBodies(blockHash)
                             .get(30, TimeUnit.SECONDS);
            if (bodies.isEmpty()) {
                return jsonError("No body returned for block " + blockNumber);
            }
            BlockBodiesMessage.BlockBody body = bodies.get(0);

            // Step 3: verify block against beacon chain
            String verificationJson = buildBlockVerificationJson(h, blockNumber);

            // Step 4: combine into JSON response
            StringBuilder sb = new StringBuilder();
            sb.append("{\"ok\":true,\"block\":{");
            sb.append("\"number\":").append(h.number);
            sb.append(",\"hash\":\"").append(vh.hash().toHexString()).append("\"");
            sb.append(",\"parentHash\":\"").append(h.parentHash.toHexString()).append("\"");
            sb.append(",\"stateRoot\":\"").append(h.stateRoot.toHexString()).append("\"");
            sb.append(",\"transactionsRoot\":\"").append(h.transactionsRoot.toHexString()).append("\"");
            sb.append(",\"receiptsRoot\":\"").append(h.receiptsRoot.toHexString()).append("\"");
            sb.append(",\"timestamp\":").append(h.timestamp);
            sb.append(",\"gasUsed\":").append(h.gasUsed);
            sb.append(",\"gasLimit\":").append(h.gasLimit);
            if (h.baseFeePerGas != null) {
                sb.append(",\"baseFeePerGas\":\"").append(h.baseFeePerGas).append("\"");
            }
            sb.append(",\"transactionCount\":").append(body.transactions().size());
            sb.append(",\"uncleCount\":").append(body.uncleCount());
            sb.append(",\"withdrawalCount\":").append(body.withdrawalCount());
            sb.append("},\"verification\":").append(verificationJson).append("}");
            return sb.toString();
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            return jsonError(msg);
        }
    }

    /**
     * Build beacon chain verification JSON for a block header.
     *
     * Verification strategy:
     * 1. State root match — check if the block's stateRoot matches a beacon-attested root
     * 2. Header chain anchored to beacon block hash — the beacon chain's ExecutionPayloadHeader
     *    contains a block_hash field verified by sync committee BLS signatures. We fetch the
     *    finalized block header from the peer, verify its keccak256(RLP) matches the beacon-
     *    attested block hash, then walk the parent-hash chain to/from the requested block.
     *    Each link in the chain is pinned by the previous header's keccak256 hash, so forging
     *    any header would require a keccak256 preimage attack.
     */
    /** The Merge block — first PoS block on mainnet (Sep 15 2022). */
    private static final long MERGE_BLOCK = 15_537_394L;
    private static final int MAX_HEADER_CHAIN_GAP = 8192;

    private String buildBlockVerificationJson(BlockHeader header, long blockNumber) {
        boolean beaconChainVerified = false;
        boolean blsVerified = false;
        long matchedSlot = -1;
        String verifyMethod = null;
        String failReason = null;

        // Pre-merge blocks cannot be verified via beacon chain
        if (blockNumber < MERGE_BLOCK) {
            failReason = "preMergeBlock";
        } else {
            // Strategy 1: direct state root match against beacon-attested roots
            byte[] blockStateRoot = header.stateRoot.toArrayUnsafe();
            BeaconSyncState.SlottedStateRoot match = beaconSyncState.findStateRoot(blockStateRoot);
            if (match != null) {
                beaconChainVerified = true;
                matchedSlot = match.slot();
                blsVerified = match.blsVerified();
                verifyMethod = "stateRootMatch";
            }

            // Strategy 2: header chain anchored to beacon-attested block hash
            if (!beaconChainVerified && beaconSyncState.isSynced()) {
                long finalizedBlockNum = beaconSyncState.getExecutionBlockNumber();
                byte[] beaconBlockHash = beaconSyncState.getExecutionBlockHash();
                long gap = Math.abs(blockNumber - finalizedBlockNum);
                log.info("[verify-block] headerChain: block={}, finalizedBlock={}, gap={}",
                        blockNumber, finalizedBlockNum, gap);
                if (finalizedBlockNum <= 0 || beaconBlockHash == null || beaconBlockHash.length != 32) {
                    failReason = "beaconBlockHashUnavailable";
                } else if (gap > MAX_HEADER_CHAIN_GAP && blockNumber != finalizedBlockNum) {
                    failReason = "headerChainGapTooLarge";
                } else {
                    try {
                        boolean chainValid;
                        if (blockNumber == finalizedBlockNum) {
                            chainValid = verifyBlockHashAgainstBeacon(
                                    finalizedBlockNum, beaconBlockHash, blockStateRoot);
                        } else if (blockNumber > finalizedBlockNum) {
                            chainValid = verifyBlockChainFromBeacon(
                                    finalizedBlockNum, blockNumber, beaconBlockHash);
                        } else {
                            chainValid = verifyBlockChainFromBeacon(
                                    blockNumber, finalizedBlockNum, beaconBlockHash);
                        }
                        if (chainValid) {
                            beaconChainVerified = true;
                            matchedSlot = beaconSyncState.getFinalizedSlot();
                            blsVerified = true;
                            verifyMethod = "headerChain";
                        } else {
                            failReason = "headerChainInvalid";
                        }
                    } catch (Exception e) {
                        log.info("[verify-block] Header chain verification failed: {}", e.getMessage());
                        failReason = "headerChainError";
                    }
                }
            } else if (!beaconChainVerified && !beaconSyncState.isSynced()) {
                failReason = "beaconNotSynced";
            }
        }

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"beaconSynced\":").append(beaconSyncState.isSynced());
        sb.append(",\"beaconChainVerified\":").append(beaconChainVerified);
        if (beaconChainVerified) {
            sb.append(",\"matchedBeaconSlot\":").append(matchedSlot);
            sb.append(",\"blsVerified\":").append(blsVerified);
            if (verifyMethod != null) {
                sb.append(",\"verifyMethod\":\"").append(verifyMethod).append("\"");
            }
        }
        if (!beaconChainVerified && failReason != null) {
            sb.append(",\"failReason\":\"").append(failReason).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Verify a single block by checking its hash against the beacon-attested block hash.
     * Used when the requested block IS the finalized block.
     */
    private boolean verifyBlockHashAgainstBeacon(long blockNumber, byte[] beaconBlockHash,
                                                  byte[] expectedStateRoot) throws Exception {
        List<BlockHeadersMessage.VerifiedHeader> headers =
                connector.requestBlockHeaders(blockNumber, 1).get(30, TimeUnit.SECONDS);
        if (headers.isEmpty()) return false;
        BlockHeadersMessage.VerifiedHeader vh = headers.get(0);
        // VerifiedHeader.hash() is keccak256(rawRLP) computed locally — compare to beacon anchor
        if (!java.util.Arrays.equals(vh.hash().toArrayUnsafe(), beaconBlockHash)) {
            log.info("[verify-block] Finalized block hash mismatch: peer={} beacon={}",
                    vh.hash().toShortHexString(), Bytes32.wrap(beaconBlockHash).toShortHexString());
            return false;
        }
        // Also confirm stateRoot matches what the requested block header has
        return java.util.Arrays.equals(vh.header().stateRoot.toArrayUnsafe(), expectedStateRoot);
    }

    /**
     * Verify a chain of blocks anchored to the beacon-attested block hash.
     *
     * Fetches headers from startBlock to endBlock. The header at finalizedBlockNum
     * must have keccak256(RLP) == beaconBlockHash (the sync-committee-verified anchor).
     * All other headers are verified via parent-hash chaining from that anchor.
     */
    private boolean verifyBlockChainFromBeacon(long startBlock, long endBlock,
                                                byte[] beaconBlockHash) throws Exception {
        long finalizedBlockNum = beaconSyncState.getExecutionBlockNumber();
        int total = (int) (endBlock - startBlock + 1);
        if (total < 2 || total > MAX_HEADER_CHAIN_GAP) {
            log.info("[verify-block] Block chain gap {} — out of range [2, {}]", total, MAX_HEADER_CHAIN_GAP);
            return false;
        }

        log.info("[verify-block] Fetching {} headers from block #{} to #{}", total, startBlock, endBlock);
        List<BlockHeadersMessage.VerifiedHeader> allHeaders =
                connector.requestBlockHeadersBatched(startBlock, total)
                        .get(120, TimeUnit.SECONDS);
        if (allHeaders.size() != total) {
            log.info("[verify-block] Expected {} headers, got {}", total, allHeaders.size());
            return false;
        }

        // Find the finalized block within the chain and verify its hash against beacon
        int anchorIndex = (int) (finalizedBlockNum - startBlock);
        if (anchorIndex < 0 || anchorIndex >= allHeaders.size()) {
            log.info("[verify-block] Finalized block #{} not in range [{}, {}]",
                    finalizedBlockNum, startBlock, endBlock);
            return false;
        }
        BlockHeadersMessage.VerifiedHeader anchorHeader = allHeaders.get(anchorIndex);
        if (!java.util.Arrays.equals(anchorHeader.hash().toArrayUnsafe(), beaconBlockHash)) {
            log.info("[verify-block] Anchor block hash mismatch at #{}: peer={} beacon={}",
                    finalizedBlockNum, anchorHeader.hash().toShortHexString(),
                    Bytes32.wrap(beaconBlockHash).toShortHexString());
            return false;
        }

        // Verify parent-hash chain continuity across all headers
        for (int i = 0; i < allHeaders.size() - 1; i++) {
            Bytes32 currentHash = allHeaders.get(i).hash();
            Bytes32 nextParent = allHeaders.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                log.info("[verify-block] Hash chain break at index {}: block #{} hash={} != block #{} parentHash={}",
                        i, allHeaders.get(i).header().number, currentHash.toShortHexString(),
                        allHeaders.get(i + 1).header().number, nextParent.toShortHexString());
                return false;
            }
        }

        log.info("[verify-block] Block chain verified: {} headers anchored at finalized block #{}",
                total, finalizedBlockNum);
        return true;
    }

    private String handleGetAccount(String jsonLine) {
        String addr = extractString(jsonLine, "address");
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            return jsonError("address must be a 20-byte hex string (40 hex chars)");
        }
        Bytes address = Bytes.fromHexString(hex);
        Bytes32 accountHash = Hash.keccak256(address);
        try {
            // Use peer's fresh state root to avoid pruning issues —
            // peers prune state beyond ~128 blocks, so a beacon-finalized root
            // (6+ min old) is usually too stale for them to serve.
            AccountRangeMessage.DecodeResult result =
                connector.requestAccount(address).get(30, TimeUnit.SECONDS);
            AccountRangeMessage.AccountData found = result.accounts().stream()
                .filter(a -> a.accountHash().equals(accountHash))
                .findFirst().orElse(null);
            // Build proof array
            StringBuilder proofSb = new StringBuilder("[");
            for (int i = 0; i < result.proof().size(); i++) {
                if (i > 0) proofSb.append(",");
                proofSb.append("\"").append(result.proof().get(i).toHexString()).append("\"");
            }
            proofSb.append("]");
            String proofJson = proofSb.toString();

            // Verify proof against the peer's state root (should always pass if proof is non-empty)
            // and against the beacon-verified state root (passes only if roots coincide)
            String verificationJson = buildVerificationJson(address.toArrayUnsafe(), result.proof(),
                    found != null ? found.nonce() : -1,
                    found != null ? found.balance().toString() : null,
                    result.stateRoot(), result.blockNumber());

            // storageRoot/codeHash from the proof-verified leaf, not the peer's
            // slim body — a peer can forge those two while keeping nonce/balance
            // honest, and the slim values would otherwise ride along as "verified".
            MerklePatriciaVerifier.VerifiedAccount verifiedAcct =
                    (found != null && result.stateRoot() != null && !result.proof().isEmpty())
                            ? MerklePatriciaVerifier.verifyAndExtractAccount(
                                    result.stateRoot().toArrayUnsafe(), address.toArrayUnsafe(),
                                    result.proof().stream().map(Bytes::toArrayUnsafe).toList(),
                                    found.nonce(), found.balance().toString())
                            : null;

            if (found == null) {
                return "{\"ok\":true,\"exists\":false"
                    + ",\"address\":\"" + addr + "\""
                    + ",\"accountHash\":\"" + accountHash.toHexString() + "\""
                    + ",\"proof\":" + proofJson
                    + ",\"verification\":" + verificationJson + "}";
            }
            return "{\"ok\":true,\"exists\":true"
                + ",\"address\":\"" + addr + "\""
                + ",\"accountHash\":\"" + found.accountHash().toHexString() + "\""
                + ",\"nonce\":" + found.nonce()
                + ",\"balance\":\"" + found.balance() + "\""
                + ",\"storageRoot\":\"" + (verifiedAcct != null
                        ? Bytes.wrap(verifiedAcct.storageRoot()).toHexString()
                        : found.storageRoot().toHexString()) + "\""
                + ",\"codeHash\":\"" + (verifiedAcct != null
                        ? Bytes.wrap(verifiedAcct.codeHash()).toHexString()
                        : found.codeHash().toHexString()) + "\""
                + ",\"proof\":" + proofJson
                + ",\"verification\":" + verificationJson + "}";
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            return jsonError(msg);
        }
    }

    private String handleGetStorage(String jsonLine) {
        String addr = extractString(jsonLine, "address");
        String slotStr = extractString(jsonLine, "slot");
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            return jsonError("address must be a 20-byte hex string (40 hex chars)");
        }
        Bytes contractAddress = Bytes.fromHexString(hex);

        // Parse slot number
        long slotNumber;
        try {
            slotNumber = Long.parseLong(slotStr);
        } catch (NumberFormatException e) {
            return jsonError("slot must be a number");
        }

        // Check if a holder address is provided (for ERC-20 mapping lookups)
        String holderAddr = null;
        try { holderAddr = extractString(jsonLine, "holder"); } catch (Exception ignored) {}

        // Compute the storage key
        byte[] storageSlotKey;
        if (holderAddr != null) {
            // ERC-20 mapping: keccak256(abi.encode(holderAddress, uint256(slot)))
            String holderHex = (holderAddr.startsWith("0x") || holderAddr.startsWith("0X"))
                    ? holderAddr.substring(2) : holderAddr;
            if (holderHex.length() != 40) {
                return jsonError("holder must be a 20-byte hex string (40 hex chars)");
            }
            byte[] holderBytes = Bytes.fromHexString(holderHex).toArrayUnsafe();
            byte[] encoded = new byte[64];
            // Left-pad holder address to 32 bytes
            System.arraycopy(holderBytes, 0, encoded, 12, 20);
            // uint256(slot) as 32 bytes big-endian
            encoded[63] = (byte) (slotNumber);
            encoded[62] = (byte) (slotNumber >>> 8);
            encoded[61] = (byte) (slotNumber >>> 16);
            encoded[60] = (byte) (slotNumber >>> 24);
            encoded[59] = (byte) (slotNumber >>> 32);
            encoded[58] = (byte) (slotNumber >>> 40);
            encoded[57] = (byte) (slotNumber >>> 48);
            encoded[56] = (byte) (slotNumber >>> 56);
            storageSlotKey = Hash.keccak256(Bytes.wrap(encoded)).toArrayUnsafe();
        } else {
            // Direct slot access: key = uint256(slot) as 32 bytes big-endian
            byte[] slotBytes = new byte[32];
            slotBytes[31] = (byte) (slotNumber);
            slotBytes[30] = (byte) (slotNumber >>> 8);
            slotBytes[29] = (byte) (slotNumber >>> 16);
            slotBytes[28] = (byte) (slotNumber >>> 24);
            slotBytes[27] = (byte) (slotNumber >>> 32);
            slotBytes[26] = (byte) (slotNumber >>> 40);
            slotBytes[25] = (byte) (slotNumber >>> 48);
            slotBytes[24] = (byte) (slotNumber >>> 56);
            storageSlotKey = slotBytes;
        }

        Bytes32 storageKeyHash = Hash.keccak256(Bytes.wrap(storageSlotKey));

        try {
            // Step 1: fetch the account to get storageRoot
            // Use peer's fresh state root to avoid pruning issues —
            // peers prune state beyond ~128 blocks, so a beacon-finalized root
            // (6+ min old) is usually too stale for them to serve.
            Bytes32 accountHash = Hash.keccak256(contractAddress);
            AccountRangeMessage.DecodeResult accountResult =
                connector.requestAccount(contractAddress).get(30, TimeUnit.SECONDS);
            AccountRangeMessage.AccountData account = accountResult.accounts().stream()
                .filter(a -> a.accountHash().equals(accountHash))
                .findFirst().orElse(null);
            if (account == null) {
                return jsonError("Contract account not found");
            }

            // Step 2: fetch storage slot using the same peer state root for consistency
            Bytes32 snapStateRoot = accountResult.stateRoot();

            // Take storageRoot from the PROOF-VERIFIED account leaf, not the peer's
            // slim body. Otherwise a peer could forge storageRoot (keeping nonce/
            // balance honest) plus a matching storage proof and fabricate a
            // "verified" slot value. snapStateRoot is anchored to the beacon below.
            List<byte[]> accountProofBytes = accountResult.proof().stream()
                    .map(Bytes::toArrayUnsafe).toList();
            MerklePatriciaVerifier.VerifiedAccount verifiedAccount =
                    snapStateRoot == null ? null
                            : MerklePatriciaVerifier.verifyAndExtractAccount(
                                    snapStateRoot.toArrayUnsafe(),
                                    contractAddress.toArrayUnsafe(), accountProofBytes,
                                    account.nonce(), account.balance().toString());
            if (verifiedAccount == null) {
                return jsonError("Contract account proof did not verify against peer state root");
            }
            Bytes32 storageRoot = Bytes32.wrap(verifiedAccount.storageRoot());
            StorageRangesMessage.DecodeResult storageResult =
                connector.requestStorage(contractAddress, storageKeyHash, snapStateRoot)
                    .get(30, TimeUnit.SECONDS);

            // Find matching slot
            StorageRangesMessage.StorageData found = storageResult.slots().stream()
                .filter(s -> s.slotHash().equals(storageKeyHash))
                .findFirst().orElse(null);

            // Build proof array
            StringBuilder proofSb = new StringBuilder("[");
            for (int i = 0; i < storageResult.proof().size(); i++) {
                if (i > 0) proofSb.append(",");
                proofSb.append("\"").append(storageResult.proof().get(i).toHexString()).append("\"");
            }
            proofSb.append("]");

            // Verify storage proof against storageRoot
            boolean storageProofValid = false;
            if (!storageResult.proof().isEmpty()) {
                List<byte[]> proofBytes = storageResult.proof().stream()
                    .map(Bytes::toArrayUnsafe).toList();
                byte[] leafValue = MerklePatriciaVerifier.verifyStorageProof(
                    storageRoot.toArrayUnsafe(), storageSlotKey, proofBytes);
                storageProofValid = (leafValue != null);
            }

            // Verify account's state root against beacon state
            boolean beaconChainVerified = false;
            boolean blsVerified = false;
            long matchedSlot = -1;
            String verifyMethod = null;
            String failReason = null;
            Bytes32 usedStateRoot = accountResult.stateRoot();
            if (usedStateRoot != null) {
                BeaconSyncState.SlottedStateRoot match =
                    beaconSyncState.findStateRoot(usedStateRoot.toArrayUnsafe());
                if (match != null) {
                    beaconChainVerified = true;
                    matchedSlot = match.slot();
                    blsVerified = match.blsVerified();
                    verifyMethod = "stateRootMatch";
                }
            }

            // Header chain verification fallback. Mirror get-account's
            // buildVerificationJson flow so that a "beaconChainVerified:false"
            // response always comes with a named failReason — silent nopes
            // used to turn into a 3-boolean blob that was impossible to debug.
            long peerBlockNumber = accountResult.blockNumber();
            if (!beaconChainVerified) {
                // Atomic snapshot: block number + state root must come from the same
                // finalized payload, since the header chain is anchored at the block
                // number and required to terminate at the state root.
                BeaconSyncState.FinalizedExecution fin = beaconSyncState.getFinalizedExecution();
                long finalizedBlockNum = fin.blockNumber();
                byte[] beaconRoot = fin.stateRoot();
                if (usedStateRoot == null) {
                    failReason = "noPeerStateRoot";
                } else if (!storageProofValid) {
                    failReason = "peerProofInvalid";
                } else if (!beaconSyncState.isSynced()) {
                    failReason = "beaconNotSynced";
                } else if (peerBlockNumber <= 0) {
                    failReason = "noPeerBlockNumber";
                } else if (finalizedBlockNum <= 0 || beaconRoot == null) {
                    failReason = "beaconBlockUnavailable";
                } else if (peerBlockNumber <= finalizedBlockNum) {
                    failReason = "peerBlockBehindFinalized";
                } else if (peerBlockNumber - finalizedBlockNum > MAX_HEADER_CHAIN_GAP) {
                    failReason = "headerChainGapTooLarge";
                } else {
                    log.info("[verify] headerChain: peerBlock={}, finalizedBlock={}, gap={}",
                            peerBlockNumber, finalizedBlockNum, peerBlockNumber - finalizedBlockNum);
                    try {
                        boolean chainValid = verifyHeaderChainBatched(
                                finalizedBlockNum, peerBlockNumber, beaconRoot,
                                usedStateRoot.toArrayUnsafe());
                        if (chainValid) {
                            beaconChainVerified = true;
                            matchedSlot = beaconSyncState.getFinalizedSlot();
                            blsVerified = true;
                            verifyMethod = "headerChain";
                        } else {
                            failReason = "headerChainInvalid";
                        }
                    } catch (Exception e) {
                        log.info("[verify] Header chain verification failed: {}", e.getMessage());
                        failReason = "headerChainError";
                    }
                }
            }

            String valueHex = found != null ? found.slotValue().toHexString() : null;
            java.math.BigInteger valueInt = null;
            if (found != null && !found.slotValue().isEmpty()) {
                valueInt = new java.math.BigInteger(1, found.slotValue().toArrayUnsafe());
            }

            StringBuilder sb = new StringBuilder("{\"ok\":true");
            sb.append(",\"address\":\"").append(addr).append("\"");
            sb.append(",\"slot\":").append(slotNumber);
            if (holderAddr != null) {
                sb.append(",\"holder\":\"").append(holderAddr).append("\"");
            }
            sb.append(",\"storageKey\":\"0x").append(bytesToHex(storageSlotKey)).append("\"");
            sb.append(",\"storageKeyHash\":\"").append(storageKeyHash.toHexString()).append("\"");
            if (found != null) {
                sb.append(",\"exists\":true");
                sb.append(",\"value\":\"").append(valueHex).append("\"");
                if (valueInt != null) {
                    sb.append(",\"valueDecimal\":\"").append(valueInt).append("\"");
                }
            } else {
                sb.append(",\"exists\":false");
                sb.append(",\"slotsReturned\":").append(storageResult.slots().size());
            }
            sb.append(",\"storageRoot\":\"").append(storageRoot.toHexString()).append("\"");
            sb.append(",\"proof\":").append(proofSb);
            sb.append(",\"verification\":{");
            sb.append("\"storageProofValid\":").append(storageProofValid);
            sb.append(",\"beaconSynced\":").append(beaconSyncState.isSynced());
            sb.append(",\"beaconChainVerified\":").append(beaconChainVerified);
            if (beaconChainVerified) {
                sb.append(",\"matchedBeaconSlot\":").append(matchedSlot);
                sb.append(",\"blsVerified\":").append(blsVerified);
                if (verifyMethod != null) {
                    sb.append(",\"verifyMethod\":\"").append(verifyMethod).append("\"");
                }
            } else {
                if (failReason != null) {
                    sb.append(",\"failReason\":\"").append(failReason).append("\"");
                }
                // Always surface the numbers so the operator can see *how far*
                // off we are, not just that we're off. Emit both finalized and
                // optimistic anchors — headerChainGapTooLarge is meaningful only
                // after you see which anchor was considered.
                long finalizedBlockNum = beaconSyncState.getExecutionBlockNumber();
                long finalizedSlot = beaconSyncState.getFinalizedSlot();
                long optBlockNum = beaconSyncState.getOptimisticBlockNumber();
                long optSlot = beaconSyncState.getOptimisticSlot();
                sb.append(",\"peerBlockNumber\":").append(peerBlockNumber);
                sb.append(",\"finalizedBlockNumber\":").append(finalizedBlockNum);
                sb.append(",\"optimisticBlockNumber\":").append(optBlockNum);
                if (peerBlockNumber > 0 && finalizedBlockNum > 0) {
                    sb.append(",\"blockGap\":").append(peerBlockNumber - finalizedBlockNum);
                }
                if (peerBlockNumber > 0 && optBlockNum > 0) {
                    sb.append(",\"optimisticBlockGap\":").append(peerBlockNumber - optBlockNum);
                }
                sb.append(",\"maxHeaderChainGap\":").append(MAX_HEADER_CHAIN_GAP);
                sb.append(",\"finalizedSlot\":").append(finalizedSlot);
                sb.append(",\"optimisticSlot\":").append(optSlot);
            }
            sb.append("}}");
            return sb.toString();
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
            return jsonError(msg);
        }
    }

    /**
     * Shared single-thread pool that drives the EVM for the {@code resolve-ens}
     * command (and any future EVM-backed commands). Created lazily on first
     * use; survives for the daemon's lifetime. Daemon thread, so it doesn't
     * keep the JVM alive on shutdown.
     *
     * <p>Reusing one pool across requests avoids the per-request
     * {@code Executors.newSingleThreadExecutor} / {@code shutdown} churn
     * that an earlier draft of {@code handleResolveEns} did. The thread is
     * single because Besu's EVM is sequential per-call; concurrent
     * resolutions would either need separate pools or a bounded
     * {@code newFixedThreadPool}, but the daemon serializes commands
     * anyway.
     */
    private static final java.util.concurrent.ExecutorService EVM_POOL =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "myotis-evm-cmd");
                t.setDaemon(true);
                return t;
            });

    /**
     * Resolve {@code name → address} via ENSIP-1 + ENSIP-10 (Universal Resolver),
     * with ERC-3668 CCIP-Read transparently handled for off-chain names
     * (Coinbase IDs, Uniswap names, Base subdomains, …).
     *
     * <p>Builds the full executor stack on demand:
     * <pre>
     *   CcipReadEvmExecutor
     *     └─ PrefetchingEvmExecutor
     *         └─ DefaultEvmExecutor
     *             └─ SnapBackedStateOracle
     *                 └─ EthHandlerSnapPeer (over a snap-capable peer)
     * </pre>
     *
     * <p>{@link BlockContext} fields come from a freshly-fetched header — the
     * peer's chain head — rather than the beacon-finalized header. Peers prune
     * state beyond ~128 blocks, so a 6-minute-old finalized root is usually
     * stale; the chain-head root is recent enough to serve. Acceptable here
     * because resolver contracts inspect block.timestamp / block.number for
     * deadline-style guards, not for trust decisions, and the headers we read
     * came from peers we already trust to serve snap data.
     *
     * <p>The CCIP-Read gateway transport is a tiny inline {@link CcipGateway}
     * impl over {@code java.net.http.HttpClient}. That's JVM-only and so not
     * suitable for the Android wallet — but {@code :app} is the daemon, not
     * the Android consumer, and the daemon already runs on JVM 21. The
     * Android module supplies a Ktor-backed {@link CcipGateway} per the
     * {@code CLAUDE.md} platform direction.
     */
    private String handleResolveEns(String jsonLine) {
        String name = extractString(jsonLine, "name");
        // Pause acquiring new peers for the duration of the resolution so its
        // snap round-trips aren't starved by outbound-dial bursts on the shared
        // event loop. See RLPxConnector.isSnapHeavy().
        connector.enterSnapHeavy();
        try {
        // AUTO: resolve against the beacon-verified finalized state first; only if
        // it yields no address (record not yet finalized) or can't be served do we
        // fall back to the peer head (returned with beaconVerified=false).
        EnsCallContext fin = null;
        Exception finErr = null;
        try {
            fin = prepareEnsCall(io.myotis.ens.EnsResolutionRoot.FINALIZED);
            java.util.Optional<io.myotis.evm.Address> resolved =
                fin.resolver.resolveAddress(name, fin.blockCtx).get(60, TimeUnit.SECONDS);
            if (resolved.isPresent()) {
                return resolveEnsJson(name, resolved.get().toHex(), true, fin.blockNumber);
            }
            // No record at the finalized block — fall through to the head.
        } catch (Exception e) {
            finErr = e;
            log.debug("[ens] finalized resolution failed for {} ({}); falling back to head",
                name, unwrapMessage(e));
        }
        // If the finalized attempt already consumed an ERC-3668 offchain (CCIP)
        // answer, the result is determined by the gateway, not by which EL state
        // root we ran against — re-resolving at the peer head would just repeat
        // the same (slow, multi-round-trip) gateway calls for the same answer.
        // (If finalized had produced an address we'd have returned above.)
        if (fin != null && fin.offchainExecutor().usedOffchain()) {
            if (finErr != null) {
                // The offchain gateway FAILED (e.g. HTTP 429 rate-limit) rather than
                // returning a valid empty record. Surface that as a transient error
                // — reporting "does not resolve" here would wrongly imply the name
                // has no address.
                return jsonError("ENS gateway error (try again): " + unwrapMessage(finErr));
            }
            log.debug("[ens] {} used an offchain gateway at finalized; skipping head fallback", name);
            return "{\"ok\":true,\"resolved\":false"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"beaconVerified\":false"
                + ",\"blockNumber\":" + fin.blockNumber + "}";
        }
        try {
            EnsCallContext head = prepareEnsCall(io.myotis.ens.EnsResolutionRoot.PEER_HEAD);
            java.util.Optional<io.myotis.evm.Address> resolved =
                head.resolver.resolveAddress(name, head.blockCtx).get(60, TimeUnit.SECONDS);
            if (resolved.isEmpty()) {
                return "{\"ok\":true,\"resolved\":false"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"beaconVerified\":false"
                    + ",\"blockNumber\":" + head.blockNumber + "}";
            }
            return resolveEnsJson(name, resolved.get().toHex(), false, head.blockNumber);
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
        } finally {
            connector.exitSnapHeavy();
        }
    }

    private static String resolveEnsJson(String name, String addressHex, boolean beaconVerified, long blockNumber) {
        return "{\"ok\":true,\"resolved\":true"
            + ",\"name\":\"" + escapeJson(name) + "\""
            + ",\"address\":\"" + addressHex + "\""
            + ",\"beaconVerified\":" + beaconVerified
            + ",\"blockNumber\":" + blockNumber + "}";
    }

    // -----------------------------------------------------------------------
    // ENS shared call setup
    // -----------------------------------------------------------------------

    /**
     * Aggregate of the per-call EVM context every ENS handler needs:
     * the peer-servable header (for the response's blockNumber), the
     * BlockContext built from it, and a network-aware
     * {@link io.myotis.ens.EnsResolver}. Constructed via
     * {@link #prepareEnsCall()} so the snap-peer probe + EVM stack
     * boilerplate isn't duplicated across the eight ENS commands.
     */
    private record EnsCallContext(
            long blockNumber,
            boolean beaconVerified,
            io.myotis.evm.BlockContext blockCtx,
            io.myotis.ens.EnsResolver resolver,
            io.myotis.evm.CcipReadEvmExecutor offchainExecutor) {}

    /**
     * Probe every active snap peer in parallel for a fresh head, pick the
     * first one with a sensible block number, and pin <em>that</em> peer
     * for every state read of the resolution. We MUST take the stateRoot
     * from the same peer that will serve the SNAP requests: peers prune
     * trie state outside a ~128-block window and the snapshot is anchored
     * at the peer's own current head. A stateRoot from peer A used against
     * peer B reliably surfaces as
     * {@code InvalidProof[... missing node ... (path idx=0)]} — peer B has
     * no node hashing to A's root.
     *
     * <p>Wraps the result in {@link EnsCallContext} so every ENS handler
     * shares the same peer-probe + EVM-stack boilerplate. Throws on any
     * failure; callers fold the throw into a {@code jsonError} response.
     */
    private EnsCallContext prepareEnsCall() throws Exception {
        return prepareEnsCall(io.myotis.ens.EnsResolutionRoot.FINALIZED);
    }

    private EnsCallContext prepareEnsCall(io.myotis.ens.EnsResolutionRoot root) throws Exception {
        List<com.jaeckel.ethp2p.networking.eth.EthHandler> snapPeers =
            connector.activeSnapHandlers();
        if (snapPeers.isEmpty()) {
            throw new IllegalStateException("No active peer with snap/1 support");
        }

        // FINALIZED (default): resolve against the light client's beacon-verified
        // finalized execution header — the name→address mapping is then anchored to
        // a beacon-attested root. ~12 min stale (finality lag); a snap peer must
        // still retain that block's state, which they often DON'T (Geth prunes
        // trie state beyond ~128 blocks and serves snap from a flat layer that
        // lags the head). So we don't blindly pin a peer here — we probe each one
        // for the finalized root and pin the first that actually serves it. If
        // none do, we throw and AUTO falls back to the head.
        if (root == io.myotis.ens.EnsResolutionRoot.FINALIZED) {
            if (beaconLightClient == null) {
                throw new IllegalStateException("beacon light client not running (needed for verified ENS)");
            }
            com.jaeckel.ethp2p.consensus.types.LightClientHeader fin =
                beaconLightClient.getStore().getFinalizedHeader();
            if (fin == null) {
                throw new IllegalStateException("no beacon-verified finalized header yet");
            }
            com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader exec = fin.execution();
            org.apache.tuweni.bytes.Bytes32 finRoot =
                org.apache.tuweni.bytes.Bytes32.wrap(exec.stateRoot());
            com.jaeckel.ethp2p.networking.eth.EthHandler finPeer =
                firstPeerServing(snapPeers, finRoot);
            if (finPeer == null) {
                throw new IllegalStateException(
                    "no snap peer retains the beacon-finalized state (block #"
                    + exec.blockNumber() + ")");
            }
            io.myotis.evm.BlockContext finCtx = new io.myotis.evm.BlockContext(
                exec.stateRoot(),
                exec.blockNumber(),
                exec.timestamp(),
                leUint256ToBigInteger(exec.baseFeePerGas()),
                io.myotis.evm.Address.of(exec.feeRecipient()),
                exec.prevRandao(),
                java.math.BigInteger.valueOf(connector.getNetwork().networkId()),
                exec.gasLimit());
            io.myotis.evm.CcipReadEvmExecutor finExec = buildEnsResolver(finPeer, finCtx);
            return new EnsCallContext(exec.blockNumber(), true, finCtx,
                io.myotis.ens.EnsResolver.forChainId(finExec, connector.getNetwork().networkId()), finExec);
        }

        // PEER_HEAD: each snap peer has its own chain head, and the bleeding-edge
        // head root is frequently NOT yet snap-servable (the flat state lags the
        // head by a few blocks). The previous implementation pinned the first peer
        // that returned a fresh header and gave up if that one peer couldn't serve
        // its own head root — which is exactly the failure get-account avoids by
        // retrying across peers. So here we walk every peer: fetch its fresh head,
        // then PROBE that the peer actually serves a snap account at that root
        // before pinning it. The first peer that passes both is pinned for the
        // whole resolution (all reads anchor to one consistent root).
        long minSensibleHead = connector.getNetwork().minSensibleHeadBlock();
        // Live staleness floor: a peer whose head is behind the beacon-finalized exec
        // block can never anchor to the beacon chain (finality already passed it), yet
        // it still snap-serves its frozen root and would be pinned here — forcing the
        // finalized fallback while fresh-headed peers sit connected.
        if (beaconLightClient != null) {
            com.jaeckel.ethp2p.consensus.types.LightClientHeader finHdr =
                    beaconLightClient.getStore().getFinalizedHeader();
            if (finHdr != null) {
                minSensibleHead = Math.max(minSensibleHead, finHdr.execution().blockNumber());
            }
        }
        String lastError = null;
        for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : snapPeers) {
            if (!peer.isReady() || peer.isSnapServingFailed()) {
                continue;
            }
            try {
                BlockHeader head = peer.requestFreshHeadHeaderAsync().get(6, TimeUnit.SECONDS);
                if (head.number < minSensibleHead) {
                    lastError = "peer " + peer.getRemoteAddress()
                        + " returned stale head #" + head.number
                        + " (< floor #" + minSensibleHead + ")";
                    continue;
                }
                if (!servesRoot(peer, head.stateRoot)) {
                    lastError = "peer " + peer.getRemoteAddress()
                        + " does not snap-serve its head root (block #" + head.number + ")";
                    continue;
                }
                io.myotis.evm.BlockContext blockCtx = new io.myotis.evm.BlockContext(
                    head.stateRoot.toArrayUnsafe(),
                    head.number,
                    head.timestamp,
                    head.baseFeePerGas,
                    io.myotis.evm.Address.of(head.beneficiary.toArrayUnsafe()),
                    head.mixHashOrPrevRandao.toArrayUnsafe(),
                    java.math.BigInteger.valueOf(connector.getNetwork().networkId()),
                    head.gasLimit);
                io.myotis.evm.CcipReadEvmExecutor headExec = buildEnsResolver(peer, blockCtx);
                return new EnsCallContext(head.number, false, blockCtx,
                    io.myotis.ens.EnsResolver.forChainId(headExec, connector.getNetwork().networkId()), headExec);
            } catch (Exception e) {
                lastError = "peer " + peer.getRemoteAddress() + " probe failed: " + unwrapMessage(e);
            }
        }
        throw new IllegalStateException("No snap peer served a fresh head root for ENS"
            + (lastError != null ? " (" + lastError + ")" : ""));
    }

    /**
     * Probe account used only to confirm a peer can actually serve snap state at a
     * given root before we pin it for a whole ENS resolution. The beacon deposit
     * contract is present in every post-Merge state and is a high-traffic account,
     * so a non-empty proof for it means the peer retains that root's trie. Any
     * always-present account would do; this one is canonical and stable.
     */
    private static final org.apache.tuweni.bytes.Bytes32 SNAP_PROBE_ACCOUNT_HASH =
        org.apache.tuweni.crypto.Hash.keccak256(
            org.apache.tuweni.bytes.Bytes.fromHexString("0x00000000219ab540356cBB839Cbe05303d7705Fa"));

    /** First ready snap peer that returns a non-empty account proof at {@code root}, or null. */
    private com.jaeckel.ethp2p.networking.eth.EthHandler firstPeerServing(
            List<com.jaeckel.ethp2p.networking.eth.EthHandler> peers,
            org.apache.tuweni.bytes.Bytes32 root) {
        for (com.jaeckel.ethp2p.networking.eth.EthHandler peer : peers) {
            if (peer.isReady() && !peer.isSnapServingFailed() && servesRoot(peer, root)) {
                return peer;
            }
        }
        return null;
    }

    /** True if this peer returns a non-empty account proof for the probe account at {@code root}. */
    private boolean servesRoot(com.jaeckel.ethp2p.networking.eth.EthHandler peer,
                               org.apache.tuweni.bytes.Bytes32 root) {
        try {
            AccountRangeMessage.DecodeResult r =
                peer.requestAccountByHashAsync(SNAP_PROBE_ACCOUNT_HASH, root).get(10, TimeUnit.SECONDS);
            return r.proof() != null && !r.proof().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Build the EVM/ENS stack pinned to one snap peer for the given block context.
     * Shared by the FINALIZED and PEER_HEAD paths of {@link #prepareEnsCall}.
     * Retries inside the oracle still engage on transient failures (timeouts,
     * channel close), but every retry targets this one peer — the one expected to
     * have {@code blockCtx}'s stateRoot in its snapshot.
     */
    /** Snap-oracle per-fetch retry budget; each attempt rotates to a different ready
     *  snap peer so a slow/dead peer fails over instead of eating the whole budget. */
    private static final int SNAP_ORACLE_MAX_ATTEMPTS = 8;

    private io.myotis.evm.CcipReadEvmExecutor buildEnsResolver(
            com.jaeckel.ethp2p.networking.eth.EthHandler pinnedPeer,
            io.myotis.evm.BlockContext blockCtx) {
        // Snap requests carry the stateRoot explicitly, so ANY connected snap peer that
        // retains blockCtx's trie can serve them. Rotate the oracle's supplier (probed
        // peer first, then round-robin the ready set) so a peer that stalls on
        // GetAccountRange fails over instead of funnelling every retry into one dead
        // peer — the single-peer pin made each eth_call against a stalled peer eat the
        // full timeout while other peers held the same state.
        final com.jaeckel.ethp2p.networking.eth.EthHandler probedPeer = pinnedPeer;
        final java.util.concurrent.atomic.AtomicInteger rotation =
            new java.util.concurrent.atomic.AtomicInteger();
        // Peers that returned an empty proof / no-state for this head's stateRoot — deny
        // them for this context so the rotation converges on peers that actually serve
        // the root (see NodeService for the rationale). Per-context.
        final java.util.Set<com.jaeckel.ethp2p.networking.eth.EthHandler> rootDenied =
            java.util.concurrent.ConcurrentHashMap.newKeySet();
        io.myotis.evm.world.SnapBackedStateOracle oracle =
            new io.myotis.evm.world.SnapBackedStateOracle(
                () -> {
                    int n = rotation.getAndIncrement();
                    if (n == 0 && probedPeer.isReady() && !probedPeer.isSnapServingFailed()
                            && !rootDenied.contains(probedPeer)) {
                        final com.jaeckel.ethp2p.networking.eth.EthHandler pp = probedPeer;
                        return new com.jaeckel.ethp2p.app.snap.EthHandlerSnapPeer(
                            pp, () -> rootDenied.add(pp));
                    }
                    // activeSnapHandlers() already filters to ready, snap-negotiated,
                    // non-failed peers; drop the ones denied for this root.
                    java.util.List<com.jaeckel.ethp2p.networking.eth.EthHandler> ready =
                        new java.util.ArrayList<>();
                    for (com.jaeckel.ethp2p.networking.eth.EthHandler p : connector.activeSnapHandlers()) {
                        if (!rootDenied.contains(p)) ready.add(p);
                    }
                    if (ready.isEmpty()) return null;
                    final com.jaeckel.ethp2p.networking.eth.EthHandler chosen =
                        ready.get(Math.floorMod(n, ready.size()));
                    return new com.jaeckel.ethp2p.app.snap.EthHandlerSnapPeer(
                        chosen, () -> rootDenied.add(chosen));
                },
                ensBytecodeCache,
                SNAP_ORACLE_MAX_ATTEMPTS);
        io.myotis.evm.DefaultEvmExecutor base = new io.myotis.evm.DefaultEvmExecutor(
            oracle, ensBytecodeCache, EVM_POOL);
        io.myotis.evm.PrefetchingEvmExecutor prefetching =
            new io.myotis.evm.PrefetchingEvmExecutor(base);
        io.myotis.evm.ccipread.CcipReadHandler ccipHandler =
            new io.myotis.evm.ccipread.CcipReadHandler(new JavaHttpCcipGateway());
        // Returned (not just wrapped) so the caller can later read usedOffchain()
        // to decide whether an AUTO head-fallback is worthwhile.
        return new io.myotis.evm.CcipReadEvmExecutor(prefetching, ccipHandler);
    }

    /** Convert an SSZ uint256 (32-byte little-endian) to a non-negative BigInteger. */
    private static java.math.BigInteger leUint256ToBigInteger(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[i] = le[le.length - 1 - i];
        return new java.math.BigInteger(1, be);
    }

    private static String unwrapMessage(Exception e) {
        Throwable cause = e.getCause() != null ? e.getCause() : e;
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }

    // -----------------------------------------------------------------------
    // Extended ENS record-type IPC handlers
    // -----------------------------------------------------------------------

    private String handleResolveEnsText(String jsonLine) {
        String name = extractString(jsonLine, "name");
        String key  = extractString(jsonLine, "key");
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<String> value =
                ctx.resolver.resolveText(name, key, ctx.blockCtx).get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"key\":\"" + escapeJson(key) + "\""
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            return head + ",\"resolved\":true,\"value\":\"" + escapeJson(value.get()) + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsContenthash(String jsonLine) {
        String name = extractString(jsonLine, "name");
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<byte[]> value =
                ctx.resolver.resolveContenthash(name, ctx.blockCtx).get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            return head + ",\"resolved\":true,\"contenthash\":\""
                + Bytes.wrap(value.get()).toHexString() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsAddrCoin(String jsonLine) {
        String name = extractString(jsonLine, "name");
        long coinType = extractLong(jsonLine, "coinType");
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<byte[]> value =
                ctx.resolver.resolveMultiCoinAddress(name, coinType, ctx.blockCtx)
                    .get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"coinType\":" + coinType
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            return head + ",\"resolved\":true,\"address\":\""
                + Bytes.wrap(value.get()).toHexString() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsPubkey(String jsonLine) {
        String name = extractString(jsonLine, "name");
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<io.myotis.ens.EnsResolver.Pubkey> value =
                ctx.resolver.resolvePubkey(name, ctx.blockCtx).get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            io.myotis.ens.EnsResolver.Pubkey pk = value.get();
            return head + ",\"resolved\":true"
                + ",\"pubkeyX\":\"" + Bytes.wrap(pk.x()).toHexString() + "\""
                + ",\"pubkeyY\":\"" + Bytes.wrap(pk.y()).toHexString() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsAbi(String jsonLine) {
        String name = extractString(jsonLine, "name");
        long contentTypes;
        // Default to "any encoding the resolver supports" (1|2|4|8 = 0xF) only
        // when the field is absent. If it's present but malformed, let the
        // parse error surface — silently defaulting on bad input would hide
        // user typos like {"contentTypes": "two"}.
        if (jsonLine.contains("\"contentTypes\"")) {
            try {
                contentTypes = extractLong(jsonLine, "contentTypes");
            } catch (Exception e) {
                return jsonError("contentTypes: " + (e.getMessage() != null ? e.getMessage() : "malformed"));
            }
        } else {
            contentTypes = 0xFL;
        }
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<io.myotis.ens.EnsResolver.AbiRecord> value =
                ctx.resolver.resolveAbi(name, contentTypes, ctx.blockCtx)
                    .get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"contentTypes\":" + contentTypes
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            io.myotis.ens.EnsResolver.AbiRecord r = value.get();
            return head + ",\"resolved\":true"
                + ",\"contentType\":" + r.contentType()
                + ",\"data\":\"" + Bytes.wrap(r.data()).toHexString() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsDns(String jsonLine) {
        String name = extractString(jsonLine, "name");
        String dnsName = extractString(jsonLine, "dnsName");
        long resource = extractLong(jsonLine, "resource");
        if (resource < 0 || resource > 0xFFFFL) {
            return jsonError("resource must fit in uint16");
        }
        try {
            EnsCallContext ctx = prepareEnsCall();
            byte[] dnsNameWire = io.myotis.ens.DnsEncoder.encode(dnsName);
            java.util.Optional<byte[]> value =
                ctx.resolver.resolveDnsRecord(name, dnsNameWire, (int) resource, ctx.blockCtx)
                    .get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"dnsName\":\"" + escapeJson(dnsName) + "\""
                + ",\"resource\":" + resource
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            return head + ",\"resolved\":true,\"data\":\""
                + Bytes.wrap(value.get()).toHexString() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    private String handleResolveEnsInterface(String jsonLine) {
        String name = extractString(jsonLine, "name");
        String interfaceIdStr = extractString(jsonLine, "interfaceId");
        String hex = (interfaceIdStr.startsWith("0x") || interfaceIdStr.startsWith("0X"))
            ? interfaceIdStr.substring(2) : interfaceIdStr;
        if (hex.length() != 8) {
            return jsonError("interfaceId must be a 4-byte hex string (8 hex chars)");
        }
        byte[] interfaceId = Bytes.fromHexString(hex).toArrayUnsafe();
        try {
            EnsCallContext ctx = prepareEnsCall();
            java.util.Optional<io.myotis.evm.Address> value =
                ctx.resolver.resolveInterfaceImplementer(name, interfaceId, ctx.blockCtx)
                    .get(60, TimeUnit.SECONDS);
            String head = "{\"ok\":true"
                + ",\"name\":\"" + escapeJson(name) + "\""
                + ",\"interfaceId\":\"0x" + hex.toLowerCase() + "\""
                + ",\"blockNumber\":" + ctx.blockNumber;
            if (value.isEmpty()) {
                return head + ",\"resolved\":false}";
            }
            return head + ",\"resolved\":true,\"implementer\":\"" + value.get().toHex() + "\"}";
        } catch (Exception e) {
            return jsonError(unwrapMessage(e));
        }
    }

    /**
     * JVM-only {@link io.myotis.evm.ccipread.CcipGateway} backed by
     * {@code java.net.http.HttpClient}. Used by the daemon, where JVM 21 is
     * guaranteed. Android consumers must supply a Ktor-backed gateway per
     * {@code CLAUDE.md} (java.net.http isn't covered by Android core library
     * desugaring below API 33).
     *
     * <p>Per ERC-3668 §6.1, any non-2xx HTTP status code must be treated as
     * an error so {@link io.myotis.evm.ccipread.CcipReadHandler} can fall
     * through to the next URL in the gateway list. We surface non-2xx as a
     * failed future carrying an {@link java.io.IOException} with the status
     * code and URL, which the handler's {@code exceptionallyCompose} catches
     * and folds into the per-URL diagnostic list.
     */
    private static final class JavaHttpCcipGateway implements io.myotis.evm.ccipread.CcipGateway {
        private static final java.net.http.HttpClient CLIENT = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(10))
                .build();

        @Override
        public java.util.concurrent.CompletableFuture<String> request(Method method, String url, String body) {
            java.net.http.HttpRequest.Builder rb = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(15));
            if (method == Method.POST) {
                rb.header("Content-Type", "application/json");
                rb.POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                        body == null ? "" : body));
            } else {
                rb.GET();
            }
            return CLIENT.sendAsync(rb.build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString())
                    .thenCompose(resp -> {
                        int status = resp.statusCode();
                        if (status >= 200 && status < 300) {
                            return java.util.concurrent.CompletableFuture.completedFuture(resp.body());
                        }
                        return java.util.concurrent.CompletableFuture.failedFuture(
                                new java.io.IOException("HTTP " + status + " from " + url));
                    });
        }
    }

    private String handleBeaconStatus() {
        // Peer / discovery counters — same shape as `status` for the EL side so
        // the two outputs compare apples-to-apples.
        long uptimeSec = (System.currentTimeMillis() - startTimeMs) / 1000;
        int discv5Live = discV5 != null ? discV5.liveNodeCount() : 0;
        List<BeaconP2PService.PeerInfo> peers = beaconLightClient != null
                ? beaconLightClient.getConnectedPeers()
                : List.of();
        int connectedPeers = peers.size();
        long lightClientPeers = peers.stream()
                .filter(BeaconP2PService.PeerInfo::supportsLightClient)
                .count();
        String peerStats = "\"uptimeSeconds\":" + uptimeSec
                + ",\"discoveredPeers\":" + discv5Live
                + ",\"connectedPeers\":" + connectedPeers
                + ",\"lightClientPeers\":" + lightClientPeers;

        String peersJson = buildBeaconPeersJson();
        BeaconSyncState.State state = beaconSyncState.getSyncState(clGenesisTime);
        // Sync-committee period progress, surfaced next to `state` so catch-up
        // progress is visible at a glance: currentPeriod / targetPeriod.
        // currentPeriod is the committee we hold (0 before bootstrap); targetPeriod
        // is the wall-clock period we're catching up to.
        long currentPeriod = beaconSyncState.getCurrentSyncCommitteePeriod();
        long targetPeriod = BeaconChainSpec.currentPeriod(clGenesisTime);
        String periodProgress = "\"currentPeriod\":" + currentPeriod
                + ",\"targetPeriod\":" + targetPeriod;
        if (state == BeaconSyncState.State.SYNCING) {
            return "{\"ok\":true,\"state\":\"SYNCING\","
                    + periodProgress + ","
                    + peerStats
                    + ",\"finalizedSlot\":0,\"optimisticSlot\":0"
                    + ",\"executionStateRoot\":null"
                    + ",\"knownStateRoots\":" + beaconSyncState.getKnownStateRootCount()
                    + ",\"peers\":" + peersJson + "}";
        }
        byte[] stateRoot = beaconSyncState.getVerifiedExecutionStateRoot();
        String stateRootHex = stateRoot != null ? "\"0x" + bytesToHex(stateRoot) + "\"" : "null";
        long finalizedSlot = beaconSyncState.getFinalizedSlot();
        long optimisticSlot = beaconSyncState.getOptimisticSlot();
        long finalizedPeriod = finalizedSlot / (32 * 256); // SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD
        return "{\"ok\":true,\"state\":\"" + state.name() + "\","
                + periodProgress + ","
                + peerStats
                + ",\"finalizedSlot\":" + finalizedSlot
                + ",\"optimisticSlot\":" + optimisticSlot
                + ",\"finalizedPeriod\":" + finalizedPeriod
                + ",\"syncCommitteePeriod\":" + currentPeriod
                + ",\"wallClockPeriod\":" + targetPeriod
                + ",\"executionStateRoot\":" + stateRootHex
                + ",\"executionBlockNumber\":" + beaconSyncState.getExecutionBlockNumber()
                + ",\"knownStateRoots\":" + beaconSyncState.getKnownStateRootCount()
                + ",\"fillThreshold\":" + BeaconSyncState.FILL_THRESHOLD
                + ",\"peers\":" + peersJson + "}";
    }

    private String buildBeaconPeersJson() {
        if (beaconLightClient == null) return "[]";
        List<BeaconP2PService.PeerInfo> peers = beaconLightClient.getConnectedPeers();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (BeaconP2PService.PeerInfo p : peers) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"peerId\":\"").append(escapeJson(truncatePeerId(p.peerId()))).append("\"");
            sb.append(",\"remoteAddress\":\"").append(escapeJson(p.remoteAddress())).append("\"");
            if (p.agentVersion() != null) {
                sb.append(",\"clientId\":\"").append(escapeJson(p.agentVersion())).append("\"");
            }
            sb.append(",\"lightClient\":").append(p.supportsLightClient());
            sb.append(",\"protocols\":").append(p.protocols().size());
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private static String truncatePeerId(String peerId) {
        return peerId != null && peerId.length() > 16
                ? peerId.substring(0, 16) + "..." : peerId;
    }

    private String handleDial(String jsonLine) {
        // Parse enode URL: enode://<pubkey>@<host>:<port>
        String enode = extractString(jsonLine, "enode");
        try {
            if (!enode.startsWith("enode://")) {
                return jsonError("enode must start with enode://");
            }
            String rest = enode.substring("enode://".length());
            int atIdx = rest.indexOf('@');
            if (atIdx < 0) return jsonError("Invalid enode format: missing @");
            String pubKeyHex = rest.substring(0, atIdx);
            String hostPort = rest.substring(atIdx + 1).split("\\?")[0]; // strip query params
            int colonIdx = hostPort.lastIndexOf(':');
            if (colonIdx < 0) return jsonError("Invalid enode format: missing port");
            String host = hostPort.substring(0, colonIdx);
            int port = Integer.parseInt(hostPort.substring(colonIdx + 1));

            org.apache.tuweni.crypto.SECP256K1.PublicKey pubKey =
                org.apache.tuweni.crypto.SECP256K1.PublicKey.fromBytes(
                    org.apache.tuweni.bytes.Bytes.fromHexString(pubKeyHex));
            java.net.InetSocketAddress addr = new java.net.InetSocketAddress(host, port);
            log.info("[ipc] Dialing enode {} at {}", pubKeyHex.substring(0, 16) + "...", addr);
            connector.connect(addr, pubKey);
            return "{\"ok\":true,\"message\":\"Dialing " + host + ":" + port + "\"}";
        } catch (Exception e) {
            return jsonError("Failed to dial: " + e.getMessage());
        }
    }

    private String handleStop() {
        log.info("[ipc] Stop command received — initiating graceful shutdown");
        stopLatch.countDown();
        return "{\"ok\":true,\"message\":\"Daemon shutting down\"}";
    }

    // -------------------------------------------------------------------------
    // Beacon proof verification helpers
    // -------------------------------------------------------------------------

    private String buildVerificationJson(byte[] address, List<Bytes> proofNodes,
                                          long nonce, String balance,
                                          Bytes32 peerStateRoot, long peerBlockNumber) {
        List<byte[]> proofBytes = proofNodes.stream().map(Bytes::toArrayUnsafe).toList();

        // Verify against the peer's state root (the root the proof was actually built for)
        boolean peerProofValid = false;
        String peerStateRootHex = null;
        if (peerStateRoot != null && !proofBytes.isEmpty()) {
            peerProofValid = MerklePatriciaVerifier.verify(
                    peerStateRoot.toArrayUnsafe(), address, proofBytes, nonce, balance);
            peerStateRootHex = peerStateRoot.toHexString();
        }

        // Check if the peer's state root matches any beacon-attested block.
        boolean beaconChainVerified = false;
        boolean blsVerified = false;
        long matchedSlot = -1;
        String verifyMethod = null;
        String failReason = null;

        if (peerStateRoot != null) {
            BeaconSyncState.SlottedStateRoot match =
                    beaconSyncState.findStateRoot(peerStateRoot.toArrayUnsafe());
            if (match != null) {
                beaconChainVerified = true;
                matchedSlot = match.slot();
                blsVerified = match.blsVerified();
                verifyMethod = "stateRootMatch";
            }
        }

        // Atomic snapshot — see note at the get-storage verification path. Block number
        // and state root must describe the same finalized payload.
        BeaconSyncState.FinalizedExecution fin = beaconSyncState.getFinalizedExecution();
        long finalizedBlockNum = fin.blockNumber();
        byte[] beaconRoot = fin.stateRoot();
        long finalizedPeriod = beaconSyncState.getFinalizedPeriod();
        long wallClockPeriod = BeaconChainSpec.currentPeriod(clGenesisTime);
        long periodLag = wallClockPeriod - finalizedPeriod;

        if (!beaconChainVerified) {
            if (peerStateRoot == null) {
                failReason = "noPeerStateRoot";
            } else if (!peerProofValid) {
                failReason = "peerProofInvalid";
            } else if (!beaconSyncState.isSynced()) {
                failReason = "beaconNotSynced";
            } else if (peerBlockNumber <= 0) {
                failReason = "noPeerBlockNumber";
            } else if (finalizedBlockNum <= 0 || beaconRoot == null) {
                failReason = "beaconBlockUnavailable";
            } else if (peerBlockNumber <= finalizedBlockNum) {
                failReason = "peerBlockBehindFinalized";
            } else if (peerBlockNumber - finalizedBlockNum > MAX_HEADER_CHAIN_GAP) {
                failReason = "headerChainGapTooLarge";
            } else {
                log.info("[verify] headerChain: peerBlock={}, finalizedBlock={}, gap={}",
                        peerBlockNumber, finalizedBlockNum, peerBlockNumber - finalizedBlockNum);
                try {
                    boolean chainValid = verifyHeaderChainBatched(
                            finalizedBlockNum, peerBlockNumber, beaconRoot,
                            peerStateRoot.toArrayUnsafe());
                    if (chainValid) {
                        beaconChainVerified = true;
                        matchedSlot = beaconSyncState.getFinalizedSlot();
                        blsVerified = true;
                        verifyMethod = "headerChain";
                    } else {
                        failReason = "headerChainInvalid";
                    }
                } catch (Exception e) {
                    log.info("[verify] Header chain verification failed: {}", e.getMessage());
                    failReason = "headerChainError";
                }
            }
        }

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"peerProofValid\":").append(peerProofValid);
        if (peerStateRootHex != null) {
            sb.append(",\"peerStateRoot\":\"").append(peerStateRootHex).append("\"");
        }
        sb.append(",\"beaconSynced\":").append(beaconSyncState.isSynced());
        sb.append(",\"beaconChainVerified\":").append(beaconChainVerified);
        if (beaconChainVerified) {
            sb.append(",\"matchedBeaconSlot\":").append(matchedSlot);
            sb.append(",\"blsVerified\":").append(blsVerified);
            if (verifyMethod != null) {
                sb.append(",\"verifyMethod\":\"").append(verifyMethod).append("\"");
            }
        } else {
            if (failReason != null) {
                sb.append(",\"failReason\":\"").append(failReason).append("\"");
            }
            sb.append(",\"finalizedPeriod\":").append(finalizedPeriod);
            sb.append(",\"wallClockPeriod\":").append(wallClockPeriod);
            sb.append(",\"periodLag\":").append(periodLag);
            if (peerBlockNumber > 0) {
                sb.append(",\"peerBlockNumber\":").append(peerBlockNumber);
            }
            if (finalizedBlockNum > 0) {
                sb.append(",\"finalizedBlockNumber\":").append(finalizedBlockNum);
            }
            long optBlockNum = beaconSyncState.getOptimisticBlockNumber();
            if (optBlockNum > 0) {
                sb.append(",\"optimisticBlockNumber\":").append(optBlockNum);
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Verify a chain of consecutive block headers.
     * Checks that:
     * 1. The first header's state root matches the beacon-finalized root
     * 2. Each header's hash equals the next header's parentHash
     * 3. The last header's state root matches the peer's state root
     */
    private static boolean verifyHeaderChain(List<BlockHeadersMessage.VerifiedHeader> headers,
                                              byte[] expectedFirstStateRoot,
                                              byte[] expectedLastStateRoot) {
        if (headers.isEmpty()) return false;

        // Check first header's state root matches beacon-finalized root
        byte[] firstStateRoot = headers.get(0).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(firstStateRoot, expectedFirstStateRoot)) return false;

        // Check last header's state root matches peer's state root
        byte[] lastStateRoot = headers.get(headers.size() - 1).header().stateRoot.toArrayUnsafe();
        if (!java.util.Arrays.equals(lastStateRoot, expectedLastStateRoot)) return false;

        // Verify hash chain: each header's hash must equal the next header's parentHash
        for (int i = 0; i < headers.size() - 1; i++) {
            Bytes32 currentHash = headers.get(i).hash();
            Bytes32 nextParent = headers.get(i + 1).header().parentHash;
            if (!currentHash.equals(nextParent)) {
                log.info("[verify] Hash chain break at index {}: block #{} hash={} != block #{} parentHash={}",
                        i, headers.get(i).header().number, currentHash.toShortHexString(),
                        headers.get(i + 1).header().number, nextParent.toShortHexString());
                return false;
            }
        }
        return true;
    }

    /**
     * Fetch headers in batches from a single peer and verify the full chain.
     * Uses RLPxConnector.requestBlockHeadersBatched to ensure all batches
     * come from the same peer, preventing cross-peer discontinuities.
     */
    private boolean verifyHeaderChainBatched(long finalizedBlock, long peerBlock,
                                              byte[] beaconStateRoot, byte[] peerStateRoot)
            throws Exception {
        int total = (int) (peerBlock - finalizedBlock + 1);
        if (total < 2 || total > 8192) {
            log.info("[verify] Header chain gap {} blocks — out of range [2, 8192]", total);
            return false;
        }

        log.info("[verify] Fetching {} headers from block #{} to #{}", total, finalizedBlock, peerBlock);
        List<BlockHeadersMessage.VerifiedHeader> allHeaders =
                connector.requestBlockHeadersBatched(finalizedBlock, total)
                        .get(60, TimeUnit.SECONDS);

        boolean valid = verifyHeaderChain(allHeaders, beaconStateRoot, peerStateRoot);
        log.info("[verify] Full header chain ({} blocks) valid: {}", total, valid);
        if (!valid && !allHeaders.isEmpty()) {
            byte[] firstSR = allHeaders.get(0).header().stateRoot.toArrayUnsafe();
            byte[] lastSR = allHeaders.get(allHeaders.size() - 1).header().stateRoot.toArrayUnsafe();
            log.info("[verify] firstStateRoot match={}, lastStateRoot match={}",
                    java.util.Arrays.equals(firstSR, beaconStateRoot),
                    java.util.Arrays.equals(lastSR, peerStateRoot));
        }
        return valid;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
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

    // -------------------------------------------------------------------------
    // JSON helpers (no external library needed for simple commands)
    // -------------------------------------------------------------------------

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

    /** Minimal field extractor for string values: finds {@code "field":"value"} in flat JSON. */
    static String extractString(String json, String field) {
        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) throw new IllegalArgumentException("Missing field: " + field);
        int colon = json.indexOf(':', keyIdx + key.length());
        if (colon < 0) throw new IllegalArgumentException("Malformed JSON near field: " + field);
        int open = json.indexOf('"', colon + 1);
        if (open < 0) throw new IllegalArgumentException("Field '" + field + "' value is not a string");
        int close = json.indexOf('"', open + 1);
        if (close < 0) throw new IllegalArgumentException("Unterminated string for field: " + field);
        return json.substring(open + 1, close);
    }

    /** Minimal field extractor for long/integer values. */
    static long extractLong(String json, String field) {
        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) throw new IllegalArgumentException("Missing field: " + field);
        int colon = json.indexOf(':', keyIdx + key.length());
        if (colon < 0) throw new IllegalArgumentException("Malformed JSON near field: " + field);
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) end++;
        if (start == end) throw new IllegalArgumentException("Field '" + field + "' is not a number");
        return Long.parseLong(json.substring(start, end));
    }
}
