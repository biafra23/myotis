package com.jaeckel.ethp2p.app;

import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.BlockResult;
import io.myotis.api.ChainHandle;
import io.myotis.api.ClPeerInfo;
import io.myotis.api.ConnectedPeer;
import io.myotis.api.DialResult;
import io.myotis.api.DiscoveredPeer;
import io.myotis.api.EngineException;
import io.myotis.api.EnsAbiResult;
import io.myotis.api.EnsApi;
import io.myotis.api.EnsContenthashResult;
import io.myotis.api.EnsDnsRecordResult;
import io.myotis.api.EnsInterfaceResult;
import io.myotis.api.EnsMultiCoinResult;
import io.myotis.api.EnsPubkeyResult;
import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import io.myotis.api.EnsTextResult;
import io.myotis.api.HeadersResult;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.StorageProofResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;

/**
 * Handles JSON-Lines IPC commands dispatched by DaemonServer.
 *
 * <p>Consumes ONLY the engine API ({@code io.myotis.api.ChainHandle}) — the daemon is a
 * thin host: argument parsing and JSON serialization live here, every fetch and every
 * verification decision lives behind the API. The single exception is the
 * {@code get-transactions} debug stream ({@link DebugCommands}), a documented exemption
 * wired at the composition root.
 */
public class CommandHandler {

    private static final Logger log = LoggerFactory.getLogger(CommandHandler.class);

    private final ChainHandle handle;
    private final CountDownLatch stopLatch;
    private final DebugCommands debugCommands; // nullable: streaming debug commands disabled
    private final long startTimeMs;

    public CommandHandler(ChainHandle handle, CountDownLatch stopLatch, DebugCommands debugCommands) {
        this.handle = handle;
        this.stopLatch = stopLatch;
        this.debugCommands = debugCommands;
        this.startTimeMs = System.currentTimeMillis();
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
                case "pause"                   -> handlePause();
                case "resume"                  -> handleResume();
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
     * Returns true if the command was handled (streaming), false if it should fall back
     * to single-response.
     */
    public boolean handleStreaming(String jsonLine, BufferedWriter writer) {
        try {
            String cmd = extractString(jsonLine, "cmd");
            if ("get-transactions".equals(cmd)) {
                if (debugCommands == null) {
                    writer.write(jsonError("get-transactions is not available"));
                    writer.newLine();
                    writer.flush();
                    return true;
                }
                debugCommands.handleGetTransactions(jsonLine, writer);
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

    // -------------------------------------------------------------------------
    // Status / peers
    // -------------------------------------------------------------------------

    /** Pause the stack into idle sleep: networking off, RPC listening, first request wakes it. */
    private String handlePause() {
        log.info("[ipc] Pause command received");
        return handle.pause()
                ? "{\"ok\":true,\"lifecycle\":\"PAUSED\"}"
                : jsonError("pause failed (lifecycle: " + handle.lifecycle() + ")");
    }

    /** Resume a paused stack (also happens automatically on the first verified read). */
    private String handleResume() {
        log.info("[ipc] Resume command received");
        return handle.resume(io.myotis.api.WakeReason.IPC)
                ? "{\"ok\":true,\"lifecycle\":\"RUNNING\"}"
                : jsonError("resume failed (lifecycle: " + handle.lifecycle() + ")");
    }

    private String handleStatus() {
        long uptimeSec = (System.currentTimeMillis() - startTimeMs) / 1000;
        StatusSnapshot s = handle.status();
        String wakeReason = s.lastWakeReason() == null ? "null" : "\"" + s.lastWakeReason() + "\"";
        return "{\"ok\":true,\"state\":\"" + handle.lifecycle() + "\",\"uptimeSeconds\":" + uptimeSec
                + ",\"discoveredPeers\":" + s.discoveredPeers()
                + ",\"connectedPeers\":" + s.connectedPeers()
                + ",\"readyPeers\":" + s.readyPeers()
                + ",\"snapPeers\":" + s.snapPeers()
                + ",\"backedOffPeers\":" + s.backedOffPeers()
                + ",\"blacklistedPeers\":" + s.blacklistedPeers()
                + ",\"pauseCount\":" + s.pauseCount()
                + ",\"totalPausedMs\":" + s.totalPausedMs()
                + ",\"lastPauseEpochMs\":" + s.lastPauseEpochMs()
                + ",\"lastResumeEpochMs\":" + s.lastResumeEpochMs()
                + ",\"lastWakeReason\":" + wakeReason + "}";
    }

    private String handlePeers() {
        java.util.List<DiscoveredPeer> discovered = handle.discoveredPeers();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"count\":").append(discovered.size()).append(",\"peers\":[");
        boolean first = true;
        for (DiscoveredPeer e : discovered) {
            if (!first) sb.append(",");
            first = false;
            // Same 8-byte truncation the daemon has always shown ("0x" + 16 hex + "...").
            String id = e.nodeIdHex();
            String shortId = id != null && id.length() >= 18 ? id.substring(0, 18) + "..." : id;
            sb.append("{\"ip\":\"").append(e.host()).append("\"")
              .append(",\"udpPort\":").append(e.udpPort())
              .append(",\"tcpPort\":").append(e.tcpPort())
              .append(",\"nodeId\":\"").append(shortId).append("\"")
              .append("}");
        }
        sb.append("],\"connected\":[");
        first = true;
        for (ConnectedPeer p : handle.connectedPeers()) {
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

    private String handleBeaconStatus() {
        long uptimeSec = (System.currentTimeMillis() - startTimeMs) / 1000;
        BeaconStatus bs = handle.beaconStatus();
        String peerStats = "\"uptimeSeconds\":" + uptimeSec
                + ",\"discoveredPeers\":" + bs.discv5TableSize()
                + ",\"connectedPeers\":" + bs.connectedPeers()
                + ",\"lightClientPeers\":" + bs.lightClientPeers()
                + ",\"servedPeersLastMinute\":" + bs.servedPeersLastMinute();
        String peersJson = buildBeaconPeersJson(bs.peers());
        String periodProgress = "\"currentPeriod\":" + bs.currentPeriod()
                + ",\"targetPeriod\":" + bs.targetPeriod();
        if (bs.state() == BeaconState.SYNCING || bs.state() == BeaconState.STARTING) {
            return "{\"ok\":true,\"state\":\"SYNCING\","
                    + periodProgress + ","
                    + peerStats
                    + ",\"finalizedSlot\":0,\"optimisticSlot\":0"
                    + ",\"executionStateRoot\":null"
                    + ",\"knownStateRoots\":" + bs.knownStateRoots()
                    + ",\"peers\":" + peersJson + "}";
        }
        String stateRootHex = bs.executionStateRootHex() != null
                ? "\"" + bs.executionStateRootHex() + "\"" : "null";
        return "{\"ok\":true,\"state\":\"" + bs.state().name() + "\","
                + periodProgress + ","
                + peerStats
                + ",\"finalizedSlot\":" + bs.finalizedSlot()
                + ",\"optimisticSlot\":" + bs.optimisticSlot()
                + ",\"finalizedPeriod\":" + bs.finalizedPeriod()
                + ",\"syncCommitteePeriod\":" + bs.currentPeriod()
                + ",\"wallClockPeriod\":" + bs.targetPeriod()
                + ",\"executionStateRoot\":" + stateRootHex
                + ",\"executionBlockNumber\":" + bs.executionBlockNumber()
                + ",\"knownStateRoots\":" + bs.knownStateRoots()
                + ",\"fillThreshold\":" + bs.fillThreshold()
                + ",\"peers\":" + peersJson + "}";
    }

    private static String buildBeaconPeersJson(java.util.List<ClPeerInfo> peers) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (ClPeerInfo p : peers) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"peerId\":\"").append(escapeJson(truncatePeerId(p.peerId()))).append("\"");
            sb.append(",\"remoteAddress\":\"").append(escapeJson(p.remoteAddress())).append("\"");
            if (p.clientId() != null) {
                sb.append(",\"clientId\":\"").append(escapeJson(p.clientId())).append("\"");
            }
            sb.append(",\"lightClient\":").append(p.lightClient());
            sb.append(",\"protocols\":").append(p.protocols());
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private static String truncatePeerId(String peerId) {
        return peerId != null && peerId.length() > 16
                ? peerId.substring(0, 16) + "..." : peerId;
    }

    // -------------------------------------------------------------------------
    // Verified queries (fetch + verification live behind the engine API;
    // these handlers parse arguments and serialize)
    // -------------------------------------------------------------------------

    private String handleGetHeaders(String jsonLine) {
        long blockNumber = extractLong(jsonLine, "blockNumber");
        int count = (int) extractLong(jsonLine, "count");
        HeadersResult result = handle.getHeaders(blockNumber, count);
        if (result.error() != null) return jsonError(result.error());
        return buildHeadersJson(result);
    }

    private String handleGetBlock(String jsonLine) {
        long blockNumber = extractLong(jsonLine, "blockNumber");
        BlockResult r = handle.getBlockVerified(blockNumber);
        if (r.error() != null) return jsonError(r.error());
        return buildBlockJson(r);
    }

    private String handleGetAccount(String jsonLine) {
        String addr = extractString(jsonLine, "address");
        String hex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (hex.length() != 40) {
            return jsonError("address must be a 20-byte hex string (40 hex chars)");
        }
        try {
            AccountProofResult r = handle.requestAccount(addr);
            return buildAccountJson(addr, r);
        } catch (EngineException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleGetStorage(String jsonLine) {
        String addr = extractString(jsonLine, "address");
        String slotStr = extractString(jsonLine, "slot");

        // Validate the address FIRST — historical error precedence: a request with a bad
        // address and a bad slot reports the address problem.
        String addrHex = (addr.startsWith("0x") || addr.startsWith("0X")) ? addr.substring(2) : addr;
        if (addrHex.length() != 40) {
            return jsonError("address must be a 20-byte hex string (40 hex chars)");
        }

        long slotNumber;
        try {
            slotNumber = Long.parseLong(slotStr);
        } catch (NumberFormatException e) {
            return jsonError("slot must be a number");
        }

        String holderAddr = null;
        try { holderAddr = extractString(jsonLine, "holder"); } catch (Exception ignored) {}

        try {
            StorageProofResult r = handle.getStorageProof(addr, slotNumber, holderAddr);
            return buildStorageJson(r);
        } catch (EngineException e) {
            return jsonError(e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // ENS (resolution policy + EVM stack live behind the engine API)
    // -------------------------------------------------------------------------

    private EnsApi ens() {
        EnsApi ens = handle.ens();
        if (ens == null) {
            throw new IllegalStateException("ENS is not available on " + handle.networkName());
        }
        return ens;
    }

    private String handleResolveEns(String jsonLine) {
        String name = extractString(jsonLine, "name");
        try {
            EnsResolutionResult r = ens().resolveAddress(name, EnsRoot.AUTO);
            if (r.addressHex() != null) {
                return "{\"ok\":true,\"resolved\":true"
                        + ",\"name\":\"" + escapeJson(name) + "\""
                        + ",\"address\":\"" + r.addressHex() + "\""
                        + ",\"beaconVerified\":" + r.verified()
                        + ",\"blockNumber\":" + r.blockNumber() + "}";
            }
            // API convention: addressHex==null && error==null = successful "no record".
            if (r.error() == null) {
                return "{\"ok\":true,\"resolved\":false"
                        + ",\"name\":\"" + escapeJson(name) + "\""
                        + ",\"beaconVerified\":false"
                        + ",\"blockNumber\":" + r.blockNumber() + "}";
            }
            return jsonError(r.error());
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleResolveEnsText(String jsonLine) {
        String name = extractString(jsonLine, "name");
        String key = extractString(jsonLine, "key");
        try {
            EnsTextResult r = ens().resolveText(name, key);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"key\":\"" + escapeJson(key) + "\""
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.value() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true,\"value\":\"" + escapeJson(r.value()) + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleResolveEnsContenthash(String jsonLine) {
        String name = extractString(jsonLine, "name");
        try {
            EnsContenthashResult r = ens().resolveContenthash(name);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.contenthashHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true,\"contenthash\":\"" + r.contenthashHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleResolveEnsAddrCoin(String jsonLine) {
        String name = extractString(jsonLine, "name");
        long coinType = extractLong(jsonLine, "coinType");
        try {
            EnsMultiCoinResult r = ens().resolveMultiCoinAddr(name, coinType);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"coinType\":" + coinType
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.addressHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true,\"address\":\"" + r.addressHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleResolveEnsPubkey(String jsonLine) {
        String name = extractString(jsonLine, "name");
        try {
            EnsPubkeyResult r = ens().resolvePubkey(name);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.pubkeyXHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true"
                    + ",\"pubkeyX\":\"" + r.pubkeyXHex() + "\""
                    + ",\"pubkeyY\":\"" + r.pubkeyYHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    private String handleResolveEnsAbi(String jsonLine) {
        String name = extractString(jsonLine, "name");
        long contentTypes;
        // Default to "any encoding the resolver supports" (1|2|4|8 = 0xF) only when the
        // field is absent. If present but malformed, surface the parse error — silently
        // defaulting on bad input would hide user typos like {"contentTypes": "two"}.
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
            EnsAbiResult r = ens().resolveAbi(name, contentTypes);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"contentTypes\":" + contentTypes
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.dataHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true"
                    + ",\"contentType\":" + r.contentType()
                    + ",\"data\":\"" + r.dataHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
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
            EnsDnsRecordResult r = ens().resolveDnsRecord(name, dnsName, (int) resource);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"dnsName\":\"" + escapeJson(dnsName) + "\""
                    + ",\"resource\":" + resource
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.dataHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true,\"data\":\"" + r.dataHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
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
        byte[] interfaceId;
        try {
            interfaceId = java.util.HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            return jsonError("interfaceId must be a 4-byte hex string (8 hex chars)");
        }
        try {
            EnsInterfaceResult r = ens().resolveInterfaceImplementer(name, interfaceId);
            if (r.error() != null) return jsonError(r.error());
            String head = "{\"ok\":true"
                    + ",\"name\":\"" + escapeJson(name) + "\""
                    + ",\"interfaceId\":\"0x" + hex.toLowerCase() + "\""
                    + ",\"blockNumber\":" + r.blockNumber();
            if (r.implementerHex() == null) return head + ",\"resolved\":false}";
            return head + ",\"resolved\":true,\"implementer\":\"" + r.implementerHex() + "\"}";
        } catch (EngineException | IllegalStateException e) {
            return jsonError(e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Dial / stop
    // -------------------------------------------------------------------------

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

            log.info("[ipc] Dialing enode {} at {}:{}",
                    pubKeyHex.substring(0, Math.min(16, pubKeyHex.length())) + "...", host, port);
            DialResult r = handle.dialPeer(host, port, pubKeyHex);
            if (!r.accepted()) {
                return jsonError("Failed to dial: " + r.error());
            }
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
    // Pure serializers (golden-tested; field order matches the historical output)
    // -------------------------------------------------------------------------

    /** Pure serializer for get-headers (golden-tested); field order matches the historical output. */
    static String buildHeadersJson(io.myotis.api.HeadersResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"count\":").append(result.headers().size()).append(",\"headers\":[");
        boolean first = true;
        for (io.myotis.api.HeaderInfo h : result.headers()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"number\":").append(h.number())
              .append(",\"hash\":\"").append(h.hashHex()).append("\"")
              .append(",\"parentHash\":\"").append(h.parentHashHex()).append("\"")
              .append(",\"stateRoot\":\"").append(h.stateRootHex()).append("\"")
              .append(",\"transactionsRoot\":\"").append(h.transactionsRootHex()).append("\"")
              .append(",\"timestamp\":").append(h.timestamp())
              .append(",\"gasUsed\":").append(h.gasUsed())
              .append(",\"gasLimit\":").append(h.gasLimit());
            if (h.baseFeePerGasWei() != null) {
                sb.append(",\"baseFeePerGas\":\"").append(h.baseFeePerGasWei()).append("\"");
            }
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    /** Pure serializer for get-block (golden-tested); field order matches the historical output. */
    static String buildBlockJson(io.myotis.api.BlockResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"block\":{");
        sb.append("\"number\":").append(r.number());
        sb.append(",\"hash\":\"").append(r.hashHex()).append("\"");
        sb.append(",\"parentHash\":\"").append(r.parentHashHex()).append("\"");
        sb.append(",\"stateRoot\":\"").append(r.stateRootHex()).append("\"");
        sb.append(",\"transactionsRoot\":\"").append(r.transactionsRootHex()).append("\"");
        sb.append(",\"receiptsRoot\":\"").append(r.receiptsRootHex()).append("\"");
        sb.append(",\"timestamp\":").append(r.timestamp());
        sb.append(",\"gasUsed\":").append(r.gasUsed());
        sb.append(",\"gasLimit\":").append(r.gasLimit());
        if (r.baseFeePerGasWei() != null) {
            sb.append(",\"baseFeePerGas\":\"").append(r.baseFeePerGasWei()).append("\"");
        }
        sb.append(",\"transactionCount\":").append(r.transactionCount());
        sb.append(",\"uncleCount\":").append(r.uncleCount());
        sb.append(",\"withdrawalCount\":").append(r.withdrawalCount());
        sb.append("},\"verification\":{");
        sb.append("\"beaconSynced\":").append(r.beaconSynced());
        sb.append(",\"beaconChainVerified\":").append(r.beaconChainVerified());
        if (r.beaconChainVerified()) {
            sb.append(",\"matchedBeaconSlot\":").append(r.matchedBeaconSlot());
            sb.append(",\"blsVerified\":").append(r.blsVerified());
            if (r.verifyMethod() != null) {
                sb.append(",\"verifyMethod\":\"").append(r.verifyMethod()).append("\"");
            }
        }
        if (!r.beaconChainVerified() && r.failReason() != null) {
            sb.append(",\"failReason\":\"").append(r.failReason()).append("\"");
        }
        sb.append("}}");
        return sb.toString();
    }

    /** Pure serializer for get-account (golden-tested); field order and conditional
     *  emissions match the historical output byte-for-byte. {@code echoAddr} is the raw
     *  request address, echoed exactly as the daemon always has. */
    static String buildAccountJson(String echoAddr, io.myotis.api.AccountProofResult r) {
        StringBuilder proofSb = new StringBuilder("[");
        for (int i = 0; i < r.proofNodesHex().size(); i++) {
            if (i > 0) proofSb.append(",");
            proofSb.append("\"").append(r.proofNodesHex().get(i)).append("\"");
        }
        proofSb.append("]");

        // The verification sub-object — the ladder lives in the engine; this is
        // serialization plus the derived periodLag.
        StringBuilder v = new StringBuilder("{");
        v.append("\"peerProofValid\":").append(r.peerProofValid());
        if (r.peerStateRootHex() != null && !r.proofNodesHex().isEmpty()) {
            v.append(",\"peerStateRoot\":\"").append(r.peerStateRootHex()).append("\"");
        }
        v.append(",\"beaconSynced\":").append(r.beaconSynced());
        v.append(",\"beaconChainVerified\":").append(r.beaconChainVerified());
        if (r.beaconChainVerified()) {
            v.append(",\"matchedBeaconSlot\":").append(r.matchedBeaconSlot());
            v.append(",\"blsVerified\":").append(r.blsVerified());
            if (r.verifyMethod() != null) {
                v.append(",\"verifyMethod\":\"").append(r.verifyMethod()).append("\"");
            }
        } else {
            if (r.failReason() != null) {
                v.append(",\"failReason\":\"").append(r.failReason()).append("\"");
            }
            v.append(",\"finalizedPeriod\":").append(r.finalizedPeriod());
            v.append(",\"wallClockPeriod\":").append(r.wallClockPeriod());
            v.append(",\"periodLag\":").append(r.wallClockPeriod() - r.finalizedPeriod());
            if (r.blockNumber() > 0) {
                v.append(",\"peerBlockNumber\":").append(r.blockNumber());
            }
            if (r.finalizedBlockNumber() > 0) {
                v.append(",\"finalizedBlockNumber\":").append(r.finalizedBlockNumber());
            }
            if (r.optimisticBlockNumber() > 0) {
                v.append(",\"optimisticBlockNumber\":").append(r.optimisticBlockNumber());
            }
        }
        v.append("}");

        if (!r.exists()) {
            return "{\"ok\":true,\"exists\":false"
                + ",\"address\":\"" + echoAddr + "\""
                + ",\"accountHash\":\"" + r.accountHashHex() + "\""
                + ",\"proof\":" + proofSb
                + ",\"verification\":" + v + "}";
        }
        return "{\"ok\":true,\"exists\":true"
            + ",\"address\":\"" + echoAddr + "\""
            + ",\"accountHash\":\"" + r.accountHashHex() + "\""
            + ",\"nonce\":" + r.nonce()
            + ",\"balance\":\"" + r.balanceWei() + "\""
            + ",\"storageRoot\":\"" + r.storageRootHex() + "\""
            + ",\"codeHash\":\"" + r.codeHashHex() + "\""
            + ",\"proof\":" + proofSb
            + ",\"verification\":" + v + "}";
    }

    /** Pure serializer for get-storage (golden-tested); field order and conditional
     *  emissions match the historical output byte-for-byte. */
    static String buildStorageJson(io.myotis.api.StorageProofResult r) {
        StringBuilder proofSb = new StringBuilder("[");
        for (int i = 0; i < r.proofNodesHex().size(); i++) {
            if (i > 0) proofSb.append(",");
            proofSb.append("\"").append(r.proofNodesHex().get(i)).append("\"");
        }
        proofSb.append("]");

        StringBuilder sb = new StringBuilder("{\"ok\":true");
        sb.append(",\"address\":\"").append(r.addressHex()).append("\"");
        sb.append(",\"slot\":").append(r.slot());
        if (r.holderHex() != null) {
            sb.append(",\"holder\":\"").append(r.holderHex()).append("\"");
        }
        sb.append(",\"storageKey\":\"").append(r.storageKeyHex()).append("\"");
        sb.append(",\"storageKeyHash\":\"").append(r.storageKeyHashHex()).append("\"");
        if (r.exists()) {
            sb.append(",\"exists\":true");
            sb.append(",\"value\":\"").append(r.valueHex()).append("\"");
            if (r.valueDecimal() != null) {
                sb.append(",\"valueDecimal\":\"").append(r.valueDecimal()).append("\"");
            }
        } else {
            sb.append(",\"exists\":false");
            sb.append(",\"slotsReturned\":").append(r.slotsReturned());
        }
        sb.append(",\"storageRoot\":\"").append(r.storageRootHex()).append("\"");
        sb.append(",\"proof\":").append(proofSb);
        sb.append(",\"verification\":{");
        sb.append("\"storageProofValid\":").append(r.storageProofValid());
        sb.append(",\"beaconSynced\":").append(r.beaconSynced());
        sb.append(",\"beaconChainVerified\":").append(r.beaconChainVerified());
        if (r.beaconChainVerified()) {
            sb.append(",\"matchedBeaconSlot\":").append(r.matchedBeaconSlot());
            sb.append(",\"blsVerified\":").append(r.blsVerified());
            if (r.verifyMethod() != null) {
                sb.append(",\"verifyMethod\":\"").append(r.verifyMethod()).append("\"");
            }
        } else {
            if (r.failReason() != null) {
                sb.append(",\"failReason\":\"").append(r.failReason()).append("\"");
            }
            // Always surface the numbers so the operator can see *how far* off we
            // are, not just that we're off — both finalized and optimistic anchors.
            sb.append(",\"peerBlockNumber\":").append(r.peerBlockNumber());
            sb.append(",\"finalizedBlockNumber\":").append(r.finalizedBlockNumber());
            sb.append(",\"optimisticBlockNumber\":").append(r.optimisticBlockNumber());
            if (r.peerBlockNumber() > 0 && r.finalizedBlockNumber() > 0) {
                sb.append(",\"blockGap\":").append(r.peerBlockNumber() - r.finalizedBlockNumber());
            }
            if (r.peerBlockNumber() > 0 && r.optimisticBlockNumber() > 0) {
                sb.append(",\"optimisticBlockGap\":").append(r.peerBlockNumber() - r.optimisticBlockNumber());
            }
            sb.append(",\"maxHeaderChainGap\":").append(r.maxHeaderChainGap());
            sb.append(",\"finalizedSlot\":").append(r.finalizedSlot());
            sb.append(",\"optimisticSlot\":").append(r.optimisticSlot());
        }
        sb.append("}}");
        return sb.toString();
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
