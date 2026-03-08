package devp2p.app;

import devp2p.core.crypto.NodeKey;
import devp2p.core.types.BlockHeader;
import devp2p.networking.discv4.DiscV4Service;
import devp2p.networking.discv4.KademliaTable;
import devp2p.networking.eth.messages.BlockHeadersMessage;
import devp2p.networking.rlpx.RLPxConnector;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * devp2p Playground Demo
 *
 * Demonstrates end-to-end devp2p connectivity:
 *   1. Load or generate a node key
 *   2. Start discv4 peer discovery (UDP)
 *   3. When a peer with TCP is discovered, connect via RLPx
 *   4. Exchange eth/68 Hello + Status
 *   5. Request block headers and verify
 *
 * Run: ./gradlew :app:run
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int UDP_PORT = 30303;
    private static final int TCP_PORT = 30303;

    public static void main(String[] args) throws Exception {
        log.info("=== devp2p Playground ===");

        // 1. Load or generate node key
        Path keyFile = Path.of("nodekey.hex");
        NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
        log.info("Node ID: {}", nodeKey.nodeId().toHexString());

        // 2. Latch to wait for block headers
        CountDownLatch headerLatch = new CountDownLatch(1);
        Set<String> attempted = ConcurrentHashMap.newKeySet();

        // 3. RLPx connector
        RLPxConnector connector = new RLPxConnector(nodeKey, TCP_PORT, headers -> {
            if (!headers.isEmpty()) {
                log.info("\n=== BLOCK HEADERS RECEIVED ===");
                for (BlockHeadersMessage.VerifiedHeader vh : headers) {
                    BlockHeader h = vh.header();
                    log.info("  Block #{}", h.number);
                    log.info("  Hash:      0x{}", vh.hash().toHexString());
                    log.info("  StateRoot: 0x{}", h.stateRoot.toHexString());
                    log.info("  TxRoot:    0x{}", h.transactionsRoot.toHexString());
                    if (h.baseFeePerGas != null) {
                        log.info("  BaseFee:   {} gwei", h.baseFeePerGas.divide(java.math.BigInteger.valueOf(1_000_000_000L)));
                    }
                }
                headerLatch.countDown();
            }
        });

        // 4. discv4 discovery — wait 30s for table to populate, then attempt connections
        long discoveryStart = System.currentTimeMillis();
        DiscV4Service discV4 = new DiscV4Service(nodeKey, entry -> {
            // Skip first 30s: let Kademlia cascade populate diverse peers beyond bootstrap neighbors
            if (System.currentTimeMillis() - discoveryStart < 30_000) return;
            if (entry.tcpPort() > 0 && attempted.size() < 500) {
                String peerKey = entry.udpAddr().getAddress().getHostAddress() + ":" + entry.tcpPort();
                if (attempted.add(peerKey)) {
                    InetSocketAddress peerTcp = new InetSocketAddress(
                        entry.udpAddr().getAddress(), entry.tcpPort());
                    log.info("[main] Attempting RLPx connection to {}", peerTcp);
                    tryConnectWithKnownKey(connector, entry, peerTcp, nodeKey);
                }
            }
        });

        discV4.start(UDP_PORT);
        log.info("[main] discv4 started. Waiting 30s for table to populate...");

        // 5. Wait up to 300 seconds for headers
        boolean success = headerLatch.await(300, TimeUnit.SECONDS);
        if (!success) {
            log.warn("[main] Timeout: no block headers received within 300s");
            log.info("[main] Table has {} known peers, attempted {} connections",
                discV4.table().size(), attempted.size());
        }

        connector.close();
        discV4.close();
        log.info("[main] Done.");
    }

    /**
     * In discv4, the Neighbors response includes 64-byte node IDs (public keys).
     * We reconstruct the SECP256K1 public key and attempt connection.
     */
    private static void tryConnectWithKnownKey(
            RLPxConnector connector, KademliaTable.Entry entry,
            InetSocketAddress peerTcp, NodeKey localKey) {
        try {
            Bytes nodeId = entry.nodeId();
            if (nodeId.size() != 64) {
                log.warn("[main] Node ID is not 64 bytes ({}b), skipping", nodeId.size());
                return;
            }
            SECP256K1.PublicKey peerPubkey = SECP256K1.PublicKey.fromBytes(nodeId);
            connector.connect(peerTcp, peerPubkey)
                .addListener(future -> {
                    if (!future.isSuccess()) {
                        log.warn("[main] Connection to {} failed: {}",
                            peerTcp, future.cause().getMessage());
                    }
                });
        } catch (Exception e) {
            log.warn("[main] Failed to connect to {}: {}", peerTcp, e.getMessage());
        }
    }
}
