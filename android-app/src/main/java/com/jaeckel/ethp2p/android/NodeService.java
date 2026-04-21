package com.jaeckel.ethp2p.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import com.jaeckel.ethp2p.networking.discv4.DiscV4Service;
import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Foreground service that runs the ethp2p node — a stripped-down port of
 * {@code Main.runDaemon}: discv4 discovery + RLPx connector, no IPC, no beacon
 * client. Enough to verify peer discovery and handshakes work on Android.
 */
public final class NodeService extends Service {

    private static final String TAG = "ethp2p.node";
    private static final String CHANNEL_ID = "ethp2p_node";
    private static final int NOTIFICATION_ID = 1;
    private static final int DEFAULT_PORT = 30303;
    private static final long BACKOFF_INCOMPATIBLE_MS = 10 * 60 * 1000L;
    private static final long BACKOFF_TRANSIENT_MS = 30 * 1000L;

    private DiscV4Service discV4;
    private RLPxConnector connector;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, buildNotification());

        // Netty boot is blocking-ish; punt off the main thread.
        new Thread(this::startNode, "ethp2p-boot").start();
        return START_NOT_STICKY;
    }

    private void startNode() {
        try {
            NetworkConfig network = NetworkConfig.byName("mainnet");
            Path keyFile = new java.io.File(getFilesDir(), "nodekey.hex").toPath();
            NodeKey nodeKey = NodeKey.loadOrGenerate(keyFile);
            Log.i(TAG, "Node ID: " + nodeKey.nodeId().toHexString());

            Path cacheFile = new java.io.File(getFilesDir(), "peers.cache").toPath();
            AndroidPeerCache peerCache = new AndroidPeerCache(cacheFile);

            Set<String> attempted = ConcurrentHashMap.newKeySet();
            Map<String, Long> backoff = new ConcurrentHashMap<>();
            Set<String> blacklistedNodeIds = ConcurrentHashMap.newKeySet();

            connector = new RLPxConnector(nodeKey, DEFAULT_PORT, network,
                    headers -> {
                        if (!headers.isEmpty()) {
                            Log.i(TAG, "Received " + headers.size() + " block header(s)");
                        }
                    },
                    peerCache::add);

            // Reconnect cached peers first
            for (AndroidPeerCache.CachedPeer peer : peerCache.load()) {
                String peerKey = peer.address().getAddress().getHostAddress()
                        + ":" + peer.address().getPort();
                attempted.add(peerKey);
                try {
                    SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(
                            Bytes.fromHexString(peer.publicKeyHex()));
                    connector.connect(peer.address(), pubKey, (incompatible, nodeIdHex) -> {
                        if (incompatible) blacklistedNodeIds.add(nodeIdHex);
                        long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                        attempted.remove(peerKey);
                    });
                } catch (Exception e) {
                    Log.w(TAG, "cached peer connect failed: " + e.getMessage());
                    attempted.remove(peerKey);
                }
            }

            discV4 = new DiscV4Service(nodeKey, network.bootnodes(), entry -> {
                if (entry.tcpPort() <= 0 || attempted.size() >= 2000) return;
                String nodeIdHex = entry.nodeId().toHexString();
                if (blacklistedNodeIds.contains(nodeIdHex)) return;
                String peerKey = entry.udpAddr().getAddress().getHostAddress()
                        + ":" + entry.tcpPort();
                Long expiry = backoff.get(peerKey);
                if (expiry != null) {
                    if (System.currentTimeMillis() < expiry) return;
                    backoff.remove(peerKey);
                }
                if (!attempted.add(peerKey)) return;
                try {
                    Bytes nodeId = entry.nodeId();
                    if (nodeId.size() != 64) {
                        attempted.remove(peerKey);
                        return;
                    }
                    // Reconstruct the uncompressed SECP256K1 public key (0x04 prefix + 64 bytes).
                    SECP256K1.PublicKey pubKey = SECP256K1.PublicKey.fromBytes(nodeId);
                    InetSocketAddress peerTcp = new InetSocketAddress(
                            entry.udpAddr().getAddress(), entry.tcpPort());
                    connector.connect(peerTcp, pubKey, (incompatible, idHex) -> {
                        if (incompatible) blacklistedNodeIds.add(idHex);
                        long ms = incompatible ? BACKOFF_INCOMPATIBLE_MS : BACKOFF_TRANSIENT_MS;
                        backoff.putIfAbsent(peerKey, System.currentTimeMillis() + ms);
                        attempted.remove(peerKey);
                    });
                } catch (Exception e) {
                    Log.w(TAG, "discovered peer connect failed: " + e.getMessage());
                    attempted.remove(peerKey);
                }
            });
            discV4.start(DEFAULT_PORT);
            Log.i(TAG, "discv4 started on UDP " + DEFAULT_PORT);
        } catch (Exception e) {
            Log.e(TAG, "node boot failed", e);
            stopSelf();
        }
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Stopping node");
        if (connector != null) try { connector.close(); } catch (Exception ignored) {}
        if (discV4 != null) try { discV4.close(); } catch (Exception ignored) {}
        super.onDestroy();
    }

    private Notification buildNotification() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW);
        nm.createNotificationChannel(channel);
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setOngoing(true)
                .build();
    }
}
