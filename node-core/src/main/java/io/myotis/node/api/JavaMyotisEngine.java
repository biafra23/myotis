package io.myotis.node.api;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.NetworkConfig;
import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.ports.EnginePorts;
import io.myotis.node.ChainPorts;
import io.myotis.node.ChainStack;
import io.myotis.node.NodeRegistry;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The JVM reference implementation of {@link MyotisEngine}: wraps {@link NodeRegistry} +
 * {@link ChainStack} behind the language-neutral API. This class is the single line a host
 * writes that names a concrete engine ({@code new JavaMyotisEngine()}); everything else the
 * host touches is {@code io.myotis.api}.
 */
public final class JavaMyotisEngine implements MyotisEngine {

    private final NodeRegistry registry = new NodeRegistry();
    private final Map<String, JavaChainHandle> handles = new ConcurrentHashMap<>();
    /**
     * Runs the blocking {@code HttpGateway} port when the engine's CCIP executor needs a
     * future (see {@link PortBridges#toCcipGateway}). Unbounded cached pool: CCIP calls are
     * rare, short (~10–15 s timeout in the port), and must never queue behind each other.
     */
    private final ExecutorService httpExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "engine-http-gateway");
        t.setDaemon(true);
        return t;
    });

    @Override
    public List<NetworkInfo> availableNetworks() {
        List<NetworkInfo> out = new ArrayList<>();
        for (NetworkConfig net : NetworkConfig.allNetworks()) {
            out.add(toInfo(net));
        }
        return out;
    }

    @Override
    public String canonicalNetworkName(String nameOrAlias) {
        if (nameOrAlias == null) throw new EngineException("network name is required");
        try {
            return NetworkConfig.byName(nameOrAlias).name();
        } catch (IllegalArgumentException e) {
            throw new EngineException(e.getMessage(), e);
        }
    }

    @Override
    public ChainHandle create(EngineConfig config, EnginePorts ports) {
        String name = canonicalNetworkName(config.networkName());
        NetworkConfig net;
        try {
            net = NetworkConfig.byName(name);
        } catch (IllegalArgumentException e) {
            throw new EngineException(e.getMessage(), e);
        }
        if (handles.containsKey(name)) {
            throw new EngineException("network already hosted: " + name);
        }
        // Fail here with a named error rather than letting a null port surface as an
        // undiagnosable NPE swallowed by ChainStack.start()'s fault isolation.
        if (ports.peerCache() == null) throw new EngineException("peerCache port is required");
        if (ports.clPeerCache() == null) throw new EngineException("clPeerCache port is required");

        ChainPorts defaults = ChainPorts.defaultsFor(net);
        ChainPorts chainPorts = new ChainPorts(
                config.elPort() > 0 ? config.elPort() : defaults.elPort(),
                config.discv5Port() > 0 ? config.discv5Port() : defaults.discv5Port(),
                config.rpcPort() > 0 ? config.rpcPort() : defaults.rpcPort());

        NodeKey nodeKey = loadOrCreateKey(name, ports);

        ChainStack stack = new ChainStack(
                net,
                chainPorts,
                nodeKey,
                PortBridges.toPeerCachePort(ports.peerCache()),
                PortBridges.toClPeerCachePort(ports.clPeerCache()),
                ports.httpGateway() != null
                        ? PortBridges.toCcipGateway(ports.httpGateway(), httpExecutor)
                        : null,
                config.syncSnapshotPath() != null ? Paths.get(config.syncSnapshotPath()) : null,
                config.gossipsubEnabled());
        if (config.targetSnapPeers() > 0) {
            stack.configureSnapMaintainer(config.targetSnapPeers(),
                    PortBridges.toDnsServerProvider(ports.dnsServers()));
        }

        JavaChainHandle handle = new JavaChainHandle(stack, config.strictStateFreshness());
        // Late-bind the JSON-RPC status source (resolves the stack↔handle cycle): the
        // handle is the NodeStatusReads, and startRpc() runs later inside handle.start().
        stack.setStatusReads(handle);
        // Atomic claim: two concurrent create()s for the same network must not both
        // register (the check above is only a fast fail).
        if (handles.putIfAbsent(name, handle) != null) {
            throw new EngineException("network already hosted: " + name);
        }
        registry.add(stack);
        return handle;
    }

    @Override
    public ChainHandle get(String networkName) {
        return handles.get(networkName);
    }

    /**
     * DEBUG-ONLY escape hatch: the underlying {@link ChainStack} for hosts' documented
     * exemptions (the daemon's TrueBlocks {@code get-transactions} stream). Deliberately
     * NOT on the {@link MyotisEngine} interface — a host that wants the engine to stay
     * replaceable must not build features on this.
     */
    public ChainStack debugStack(String networkName) {
        JavaChainHandle handle = handles.get(networkName);
        return handle != null ? handle.stack() : null;
    }

    @Override
    public List<String> hostedNetworks() {
        return List.copyOf(handles.keySet());
    }

    @Override
    public void stop(String networkName) {
        handles.remove(networkName);
        registry.remove(networkName);
    }

    @Override
    public void shutdownAll() {
        handles.clear();
        registry.shutdownAll();
    }

    private NodeKey loadOrCreateKey(String networkName, EnginePorts ports) {
        if (ports.keyStore() == null) throw new EngineException("keyStore port is required");
        byte[] secret = ports.keyStore().load(networkName);
        if (secret == null) {
            NodeKey fresh = NodeKey.generate();
            ports.keyStore().store(networkName, fresh.secretKey().bytes().toArrayUnsafe());
            return fresh;
        }
        if (secret.length != 32) {
            throw new EngineException("stored node key for " + networkName
                    + " must be 32 bytes, got " + secret.length);
        }
        try {
            return NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(Bytes32.wrap(secret)));
        } catch (Exception e) {
            throw new EngineException("stored node key for " + networkName + " is invalid: "
                    + e.getMessage(), e);
        }
    }

    private static NetworkInfo toInfo(NetworkConfig net) {
        return new NetworkInfo(
                net.name(),
                net.displayName(),
                net.networkId(),
                net.hasEns(),
                net.defaultElPort(),
                net.defaultDiscv5Port(),
                net.defaultRpcPort(),
                net.clGenesisTime(),
                net.secondsPerSlot());
    }
}
