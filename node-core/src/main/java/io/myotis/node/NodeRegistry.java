package io.myotis.node;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds the live {@link ChainStack}s a single process is hosting, keyed by network
 * name. The host (the {@code :app} daemon or {@code :android-app} {@code NodeService})
 * builds stacks with its own platform adapters, registers them here, and uses the
 * registry to iterate (for snapshots), look one up (to route a per-network command),
 * and tear them all down.
 *
 * <p>One process can hold several stacks at once (mainnet + Gnosis + …), each on its
 * own ports. A failure in one stack is isolated to that stack (see
 * {@link ChainStack#start()}); the registry never assumes all stacks are healthy.
 */
public final class NodeRegistry {

    private final Map<String, ChainStack> stacks = new ConcurrentHashMap<>();

    /** Register an already-built stack (call {@link ChainStack#start()} separately). */
    public void add(ChainStack stack) {
        stacks.put(stack.network().name(), stack);
    }

    /** The stack for {@code networkName}, or {@code null} if not hosted. */
    public ChainStack get(String networkName) {
        return stacks.get(networkName);
    }

    /** All hosted stacks (live view). */
    public Collection<ChainStack> all() {
        return stacks.values();
    }

    /** Network names currently hosted. */
    public java.util.Set<String> networkNames() {
        return stacks.keySet();
    }

    public boolean isEmpty() {
        return stacks.isEmpty();
    }

    public int size() {
        return stacks.size();
    }

    /** Shut down and remove a single stack (no-op if absent). */
    public void remove(String networkName) {
        ChainStack stack = stacks.remove(networkName);
        if (stack != null) stack.shutdown();
    }

    /** Shut down every stack and clear the registry. */
    public void shutdownAll() {
        for (ChainStack stack : stacks.values()) {
            try { stack.shutdown(); } catch (Throwable ignored) {}
        }
        stacks.clear();
    }
}
