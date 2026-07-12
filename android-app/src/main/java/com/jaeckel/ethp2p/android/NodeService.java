package com.jaeckel.ethp2p.android;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Binder;
import android.os.IBinder;
import com.jaeckel.ethp2p.android.diag.ProcessHealthDiag;
import com.jaeckel.ethp2p.android.log.LogBuffer;

import io.myotis.api.AccountProofResult;
import io.myotis.api.BeaconState;
import io.myotis.api.BeaconStatus;
import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import io.myotis.api.MyotisEngine;
import io.myotis.api.NetworkInfo;
import io.myotis.api.StatusSnapshot;
import io.myotis.api.ports.EnginePorts;
import io.myotis.api.ports.NodeKeyStore;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

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
    // Keep a working set of snap peers connected so a verified request almost
    // always finds one even as peers churn. Below this we proactively re-dial
    // known snap peers from the cache (CONFIRMED-quality first, via snapDialRank).
    //
    // 12, not 4: being a snap peer is NOT the same as retaining the state at the
    // head root we anchor. Geth prunes trie state beyond ~128 blocks and snap-serves
    // from a flat layer that lags the head, so at any moment only SOME connected snap
    // peers can serve the current root — the rest fail with StateUnavailable. On-device
    // captures showed eth_call/the confirm-screen Multicall3 sim failing for minutes
    // with several snap peers connected: 4 wasn't a deep enough pool to reliably hold
    // one peer whose retained state covers the head. A deeper pool makes the
    // probe-and-pin build (firstPeerServing / the PEER_HEAD race) far likelier to find
    // a state-servable peer. The daemon holds ~36 organically with no ill effect;
    // 12 lightweight eth/snap connections is a fine bound for a phone actively serving
    // a wallet in the foreground.
    /** Default node snap-peer target; overridable via settings ({@link #snapTarget}). */
    public static final int DEFAULT_SNAP_TARGET = 32;
    /** Live snap-peer target, read from settings at boot; the maintainer reads it each tick
     *  so a settings change applies without a restart. */
    private volatile int targetSnapPeers = DEFAULT_SNAP_TARGET;
    // How many recent blocks below the verified head to scan for a tx in
    // eth_getTransactionReceipt. Kept small to bound the bandwidth/battery cost of the
    // (trustless) body scan on mobile: ~8 blocks ≈ 1.5 min covers a wallet polling a
    // just-submitted tx. A pending/older tx isn't found here and falls through to the
    // proxy. Bodies within the window are fetched concurrently, so latency ≈ one
    // round-trip regardless of the count.
    private static final int RECEIPT_LOOKBACK_BLOCKS = 8;
    // Permissionless mode: do NOT fall back to the (permissioned) upstream proxy. A
    // method we can't answer from cryptographically-verified data ERRORS instead of
    // silently returning unverified upstream data — that is the whole point of Myotis.
    // The proxy was only ever a transition aid to learn what MetaMask calls; the
    // MethodLogger / myotis_rpcCoverage still records every rejected method, so we keep
    // that discovery signal without serving unverified data. Flip to false only for
    // local debugging against an injected upstream.
    private static final boolean STRICT_NO_PROXY = true;
    // Max blocks below the verified head we'll fetch+verify headers for to answer
    // eth_getBlockByNumber by number. "latest" is 1 header; older numbers cost a header
    // range, so bound it (MetaMask asks for "latest" for the fee market anyway).
    private static final int BLOCK_LOOKBACK_MAX = 256;

    // Static so MainActivity can reflect the correct button state after a
    // configuration change — the activity instance is recreated, but the
    // service process (and this flag) outlive it.
    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    public static boolean isRunning() {
        return RUNNING.get();
    }

    // ----- Settings (SharedPreferences "ethp2p"), shared by the service + Compose UI -----
    private static final String PREFS_NAME = "ethp2p";
    private static final String K_NETWORK = "network";
    private static final String K_RPC_PORT = "rpcPort";
    private static final String K_SNAP_TARGET = "snapTarget";
    private static final String K_SERVED_WINDOW = "servedBlockWindow";
    private static final String K_DEEP_POOL = "deepPoolThreshold";
    private static final String K_STRICT_FRESHNESS = "strictStateFreshness";
    private static final String K_NATIVE_BLS = "nativeBls";
    private static final String K_RUST_ENGINE = "rustEngine";
    private static final String K_IDLE_PAUSE_MIN = "idlePauseMinutes";
    private static final String K_STAY_AWAKE_CHARGING = "stayAwakeWhileCharging";
    public static final int DEFAULT_IDLE_PAUSE_MIN = 5;
    public static final int DEFAULT_RPC_PORT = 8545;
    // Gnosis defaults to a distinct port so both networks can be added to MetaMask
    // at once: MetaMask refuses to save two RPC endpoints that share the same URL
    // (host:port), so mainnet and Gnosis must not collide on 8545.
    public static final int DEFAULT_RPC_PORT_GNOSIS = 8546;
    public static final int DEFAULT_DEEP_POOL = 16;

    private static int clampInt(int v, int lo, int hi, int dflt) {
        if (v < lo || v > hi) return (dflt < lo || dflt > hi) ? lo : dflt;
        return v;
    }
    private static android.content.SharedPreferences prefs(android.content.Context c) {
        return c.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE);
    }
    /**
     * The engine, and its static network catalog for the pref helpers below (they're
     * static — callable from Activities without a bound service). One process-global
     * engine mirrors the process-global RUNNING flag: service instances come and go,
     * the hosted-network registry persists across them. The composition root is the
     * :myotis-engines selector — `myotis.engine` (the Settings "Rust engine" toggle
     * via {@link #applyEngineChoice}) picks Java or Rust per network (re)start.
     */
    private static final MyotisEngine ENGINE = io.myotis.engines.Engines.engine();
    private static final List<NetworkInfo> NETWORKS = ENGINE.availableNetworks();

    private static NetworkInfo networkInfo(String canonical) {
        for (NetworkInfo n : NETWORKS) {
            if (n.name().equals(canonical)) return n;
        }
        return NETWORKS.get(0); // mainnet — canonicalNetwork() already fell back
    }

    /**
     * Canonicalize a network name to one the engine hosts AND that the per-network
     * helpers (which test {@code "gnosis".equals(network)}) handle consistently.
     * Unknown/corrupt/empty values fall back to mainnet so a bad pref can never crash
     * node startup or silently desync the RPC-port/preset selection from the resolved
     * chain (which is why this doesn't use {@code ENGINE.canonicalNetworkName} — that
     * throws on unknown names).
     */
    private static String canonicalNetwork(String n) {
        if (n == null) return "mainnet";
        switch (n.toLowerCase(java.util.Locale.ROOT)) {
            case "gnosis": case "gbc": case "xdai": return "gnosis";
            case "sepolia": return "sepolia";
            default: return "mainnet";
        }
    }
    /** Legacy single-selected chain ("mainnet"/"gnosis"/"sepolia"); only used to seed the
     *  per-network enabled-set on first run after upgrade. New code uses {@link #enabledNetworks}. */
    public static String selectedNetwork(android.content.Context c) {
        return canonicalNetwork(prefs(c).getString(K_NETWORK, "mainnet"));
    }
    public static void setSelectedNetwork(android.content.Context c, String n) {
        prefs(c).edit().putString(K_NETWORK, canonicalNetwork(n)).apply();
    }

    // Per-network "enabled" flags (Step 9). Each network runs as an independent stack the
    // user toggles in Settings; the enabled-set is what onStartCommand boots. Default:
    // mainnet on, everything else off (two beacon light clients is heavy on mobile, so
    // concurrency is opt-in). Existing installs are seeded from the legacy K_NETWORK once.
    private static final String K_ENABLED_PREFIX = "enabled_";
    private static String enabledKey(String network) { return K_ENABLED_PREFIX + canonicalNetwork(network); }

    /** Whether {@code network} is enabled. Falls back to the seeded default if never set. */
    public static boolean isNetworkEnabled(android.content.Context c, String network) {
        String n = canonicalNetwork(network);
        android.content.SharedPreferences p = prefs(c);
        if (p.contains(enabledKey(n))) return p.getBoolean(enabledKey(n), false);
        // Unset: seed from the legacy selection (upgrade path), else mainnet-only default.
        return n.equals(selectedNetwork(c)) || (n.equals("mainnet") && !p.contains(K_NETWORK));
    }
    public static void setNetworkEnabled(android.content.Context c, String network, boolean on) {
        prefs(c).edit().putBoolean(enabledKey(canonicalNetwork(network)), on).apply();
    }
    /** The set of enabled networks (in the engine catalog's display order). Never
     *  empty — falls back to mainnet so the service always has something to run. */
    public static List<String> enabledNetworks(android.content.Context c) {
        List<String> out = new ArrayList<>();
        for (NetworkInfo nc : NETWORKS) {
            if (isNetworkEnabled(c, nc.name())) out.add(nc.name());
        }
        if (out.isEmpty()) out.add("mainnet");
        return out;
    }
    /** Primary network = the first enabled one; the default target for back-compat query calls. */
    public static String primaryNetwork(android.content.Context c) {
        return enabledNetworks(c).get(0);
    }
    /** Per-network default RPC port — from the engine's catalog so the defaults stay
     *  collision-free and consistent with the engine's own port defaulting (mainnet 8545,
     *  Gnosis 8546, Sepolia 8547). A NodeService-local table would silently put Sepolia on
     *  8545 and collide with mainnet's RPC bind when both run. */
    public static int defaultRpcPort(String network) {
        return networkInfo(canonicalNetwork(network)).defaultRpcPort();
    }
    /** All supported networks in display order, from the engine's catalog. */
    public static List<String> allNetworkNames() {
        List<String> out = new ArrayList<>(NETWORKS.size());
        for (NetworkInfo n : NETWORKS) out.add(n.name());
        return out;
    }
    /** Human-facing chain name, from the engine's catalog. */
    public static String displayName(String network) {
        return networkInfo(canonicalNetwork(network)).displayName();
    }
    /** Whether ENS resolution is available on {@code network}, from the engine's catalog. */
    public static boolean hasEns(String network) {
        return networkInfo(canonicalNetwork(network)).hasEns();
    }
    // The RPC port is stored per network so each chain keeps an independent port — a shared key
    // would force the same URL on multiple chains, which MetaMask rejects and which collides on
    // bind when they run concurrently. Mainnet keeps the legacy key (no migration); EVERY other
    // chain gets a "<key>_<network>" suffix (not just Gnosis — Sepolia must not share mainnet's).
    private static String rpcPortKey(String network) {
        String n = canonicalNetwork(network);
        return n.equals("mainnet") ? K_RPC_PORT : K_RPC_PORT + "_" + n;
    }
    /** JSON-RPC server port for {@code network} (1024–65535; default per {@link #defaultRpcPort}). */
    public static int rpcPortFor(android.content.Context c, String network) {
        int dflt = defaultRpcPort(network);
        return clampInt(prefs(c).getInt(rpcPortKey(network), dflt), 1024, 65535, dflt);
    }
    /** JSON-RPC server port for the primary enabled network (back-compat convenience). */
    public static int rpcPort(android.content.Context c) {
        return rpcPortFor(c, primaryNetwork(c));
    }
    /** Persist the JSON-RPC port for a specific network (ports are per-network — see {@link #rpcPortKey}). */
    public static void setRpcPort(android.content.Context c, String network, int p) {
        String net = canonicalNetwork(network);
        int dflt = defaultRpcPort(net);
        prefs(c).edit().putInt(rpcPortKey(net), clampInt(p, 1024, 65535, dflt)).apply();
    }
    /** Node snap-peer target (1–128, default 32). */
    public static int snapTarget(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_SNAP_TARGET, DEFAULT_SNAP_TARGET), 1, 128, DEFAULT_SNAP_TARGET);
    }
    public static void setSnapTargetPref(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_SNAP_TARGET, clampInt(v, 1, 128, DEFAULT_SNAP_TARGET)).apply();
    }
    /** eth/69 served-block window (1-4096, default 32) — recent headers retained and
     *  advertised as servable to peers. NB clampInt resets OUT-OF-RANGE input to the
     *  DEFAULT (32) — matching snapTarget's semantics — whereas desktop/ChainStack
     *  coerce to the nearer bound; within this host, persisted and live values always
     *  agree because both paths clamp identically. */
    public static int servedBlockWindow(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_SERVED_WINDOW, 32), 1, 4096, 32);
    }
    public static void setServedBlockWindowPref(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_SERVED_WINDOW, clampInt(v, 1, 4096, 32)).apply();
    }
    /** UI readiness "deep pool" threshold (1–128, default 16). */
    public static int deepPoolThreshold(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_DEEP_POOL, DEFAULT_DEEP_POOL), 1, 128, DEFAULT_DEEP_POOL);
    }
    public static void setDeepPoolThreshold(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_DEEP_POOL, clampInt(v, 1, 128, DEFAULT_DEEP_POOL)).apply();
    }
    /** Minutes of no RPC/UI activity before a running stack is paused (networking off,
     *  RPC keeps listening; the first request wakes it). 0 disables auto-pause. */
    public static int idlePauseMinutes(android.content.Context c) {
        return clampInt(prefs(c).getInt(K_IDLE_PAUSE_MIN, DEFAULT_IDLE_PAUSE_MIN),
                0, 240, DEFAULT_IDLE_PAUSE_MIN);
    }
    public static void setIdlePauseMinutes(android.content.Context c, int v) {
        prefs(c).edit().putInt(K_IDLE_PAUSE_MIN, clampInt(v, 0, 240, DEFAULT_IDLE_PAUSE_MIN)).apply();
    }
    /** When true (default), the idle controller skips auto-pause while the device is charging and
     *  online — plugged in with a network, battery isn't a concern, so the node stays awake and
     *  synced. Plugged in but offline still pauses (nothing to sync). The emergency low-memory
     *  pause ({@link #onTrimMemory}) ignores this. Read live by the idle tick. */
    public static boolean stayAwakeWhileCharging(android.content.Context c) {
        return prefs(c).getBoolean(K_STAY_AWAKE_CHARGING, true);
    }
    public static void setStayAwakeWhileCharging(android.content.Context c, boolean v) {
        prefs(c).edit().putBoolean(K_STAY_AWAKE_CHARGING, v).apply();
    }
    /** Whether RPC state reads use the strict 2-min head-staleness bound. Default true
     *  (strict). Relaxing it (toggle OFF strict / ON "relaxed") lets eth_call / balance /
     *  estimateGas serve an older root — but that *backfired* into 120-s confirm-screen
     *  HANGS when the older root isn't fully servable, so strict (fast-fail) is the default;
     *  relaxed is an explicit opt-in. Read by VerifiedRpcBackend via a system property.
     *  See OPTIMISATIONS_AND_LIMITATIONS.md §2.14. */
    public static boolean strictStateFreshness(android.content.Context c) {
        return prefs(c).getBoolean(K_STRICT_FRESHNESS, true);
    }
    public static void setStrictStateFreshness(android.content.Context c, boolean v) {
        prefs(c).edit().putBoolean(K_STRICT_FRESHNESS, v).apply();
    }
    /** Whether the bundled native blst BLS backend may be used. Default true. When false,
     *  BLS verification is forced onto the pure-Java Milagro path (slower — Milagro is
     *  ~30-55s cold on ART) regardless of whether the native lib loaded; useful to rule the
     *  native lib out when debugging (e.g. a 16 KB-alignment load failure) or to compare
     *  behavior. Mapped to the {@code myotis.bls.backend} property via {@link #blsBackendChoice}
     *  and applied live by {@link #applyBlsBackend} (also re-applied on each node start).
     *  See docs/bls-rust-acceleration.md. */
    public static boolean nativeBlsEnabled(android.content.Context c) {
        return prefs(c).getBoolean(K_NATIVE_BLS, true);
    }
    public static void setNativeBlsEnabled(android.content.Context c, boolean v) {
        prefs(c).edit().putBoolean(K_NATIVE_BLS, v).apply();
    }
    /** Apply the current native-BLS setting to the process-wide BlsBackends selection now:
     *  set the {@code myotis.bls.backend} property (read on a cold process) AND select() the
     *  backend live — active() memoizes its first result, so the property alone wouldn't flip
     *  a process that has already verified. Cheap to call anytime, including on a running node:
     *  the decompressed-pubkey cache is process-global (BlsVerifier), so the swap preserves it.
     *  Returns the applied choice (for logging). */
    public static String applyBlsBackend(android.content.Context c) {
        String choice = blsBackendChoice(c);
        System.setProperty(com.jaeckel.ethp2p.consensus.bls.BlsBackends.PROP, choice);
        com.jaeckel.ethp2p.consensus.bls.BlsBackends.select(choice);
        return choice;
    }
    /** The {@code myotis.bls.backend} choice for the current setting: {@code milagro} when
     *  native BLS is disabled, otherwise {@code auto} (native blst when present, else
     *  Milagro) — on EVERY build type. Debuggable builds used to default to {@code compare}
     *  (Milagro AND native per verify, as a measurement harness), but on-device that costs
     *  10-16 s of Milagro math per sync-committee update (~500x slower than blst alone) and
     *  froze catch-up/status for minutes — diagnosed on a Pixel 7, 2026-07-06. Compare mode
     *  is explicit opt-in only, via the {@code myotis.bls.backend=compare} system property
     *  ({@code -Pbls=compare} on the daemon); no build type defaults to it. */
    public static String blsBackendChoice(android.content.Context c) {
        return nativeBlsEnabled(c) ? "auto" : "milagro";
    }
    /** Settings toggle: prefer the (experimental) Rust engine for newly started networks.
     *  Default off — the Java engine is the proven path. */
    public static boolean rustEngineEnabled(android.content.Context c) {
        return prefs(c).getBoolean(K_RUST_ENGINE, false);
    }
    public static void setRustEngineEnabled(android.content.Context c, boolean v) {
        prefs(c).edit().putBoolean(K_RUST_ENGINE, v).apply();
    }
    /** Apply the Rust-engine setting to the process-wide {@code Engines} selector. Maps
     *  enabled → {@code auto} (prefer Rust where it can serve, fall back to Java with a
     *  log — the Rust engine is catalog-only today), disabled → {@code java}. Unlike the
     *  BLS toggle this is NOT live: networks keep the engine that created them; the new
     *  choice applies on the next network (re)start. Returns the applied choice. */
    public static String applyEngineChoice(android.content.Context c) {
        String choice = rustEngineEnabled(c) ? "auto" : "java";
        System.setProperty(io.myotis.engines.Engines.PROP, choice);
        io.myotis.engines.Engines.select(choice);
        return choice;
    }
    /** Live-update the snap-peer target (no restart) on every live stack and persist it. */
    public void setTargetSnapPeers(int v) {
        int c = clampInt(v, 1, 128, DEFAULT_SNAP_TARGET);
        this.targetSnapPeers = c;
        setSnapTargetPref(this, c);
        for (ChainHandle h : handles.values()) h.setTargetSnapPeers(c);
    }

    /** Live-update the eth/69 served-block window (no restart) on every live stack and persist it. */
    public void setServedBlockWindow(int v) {
        int c = clampInt(v, 1, 4096, 32);
        setServedBlockWindowPref(this, c);
        // Same monitor as buildAndStart's read-apply-publish: see the comment there.
        synchronized (handles) {
            for (ChainHandle h : handles.values()) h.setServedBlockWindow(c);
        }
    }

    /** Currently live networks (a chip per entry), in display order. */
    public List<String> liveNetworks() {
        List<String> out = new ArrayList<>();
        for (NetworkInfo nc : NETWORKS) {
            if (handles.containsKey(nc.name())) out.add(nc.name());
        }
        return out;
    }

    /**
     * Enable a network (Settings semantics): persist the flag AND bring its stack up
     * via {@link #startNetwork}.
     */
    public void enableNetwork(String name) {
        String n = canonicalNetwork(name);
        setNetworkEnabled(this, n, true);
        startNetwork(n);
    }

    /**
     * Disable a network (Settings semantics): persist the flag off AND shut its stack
     * down via {@link #stopNetwork}.
     */
    public void disableNetwork(String name) {
        String n = canonicalNetwork(name);
        setNetworkEnabled(this, n, false);
        stopNetwork(n);
    }

    /**
     * Runtime-only start (the Status page's Start button): bring the stack up WITHOUT
     * touching the persisted enabled flag. If the service isn't running yet, start it
     * (onStartCommand boots the whole enabled-set — callers ensure the network is in it,
     * or go through {@link #enableNetwork}); otherwise build and start just this stack
     * on a worker. No-op if it's already live.
     */
    public void startNetwork(String name) {
        noteUiActivity();
        String n = canonicalNetwork(name);
        if (!RUNNING.get()) {
            startForegroundService(new Intent(this, NodeService.class));
            return;
        }
        if (handles.containsKey(n)) return;
        spawnBoot(n, stopGen(n), null, "ethp2p-boot-" + n);
    }

    /**
     * Runtime-only stop (the Status page's Stop button): remove and shut down the stack
     * on a worker WITHOUT touching the persisted enabled flag — the chain stays enabled
     * and boots again on the next service start. If it was the last live stack, the
     * whole service stops (mirrors a Stop-node tap): a service with zero stacks has
     * nothing to host, and its notification would read "Starting…" forever.
     */
    public void stopNetwork(String name) {
        String n = canonicalNetwork(name);
        // Invalidate any queued/in-flight boot of this chain. The old disable path got
        // this for free from buildAndStart's enabled-flag re-check; a runtime stop
        // leaves the flag on, so without the generation bump a boot that loses the
        // bootLock race would resurrect the chain the user just stopped.
        stopGens.computeIfAbsent(n, k -> new java.util.concurrent.atomic.AtomicLong()).incrementAndGet();
        forgetStack(n);   // drop from the UI's live map immediately
        new Thread(() -> {
            synchronized (bootLock(n)) {
                try { ENGINE.stop(n); } catch (Throwable ignored) {}
            }
            // userStop=true: an empty map is decisive even though flags stay enabled.
            stopIfNoStacksLeft(true);
        }, "ethp2p-stop-" + n).start();
    }

    /**
     * Reboot one network's stack in place (e.g. after an RPC-port change) without touching
     * its enabled flag or any other chain. ChainStack's start()/shutdown() are synchronized
     * together, so the rebuilt stack's start() waits for the old one's ports to free.
     */
    public void rebootNetwork(String name) {
        String n = canonicalNetwork(name);
        if (!RUNNING.get()) return;
        // Only reboot a chain that's actually live. If it isn't (disabled / not yet built), do
        // nothing — the new port is already persisted and applies on the next enable. Without this,
        // saving settings would start a chain the user has turned off.
        if (handles.remove(n) == null) return;
        // A reboot is a cold restart of this stack: clear the SYNCED-once flag so it runs through
        // to SYNCED again before the idle controller may pause it. buildAndStart re-stamps the
        // start clocks. (rebootNetwork doesn't go through forgetStack, so clear it explicitly here.)
        reachedSynced.remove(n);
        // preBoot tears the old instance down; buildAndStart then re-acquires
        // bootLock(n) for its start() — the teardown frees the ports first.
        spawnBoot(n, stopGen(n), () -> {
            synchronized (bootLock(n)) {
                try { ENGINE.stop(n); } catch (Throwable ignored) {}
            }
        }, "ethp2p-reboot-" + n);
    }

    /** Drop all NodeService-side bookkeeping for a network (the engine-side stop happens separately). */
    private void forgetStack(String n) {
        handles.remove(n);
        cachedElCounts.remove(n);
        cachedClCounts.remove(n);
        elCaches.remove(n);
        clCaches.remove(n);
        stackStartMs.remove(n);
        stackStartNano.remove(n);
        lastResumeMs.remove(n);
        reachedSynced.remove(n);   // a re-enable cold-starts the SYNCED-once gate again
    }

    /** True if any network is still enabled (incl. the seeded default). */
    private boolean anyNetworkEnabled() {
        for (NetworkInfo nc : NETWORKS) {
            if (isNetworkEnabled(this, nc.name())) return true;
        }
        return false;
    }

    /** Boots claimed by {@link #spawnBoot} (on the calling thread, before the worker
     *  starts) and released in the worker's finally — guards {@link #stopIfNoStacksLeft}
     *  against the transiently-empty {@link #handles} map while a chain is still
     *  spinning up (a boot only registers its handle once start() succeeds). */
    private final java.util.concurrent.atomic.AtomicInteger bootsInFlight =
            new java.util.concurrent.atomic.AtomicInteger();

    /** Per-network stop generation, bumped by {@link #stopNetwork}. Boot threads
     *  snapshot it at spawn and bail if it moved — see the stopNetwork comment. */
    private final java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong> stopGens =
            new java.util.concurrent.ConcurrentHashMap<>();

    private long stopGen(String n) {
        return stopGens.computeIfAbsent(n, k -> new java.util.concurrent.atomic.AtomicLong()).get();
    }

    /**
     * Spawn a boot worker for {@code n}: runs {@code preBoot} (nullable — reboot's
     * old-instance teardown), then {@link #buildAndStart}, and once the worker
     * finishes (success, bail, or failure) gives the service-stop check one shot.
     * The in-flight count is claimed HERE, on the CALLING thread, before start():
     * claimed inside the worker there'd be a scheduling gap in which a concurrent
     * user stop sees zero boots in flight over an empty map and tears the service
     * down under the pending boot. The gen comparison in the finally finishes a
     * runtime stop that raced this boot: the stop's own check ran while this boot
     * was still in flight and skipped.
     */
    private void spawnBoot(String n, long gen, Runnable preBoot, String threadName) {
        bootsInFlight.incrementAndGet();
        new Thread(() -> {
            try {
                if (preBoot != null) preBoot.run();
                buildAndStart(n, gen);
            } finally {
                bootsInFlight.decrementAndGet();
                stopIfNoStacksLeft(stopGen(n) != gen);
            }
        }, threadName).start();
    }

    /**
     * Stop the whole foreground service once the last stack is gone and no boot is in
     * flight. {@code userStop} (Status Stop / Settings disable, incl. one racing a boot —
     * see {@link #spawnBoot}) makes the empty map decisive even while networks are still
     * ENABLED: a runtime stop keeps the flags on by design, and a zero-stack service has
     * nothing to host (its notification would read "Starting…" forever). Start cold-starts
     * the service again and onStartCommand boots the enabled set. Non-user callers
     * (boot-bail/failure paths) keep the old enabled-set guard, so a failed boot with
     * enabled chains leaves the service up exactly as before. The boots-in-flight guard
     * covers the transiently-empty map while another chain is still spinning up.
     */
    private void stopIfNoStacksLeft(boolean userStop) {
        if (handles.isEmpty() && bootsInFlight.get() == 0
                && (userStop || !anyNetworkEnabled())
                && RUNNING.compareAndSet(true, false)) {
            LogBuffer.i(TAG, "no stacks left; stopping service");
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        }
    }

    /** Cache file in getCacheDir(), suffixed by the network (mainnet keeps the bare name) so
     *  chains never share peer caches / sync snapshots. */
    private java.io.File netCacheFor(String network, String base, String ext) {
        String n = canonicalNetwork(network);
        String suffix = n.equals("mainnet") ? "" : "-" + n;
        return new java.io.File(getCacheDir(), base + suffix + ext);
    }


    // One per-network engine handle (EL + discv4/5 + beacon LC + verified RPC + the
    // snap-peer maintainer), shared with the :app daemon via the engine API. The map is
    // the UI's source of truth for "what's live" — snapshot, query routing and shutdown
    // all iterate it; the engine's own registry parallels it (entries are added/removed
    // together under the per-network bootLock). Keyed by canonical network name.
    private final Map<String, ChainHandle> handles = new ConcurrentHashMap<>();
    // Per-network "peers loaded from cache at boot" counts, captured when a stack is built
    // (ChainStack owns the live caches via the adapters, so we read the size once here).
    private final Map<String, Integer> cachedElCounts = new ConcurrentHashMap<>();
    private final Map<String, Integer> cachedClCounts = new ConcurrentHashMap<>();
    // The live cache instances per network (also handed to the engine via the port
    // adapters), kept so "Clear caches" can wipe the in-memory + on-disk cache of a
    // running chain. Removed on shutdown.
    private final Map<String, AndroidPeerCache> elCaches = new ConcurrentHashMap<>();
    private final Map<String, AndroidCLPeerCache> clCaches = new ConcurrentHashMap<>();
    // Per-network lifecycle lock: a network's start() and stop() serialize on this, so a
    // fast Stop→Start or disable→enable of the same chain has the new boot wait for the old
    // teardown to free its ports AND unregister from the engine (create() throws on a
    // still-hosted network). STATIC, matching ENGINE and RUNNING: the engine registry
    // outlives a service instance, so a recreated service's boot must serialize against the
    // PREVIOUS instance's teardown thread — instance-scoped locks would let them interleave.
    private static final Map<String, Object> BOOT_LOCKS = new ConcurrentHashMap<>();
    private static Object bootLock(String network) {
        return BOOT_LOCKS.computeIfAbsent(canonicalNetwork(network), k -> new Object());
    }

    // ---------------------------------------------------------------------
    // Idle sleep controller: pause a stack's networking after idlePauseMinutes
    // of no RPC / UI activity. The engine self-wakes on an incoming JSON-RPC
    // request (the wake gate holds it until ready), so the controller only has
    // to decide when to go BACK to sleep — and to reconcile the notification
    // with wakes it didn't perform.
    // ---------------------------------------------------------------------

    /** How often the idle controller checks activity and reconciles the notification. */
    private static final long IDLE_TICK_MS = 30_000;
    /** Last UI-originated activity (query tab, ENS lookup, enable, app foreground). */
    private volatile long uiActivityMs;
    /** Per-network boot stamp: a freshly-started stack gets a full idle window.
     *  STATIC (matching ENGINE / RUNNING / BOOT_LOCKS): this is per-network-stack state that
     *  outlives a service instance, and the static {@link #dailyCatchUp} worker path reads/writes it. */
    private static final Map<String, Long> stackStartMs = new ConcurrentHashMap<>();
    /** Per-network stack-start stamp in monotonic {@link System#nanoTime} for the SYNCED-once
     *  ceiling only. Separate from {@link #stackStartMs} (wall-clock, used for idle-window display
     *  and the pause decision) so a wall-clock/NTP step can't prematurely expire or indefinitely
     *  extend the 30-minute run-until-synced backstop. Stamped alongside stackStartMs at boot,
     *  cleared on teardown. */
    private static final Map<String, Long> stackStartNano = new ConcurrentHashMap<>();
    /** Per-network HOST-side resume stamp (foreground resume, daily catch-up): gives
     *  the resumed stack a full idle window even though no request bumped the engine's
     *  activity clock. Engine-side wakes need no stamp — the waking request did it.
     *  STATIC so the {@link #dailyCatchUp} worker (no service binder) can hold the grace
     *  stamp while it catches up, keeping the instance idle ticker from pausing it mid-pass. */
    private static final Map<String, Long> lastResumeMs = new ConcurrentHashMap<>();
    /** Per-network flag: the stack has reached SYNCED (with a warm verified head) at least once
     *  since it (re)started. A fresh start must run through to SYNCED before the idle controller
     *  is allowed to pause it — pausing mid-initial-sync just makes the next wake redo the work.
     *  STATIC (like the stamps above): survives a service instance. Set true when first observed
     *  SYNCED and cleared when the network is torn down (so a disable→re-enable cold-starts the
     *  gate again); a stack that briefly falls out of sync after its first SYNCED still pauses on
     *  the normal idle rules. */
    private static final java.util.Set<String> reachedSynced = ConcurrentHashMap.newKeySet();
    /** Backstop for the SYNCED-once gate: if a fresh stack has been trying to reach SYNCED for
     *  this long (measured from its boot stamp) without success — no peers, a wedged sync, a
     *  perpetually-throwing status() — stop keeping it awake and let the idle controller pause it.
     *  Otherwise "run until synced" could drain the battery indefinitely on a node that never
     *  syncs, the exact thing the feature fights. Generous so a slow-but-progressing initial sync
     *  on a poor network still completes first. */
    private static final long SYNC_RUN_CEILING_MS = 30 * 60_000L;
    private volatile java.util.concurrent.ScheduledExecutorService idleTicker;
    /** The notification's current "title\ntext" content, so we re-notify only when it changes.
     *  Guarded by {@link #notifLock} for an atomic diff-and-notify across the idle ticker,
     *  boot threads, and the connectivity callback. */
    private volatile String notifiedContent;
    private final Object notifLock = new Object();
    /** Default-network callback: refreshes the notification the moment connectivity changes,
     *  so "No network connection" appears/clears without waiting for the 30 s idle reconcile. */
    private volatile ConnectivityManager.NetworkCallback notifNetCallback;
    /** Last device connectivity seen by the callback, so a capability jitter that doesn't flip
     *  up↔down skips the (per-stack) readiness poll. */
    private volatile Boolean lastNetworkUp;

    /** Note UI-originated activity so the idle controller keeps the node awake. */
    public void noteUiActivity() {
        uiActivityMs = System.currentTimeMillis();
    }

    /**
     * The app came to the foreground: count it as activity and proactively resume
     * every paused stack so the UI shows live data without waiting for a query.
     */
    public void onAppForeground() {
        noteUiActivity();
        for (Map.Entry<String, ChainHandle> e : handles.entrySet()) {
            String n = e.getKey();
            ChainHandle h = e.getValue();
            if (h.lifecycle() != io.myotis.api.LifecycleState.PAUSED) continue;
            lastResumeMs.put(n, System.currentTimeMillis());
            new Thread(() -> {
                synchronized (bootLock(n)) {
                    ChainHandle cur = handles.get(n);
                    if (cur != null && RUNNING.get()) {
                        LogBuffer.i(TAG, "[" + n + "] resuming (app foreground)");
                        // FOREGROUND is an observation wake: counts toward the pause total but
                        // must not overwrite the last-wake reason, or opening the app to view
                        // the status page would hide the request/catch-up wake being debugged.
                        try { cur.resume(io.myotis.api.WakeReason.FOREGROUND); } catch (Throwable t) {
                            LogBuffer.w(TAG, "[" + n + "] foreground resume failed: " + t);
                        }
                    }
                }
                updateNotification();
            }, "ethp2p-fg-resume-" + n).start();
        }
    }

    private void startIdleTicker() {
        if (idleTicker != null) return;
        java.util.concurrent.ScheduledExecutorService ex =
                Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "ethp2p-idle");
                    t.setDaemon(true);
                    return t;
                });
        ex.scheduleWithFixedDelay(() -> idleTick(idlePauseMinutes(this) * 60_000L),
                IDLE_TICK_MS, IDLE_TICK_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
        idleTicker = ex;
    }

    private void stopIdleTicker() {
        java.util.concurrent.ScheduledExecutorService ex = idleTicker;
        if (ex != null) {
            ex.shutdownNow();
            idleTicker = null;
        }
    }

    /**
     * One idle-controller pass: pause every RUNNING stack whose last activity —
     * engine-side (gated RPC/ENS/query), UI-side, or a host resume/boot stamp —
     * is older than {@code idleMs}, then reconcile the notification. Guarded:
     * an uncaught throw would silently stop all future scheduled runs.
     */
    private void idleTick(long idleMs) { idleTick(idleMs, true); }

    /**
     * @param routine {@code true} for the scheduled idle ticker — applies the battery-saving
     *   gates below. {@code false} for the emergency {@link #onTrimMemory} pause, which must go
     *   through regardless (a pre-sync node under memory pressure is better paused than
     *   OOM-killed and cold-started).
     *
     * <p>Routine gates, all skipped when {@code routine} is false:
     * <ul>
     *   <li><b>SYNCED-once</b> — never pause a stack that hasn't yet reached SYNCED (+ warm head)
     *       this run, so a fresh start finishes initial sync before its first sleep. Exception:
     *       if no network is available it can't sync anyway, so allow the pause rather than keep
     *       the radio scanning.</li>
     *   <li><b>Charging</b> — when {@link #stayAwakeWhileCharging} is on (default), the device is
     *       plugged in, <em>and</em> a network is available, skip auto-pause: battery isn't a
     *       concern, stay synced. Plugged in but offline still pauses (nothing to sync).</li>
     * </ul>
     */
    private void idleTick(long idleMs, boolean routine) {
        // Bail if the service is being torn down: doShutdown() runs on a worker thread, so a
        // scheduled tick (or the onTrimMemory pass) could otherwise spawn pause threads or mutate
        // reachedSynced after Stop. The per-stack pause thread re-checks RUNNING under bootLock too.
        if (!RUNNING.get()) return;
        try {
            long now = System.currentTimeMillis();
            // Process-global conditions, evaluated once per pass rather than per stack.
            boolean netUp = networkAvailable();
            // Stay awake while charging only when there's actually a network to stay synced over.
            // Plugged in but offline there's nothing to do, so let the stack pause rather than keep
            // the radio scanning — the same "no network -> pause anyway" rule the SYNCED gate uses.
            boolean skipWhileCharging =
                    routine && stayAwakeWhileCharging(this) && isCharging() && netUp;
            for (Map.Entry<String, ChainHandle> e : handles.entrySet()) {
                String n = e.getKey();
                ChainHandle h = e.getValue();
                if (idleMs <= 0) break; // auto-pause disabled
                io.myotis.api.LifecycleState ls;
                try { ls = h.lifecycle(); } catch (Throwable t) { continue; }
                if (ls != io.myotis.api.LifecycleState.RUNNING) continue;
                long lastActivity = Math.max(
                        Math.max(h.lastActivityEpochMillis(), uiActivityMs),
                        Math.max(lastResumeMs.getOrDefault(n, 0L),
                                 stackStartMs.getOrDefault(n, 0L)));
                if (now - lastActivity <= idleMs) continue;
                if (skipWhileCharging) continue; // plugged in: keep awake and synced
                // SYNCED-once gate: don't pause a stack still doing its initial sync — unless
                // there's no network to sync over, in which case sleeping saves battery.
                if (routine && !reachedSynced.contains(n)) {
                    if (isSyncedWarm(h)) {
                        reachedSynced.add(n); // first SYNCED reached; fall through to the pause
                        LogBuffer.i(TAG, "[" + n + "] reached SYNCED; idle-pause now eligible");
                    } else if (netUp && !syncRunCeilingReached(n)) {
                        continue; // still catching up with a network available — keep networking on
                    } else if (netUp) {
                        // Online but still not synced after the ceiling — stop draining battery
                        // on a stack that can't sync; let it pause and wake/retry later.
                        LogBuffer.i(TAG, "[" + n + "] not SYNCED after "
                                + (SYNC_RUN_CEILING_MS / 60_000L) + "m; allowing idle pause");
                    }
                    // else: not synced and offline → allow the pause below
                }
                long idleForSec = (now - lastActivity) / 1000;
                new Thread(() -> {
                    synchronized (bootLock(n)) {
                        // Re-check under the lock: a disable/reboot/stop may have raced us,
                        // and pause() on a stack that lost that race is a no-op anyway.
                        ChainHandle cur = handles.get(n);
                        if (cur != null && RUNNING.get() && isNetworkEnabled(this, n)) {
                            LogBuffer.i(TAG, "[" + n + "] idle " + idleForSec
                                    + "s; pausing networking (RPC keeps listening)");
                            try { cur.pause(); } catch (Throwable t) {
                                LogBuffer.w(TAG, "[" + n + "] pause failed: " + t);
                            }
                        }
                    }
                    updateNotification();
                }, "ethp2p-pause-" + n).start();
            }
            updateNotification();
        } catch (Throwable t) {
            LogBuffer.w(TAG, "idle tick error: " + t);
        }
    }

    /** The stack has a fresh verified head from a SYNCED beacon light client — the same
     *  "synced + warm head" bar the daily catch-up waits for before pausing again. */
    private static boolean isSyncedWarm(ChainHandle h) {
        try {
            StatusSnapshot s = h.status();
            return s.beaconState() == BeaconState.SYNCED
                    && s.verifiedHeadAgeMs() != Long.MAX_VALUE;
        } catch (Throwable t) {
            return false;
        }
    }

    /** True once a still-unsynced stack has been running past {@link #SYNC_RUN_CEILING_MS}, measured
     *  on the monotonic clock so a wall-clock/NTP step can't skew it. This is the backstop that stops
     *  "run until synced" from keeping networking on (and draining the battery) forever on a stack
     *  that never syncs. An absent stamp (shouldn't happen — set at boot) is treated as reached, so
     *  the SYNCED-once gate can't wedge a stack awake indefinitely. */
    private static boolean syncRunCeilingReached(String n) {
        Long startNano = stackStartNano.get(n);
        if (startNano == null) return true;
        return System.nanoTime() - startNano >= SYNC_RUN_CEILING_MS * 1_000_000L;
    }

    /** True when a network with Internet capability is active. Fail-open (true) if the state
     *  can't be read, so a transient query error doesn't wrongly let the idle tick pause a
     *  still-syncing stack. */
    private boolean networkAvailable() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (cm == null) return true;
            Network net = cm.getActiveNetwork();
            if (net == null) return false;
            android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            return caps != null
                    && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET);
        } catch (Throwable t) {
            return true;
        }
    }

    /** True when the device is plugged in (AC / USB / wireless) or actively charging — i.e.
     *  battery isn't a concern. Plug-state is read first (via the sticky ACTION_BATTERY_CHANGED
     *  intent) because {@code BatteryManager.isCharging()} reports charge state, which is false
     *  when plugged in but momentarily discharging under load. Fail-safe to false so a read error
     *  never blocks a pause. */
    private boolean isCharging() {
        try {
            android.content.Intent i = registerReceiver(null,
                    new android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED));
            if (i != null
                    && i.getIntExtra(android.os.BatteryManager.EXTRA_PLUGGED, 0) != 0) {
                return true; // plugged into AC / USB / wireless
            }
        } catch (Throwable ignored) {
            // fall through to the charge-state check
        }
        try {
            android.os.BatteryManager bm = getSystemService(android.os.BatteryManager.class);
            return bm != null && bm.isCharging();
        } catch (Throwable t) {
            return false;
        }
    }

    /** True when the service runs at least one stack and every live stack is paused. */
    private boolean allStacksPaused() {
        boolean any = false;
        for (ChainHandle h : handles.values()) {
            any = true;
            try {
                if (h.lifecycle() != io.myotis.api.LifecycleState.PAUSED) return false;
            } catch (Throwable t) {
                return false;
            }
        }
        return any;
    }

    /**
     * The daily maintenance pass ({@link CatchUpWorker}): for each idle-PAUSED stack,
     * resume, wait until the beacon client is SYNCED and the verified head is warm (or
     * the per-network budget slice runs out), and pause again — but only if no real
     * activity arrived meanwhile (then the idle controller owns the stack again).
     *
     * <p>Two distinct clocks, deliberately: the worker never touches the ENGINE's
     * activity clock ({@code lastActivityEpochMillis}), so the "did real activity
     * arrive?" check at the end stays honest. It DOES hold the host-side
     * {@link #lastResumeMs} grace stamp (refreshed each loop) while it runs, so the
     * instance idle ticker — which also considers {@code lastResumeMs} — won't pause
     * the just-resumed stack out from under the catch-up before it reaches SYNCED.
     * Snapshot persistence is free: the engine persists on every pause.
     *
     * <p>Static: the Worker has no binder; ENGINE / BOOT_LOCKS / the idle stamps are
     * all process-global.
     */
    public static void dailyCatchUp(long budgetMs) {
        List<String> hosted = ENGINE.hostedNetworks();
        if (hosted.isEmpty()) return;
        long sliceMs = Math.max(30_000L, budgetMs / hosted.size());
        for (String n : hosted) {
            ChainHandle h = ENGINE.get(n);
            if (h == null || h.lifecycle() != io.myotis.api.LifecycleState.PAUSED) continue;
            long activityBefore = h.lastActivityEpochMillis();
            LogBuffer.i(TAG, "[" + n + "] daily catch-up: resuming");
            boolean resumed;
            synchronized (bootLock(n)) {
                // Hold the grace stamp BEFORE resume returns RUNNING, so the idle ticker
                // can't pause the stack in the window between resume() and the loop.
                lastResumeMs.put(n, System.currentTimeMillis());
                resumed = h.resume(io.myotis.api.WakeReason.CATCH_UP);
            }
            if (!resumed) continue; // stays paused; next daily run retries
            // Monotonic deadline (nanoTime, overflow-safe compare) so an NTP/wall-clock
            // step can't cut the pass short or hang it.
            long deadlineNano = System.nanoTime() + sliceMs * 1_000_000L;
            while (System.nanoTime() - deadlineNano < 0) {
                // Refresh the grace stamp each iteration: keeps now-lastResumeMs well under
                // any idle window (min 60s) so the 30s idle ticker never pauses us mid-pass.
                lastResumeMs.put(n, System.currentTimeMillis());
                try {
                    StatusSnapshot s = h.status();
                    if (s.beaconState() == BeaconState.SYNCED
                            && s.verifiedHeadAgeMs() != Long.MAX_VALUE) {
                        break;
                    }
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Throwable ignored) {
                    break;
                }
            }
            // Real user/RPC activity arrived mid-catch-up → leave the stack to the
            // idle controller; otherwise go straight back to sleep (pause persists
            // the freshly-caught-up snapshot).
            if (h.lastActivityEpochMillis() == activityBefore) {
                synchronized (bootLock(n)) {
                    try { h.pause(); } catch (Throwable ignored) {}
                }
                LogBuffer.i(TAG, "[" + n + "] daily catch-up done; paused again");
            } else {
                LogBuffer.i(TAG, "[" + n + "] daily catch-up: activity arrived; staying awake");
            }
        }
    }

    /** Re-issue the foreground notification when its content changed — the sleeping/active
     *  state (incl. engine-initiated wakes), the per-network readiness, or connectivity. */
    private void updateNotification() {
        if (!RUNNING.get()) return;
        try {
            // Poll live state OUTSIDE the lock (status()/lifecycle() are blocking engine calls).
            String[] tt = notificationText();
            String key = tt[0] + "\n" + tt[1];
            // Diff-and-notify atomically so concurrent callers can't post out of order or both
            // re-notify the same content; building the Notification is cheap (no engine calls).
            synchronized (notifLock) {
                if (key.equals(notifiedContent)) return;   // unchanged → skip the re-notify
                notifiedContent = key;
                NotificationManager nm = getSystemService(NotificationManager.class);
                if (nm != null) nm.notify(NOTIFICATION_ID, buildNotification(tt[0], tt[1]));
            }
        } catch (Throwable t) {
            LogBuffer.w(TAG, "notification update failed: " + t);
        }
    }

    /**
     * The ongoing notification's {@code [title, text]}, derived from live node + connectivity
     * state. Priority: idle-sleep (networking intentionally off) → no device network → per-network
     * readiness. Readiness mirrors the in-app {@code ReadinessStrip} tiers.
     */
    private String[] notificationText() {
        if (allStacksPaused()) {
            return new String[]{"ethp2p node sleeping", "Networking off — a wallet request wakes it"};
        }
        if (!networkAvailable()) {
            // Actively meant to be running, but the device has no connectivity — surface it: the
            // node can't discover peers or sync until a network returns.
            return new String[]{"ethp2p node running", "No network connection"};
        }
        return new String[]{"ethp2p node running", readinessSummary()};
    }

    /** Per-network readiness on one line, e.g. {@code "mainnet ready · gnosis syncing"}; sorted by
     *  network name so the text is stable across polls. Empty (pre-boot) → {@code "Starting…"}. */
    private String readinessSummary() {
        java.util.List<String> names = new java.util.ArrayList<>(handles.keySet());
        java.util.Collections.sort(names);
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            ChainHandle h = handles.get(n);
            if (h == null) continue;
            if (sb.length() > 0) sb.append(" · ");
            sb.append(n).append(' ').append(readinessWord(h));
        }
        return sb.length() == 0 ? "Starting…" : sb.toString();
    }

    /** One-word readiness for a stack, mirroring the app's {@code ReadinessStrip} tiers:
     *  {@code sleeping} (paused) → {@code syncing} (beacon not SYNCED) → {@code warming up}
     *  (SYNCED but no verified head yet, so reads would 503) → {@code ready}. */
    private static String readinessWord(ChainHandle h) {
        try {
            if (h.lifecycle() == io.myotis.api.LifecycleState.PAUSED) return "sleeping";
            StatusSnapshot s = h.status();
            if (s.beaconState() != BeaconState.SYNCED) return "syncing";
            if (s.verifiedHeadAgeMs() == Long.MAX_VALUE) return "warming up";
            return "ready";
        } catch (Throwable t) {
            return "…";
        }
    }

    /** Register a default-network callback that refreshes the notification on connectivity
     *  changes, so the "No network connection" line appears/clears promptly. Best-effort. */
    private void registerNotifNetworkCallback() {
        if (notifNetCallback != null) return;
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (cm == null) return;
            lastNetworkUp = networkAvailable();   // seed so the first callback doesn't spuriously poll
            ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { onNotifConnectivityChanged(); }
                @Override public void onLost(Network network) { onNotifConnectivityChanged(); }
                @Override public void onCapabilitiesChanged(
                        Network network, android.net.NetworkCapabilities caps) { onNotifConnectivityChanged(); }
            };
            cm.registerDefaultNetworkCallback(cb);
            // Publish only AFTER registration succeeded: if register throws, the
            // field stays null so the top-of-method guard lets a later call retry
            // (a pre-assignment would wedge connectivity refreshes until restart).
            notifNetCallback = cb;
        } catch (Throwable t) {
            LogBuffer.w(TAG, "notification network callback registration failed: " + t);
        }
    }

    /** Refresh the notification only when device connectivity actually flipped up↔down —
     *  capability callbacks fire often (signal / metering / validation changes) and each would
     *  otherwise trigger a full per-stack readiness poll.
     *
     *  <p>NetworkCallback runs on the system's shared connectivity thread, so the blocking
     *  readiness poll (h.status()) must NOT run here — offload to {@link #QUERY_POOL}. The
     *  up↔down gate is checked under {@link #notifLock} so concurrent callbacks don't both poll. */
    private void onNotifConnectivityChanged() {
        QUERY_POOL.execute(() -> {
            boolean up = networkAvailable();
            synchronized (notifLock) {
                Boolean prev = lastNetworkUp;
                if (prev != null && prev == up) return;   // no real change → skip the readiness poll
                lastNetworkUp = up;
            }
            updateNotification();
        });
    }

    private void unregisterNotifNetworkCallback() {
        ConnectivityManager.NetworkCallback cb = notifNetCallback;
        notifNetCallback = null;
        if (cb == null) return;
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (cm != null) cm.unregisterNetworkCallback(cb);
        } catch (Throwable ignored) {}
    }

    // Runs the BLOCKING engine-API calls (requestAccount, ens().resolveAddress) off the
    // caller's thread — the service's public surface stays CompletableFuture-based for
    // the Kotlin bridge, so the blocking API call is wrapped here. Static daemon pool:
    // queries may outlive a service instance teardown harmlessly.
    private static final ExecutorService QUERY_POOL =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "android-engine-query");
                t.setDaemon(true);
                return t;
            });

    // Query-tab history. Lazily created from getFilesDir() so it works even
    // when the node is stopped (the UI can browse/re-run past queries anytime).
    private AndroidQueryHistory queryHistory;

    private final IBinder binder = new LocalBinder();

    public final class LocalBinder extends Binder {
        public NodeService service() { return NodeService.this; }
    }

    public record Snapshot(
            boolean running,
            String lifecycle,         // "RUNNING" | "PAUSED" | "STOPPED" — PAUSED is the
                                      // idle sleep state: networking off, RPC listening,
                                      // warm state retained, first request wakes it
            long startTimeMs,         // start stamp of THIS network's stack (per engine
                                      // start; resets on every network/engine reboot),
                                      // 0 when the stack isn't live — drives the UI uptime
            int discoveredPeers,
            int connectedPeers,
            int readyPeers,
            int snapPeers,            // peers that NEGOTIATED snap/1 (capability flag)
            int snapServingPeers,     // peers actually in the serving pool right now
                                      // (negotiated, READY, not benched by snapServingFailed) —
                                      // this is what head builds / heavy confirm screens use.
                                      // Can be far below snapPeers when peers bench out, which
                                      // is what made "54 snap peers but amber/stuck" so confusing.
            int cachedPeers,           // EL peers in peers[-net].cache (live file count)
            int elCachedSnapOk,        // …of which snap-serving confirmed (snapok token)
            int elCachedSnapBad,       // …of which snap-serving denied (snapbad token)
            int attemptedPeers,
            int backedOffPeers,
            int blacklistedPeers,
            int discv5Peers,          // total live nodes in the discv5 routing table
            int clPeersDiscovered,    // discv5 peers whose eth2 field matches our fork digest
            // Beacon light client status (filled in only when BLC is wired up)
            String beaconState,       // "STOPPED", "SYNCING", "CATCHING_UP", "SYNCED"
            boolean beaconBootstrapped,
            int clPeersConnected,
            int clPeersLightClient,
            int clPeersServedLastMin, // distinct peers that served a light-client
                                      // response in the last 60s — CL connections are
                                      // short-lived, so clPeersConnected is usually 0
                                      // and THIS is the "are we being fed?" signal
            int clPeersCached,         // CL peers in cl-peers[-net].cache (live file count)
            int clCachedProven,        // …of which proven LC servers (served-range or lc token)
            int clCachedNolc,          // …of which known non-LC (nolc token; proven wins on conflict)
            long finalizedSlot,
            long executionBlockNumber,
            String executionBlockHashHex, // null until first finality update
            // Sync-committee-period catch-up progress; all -1 until known. UI draws a
            // determinate progress bar from (current - start) / (target - start).
            long syncStartPeriod,
            long syncCurrentPeriod,
            long syncTargetPeriod,
            // Age (ms) of the last verified RPC head, Long.MAX_VALUE if none built yet.
            // The readiness traffic-light's green gate: a recent head means wallet
            // calls serve instead of hitting "no verified head".
            long verifiedHeadAgeMs,
            List<io.myotis.api.PeerInfo> readyPeerList,
            String network,               // active chain ("mainnet"/"gnosis")
            // Idle-sleep metrics (see WakeReason / SleepMetrics) — for the Status screen.
            int pauseCount,               // times this stack entered idle sleep since start
            long totalPausedMs,           // cumulative time paused (ms)
            long lastPauseEpochMs,        // wall-clock ms of the last pause; 0 if never
            long lastResumeEpochMs,       // wall-clock ms of the last DEMAND wake; 0 if none
            String lastWakeReason,        // reason tag of the last demand wake; null if none
            boolean lcHunting) {}         // LC hunt engaged (starved of light-client servers)

    /** Result of a get-account query. Mirrors the JVM daemon's JSON response shape. */
    public record AccountQueryResult(
            String address,                  // 0x-prefixed checksum-form input
            boolean exists,                  // false when the account isn't in the trie
            long nonce,                      // -1 when !exists
            String balanceWei,               // decimal string (BigInteger.toString); null when !exists
            String storageRootHex,           // null when !exists
            String codeHashHex,              // null when !exists
            long blockNumber,                // peer-reported block number the proof is anchored to
            String peerStateRootHex,         // 0x… root the proof was built against
            boolean peerProofValid,          // proof verifies against peerStateRoot
            boolean beaconChainVerified,     // peerStateRoot matches a beacon-attested root
            boolean blsVerified,             // beacon match was BLS-signed (vs. unverified header)
            long matchedBeaconSlot,          // -1 when not matched
            String verifyMethod,             // "stateRootMatch" or null
            String failReason                // null when verified
    ) {}

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    /**
     * Run a get-account query against any active READY+snap peer and verify
     * the returned proof against the beacon-attested state root.
     *
     * <p>Two verification methods, mirroring the JVM daemon
     * ({@code CommandHandler#buildVerificationJson} for {@code get-account}):
     * <ul>
     *   <li><b>headerChain</b> (load-bearing path) — fetch the contiguous
     *       header range {@code [finalizedBlock .. peerBlock]} via eth/68
     *       from the same peer that served the proof, verify the
     *       parent-hash chain, and require the first header's stateRoot
     *       to equal the BLC-finalized execution stateRoot and the last
     *       header's stateRoot to equal the peer-reported stateRoot. This
     *       is what succeeds in normal operation, because snap peers serve
     *       proofs at their head while the BLC's attested-root window
     *       trails finalized + a few recent optimistic slots.</li>
     *   <li><b>stateRootMatch</b> (fast-path shortcut) — if the peer's
     *       reported stateRoot happens to be one the BLC has already
     *       attested ({@code BeaconSyncState.findStateRoot}), skip the
     *       header fetch entirely. Rare in practice: only fires when the
     *       peer's head briefly aligns with a slot the BLC has just seen.</li>
     * </ul>
     * The shortcut is checked first so that when it does fire we save a
     * round-trip; otherwise we fall through to the headerChain path.
     */
    // CompletableFuture.failedFuture (Java 9, hidden behind Android API 31)
    // and orTimeout (also gated to API 31) are backported to minSdk 29 via
    // desugar_jdk_libs 2.1.3 — see android-app/build.gradle.kts. Lint flags
    // them anyway because its API database doesn't track desugar coverage
    // for every CF method. Suppress at the method level rather than file —
    // a future use of a *genuinely* unbackported API should still trip.
    /** Back-compat: query against the primary enabled network. */
    public CompletableFuture<AccountQueryResult> requestAccount(String hexAddress) {
        return requestAccount(primaryNetwork(this), hexAddress);
    }

    @SuppressLint("NewApi") // CompletableFuture.failedFuture (API 31) is backported to
                            // minSdk 29 via desugar_jdk_libs — see the comment block above.
    public CompletableFuture<AccountQueryResult> requestAccount(String network, String hexAddress) {
        noteUiActivity();
        ChainHandle handle = handles.get(canonicalNetwork(network));
        if (handle == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Node is not running"));
        }
        // The engine call is blocking (snap fetch + verification ladder, internally
        // timeout-bounded) — run it on the query pool and expose the future the UI expects.
        return CompletableFuture.supplyAsync(
                () -> toAccountQueryResult(handle.requestAccount(hexAddress)), QUERY_POOL);
    }

    private static AccountQueryResult toAccountQueryResult(AccountProofResult r) {
        return new AccountQueryResult(
                r.address(), r.exists(), r.nonce(), r.balanceWei(),
                r.storageRootHex(), r.codeHashHex(), r.blockNumber(),
                r.peerStateRootHex(), r.peerProofValid(), r.beaconChainVerified(),
                r.blsVerified(), r.matchedBeaconSlot(), r.verifyMethod(), r.failReason());
    }

    // ---------------------------------------------------------------------
    // ENS resolution + query history
    // ---------------------------------------------------------------------

    private static final long ENS_TIMEOUT_SEC = 60;

    /** Lazily-created, file-backed history of Query-tab inputs. */
    public synchronized AndroidQueryHistory queryHistory() {
        if (queryHistory == null) {
            queryHistory = new AndroidQueryHistory(
                    new java.io.File(getFilesDir(), "query-history.tsv").toPath());
        }
        return queryHistory;
    }

    /**
     * Heuristic: is {@code input} an ENS name (vs a hex address)? A 40-hex
     * string (with or without {@code 0x}) is an address; anything else is an
     * ENS name. Addresses never contain a dot; ENS names do.
     */
    public static boolean looksLikeEnsName(String input) {
        if (input == null) return false;
        String s = input.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if (s.length() != 40) return true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return true;
        }
        return false;
    }

    /**
     * Outcome of an ENS forward resolution. {@code addressHex} null if unresolved.
     * {@code beaconVerified} is true when the resolution ran against the
     * beacon-verified finalized state (default), so the name→address mapping is
     * cryptographically anchored; false in PEER_HEAD mode (peer-claimed mapping).
     */
    public record EnsResolution(String name, String addressHex, long blockNumber,
                                boolean beaconVerified, String error) {}

    /**
     * Which state ENS resolution runs against. Defaults to AUTO (beacon-verified
     * finalized root first, peer-head fallback); switch to {@link EnsRoot#PEER_HEAD}
     * for freshest (unverified) data. Library consumers can override via
     * {@link #setEnsResolutionRoot}.
     */
    private volatile EnsRoot ensResolutionRoot = EnsRoot.AUTO;

    public void setEnsResolutionRoot(EnsRoot root) {
        if (root != null) this.ensResolutionRoot = root;
    }

    public EnsRoot getEnsResolutionRoot() {
        return ensResolutionRoot;
    }

    /**
     * Resolve an ENS name to an address by running the ENS contracts in a local
     * Besu EVM over SNAP-verified state — the same stack as the JVM daemon's
     * {@code resolve-ens}. Never throws; failures come back in
     * {@link EnsResolution#error}.
     *
     * <p>In {@link io.myotis.ens.EnsResolutionRoot#AUTO} (default) we resolve
     * against the beacon-verified finalized state first; only if that yields no
     * address (record not yet in finalized state) or errors do we fall back to
     * the peer head (returned marked unverified). See {@link EnsResolutionRoot}.
     */
    /** Back-compat: resolve against the primary enabled network. */
    public CompletableFuture<EnsResolution> resolveEns(String name) {
        return resolveEns(primaryNetwork(this), name);
    }

    @SuppressLint("NewApi") // CompletableFuture.failedFuture — see requestAccount
    public CompletableFuture<EnsResolution> resolveEns(String network, String name) {
        noteUiActivity();
        final String trimmed = name == null ? "" : name.trim();
        final String n = canonicalNetwork(network);
        // ENS is mainnet/Sepolia-only — refuse early so we never run ENS contracts against
        // a chain that can't have them; the UI also hides the ENS path there.
        if (!networkInfo(n).hasEns()) {
            return CompletableFuture.completedFuture(new EnsResolution(
                    trimmed, null, -1, false, "ENS is not available on " + n));
        }
        ChainHandle handle = handles.get(n);
        io.myotis.api.EnsApi ens = handle != null ? handle.ens() : null;
        if (!RUNNING.get() || ens == null) {
            return CompletableFuture.completedFuture(
                    new EnsResolution(trimmed, null, -1, false, "node not running on " + n));
        }
        // Delegate to the engine's shared resolution machinery (one AUTO → FINALIZED →
        // PEER_HEAD policy for daemon + desktop + Android). The engine call is blocking —
        // run on the query pool; NOTE the API's no-record convention: addressHex==null
        // with error==null is a successful "name has no record".
        final EnsRoot root = ensResolutionRoot;
        return CompletableFuture.supplyAsync(() -> {
            EnsResolutionResult r = ens.resolveAddress(trimmed, root);
            return new EnsResolution(r.name(), r.addressHex(), r.blockNumber(),
                    r.verified(), r.error());
        }, QUERY_POOL);
    }


    /** DNS server IPs for the active network, for EIP-1459 ENR-tree TXT lookups.
     *  dnsjava has no system resolver config on Android, so we feed it these
     *  explicitly. Returns empty (→ resolver uses public-DNS fallback) on any error. */
    private List<String> activeNetworkDnsServers() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (cm == null) return List.of();
            Network active = cm.getActiveNetwork();
            if (active == null) return List.of();
            LinkProperties lp = cm.getLinkProperties(active);
            if (lp == null) return List.of();
            List<String> ips = new ArrayList<>();
            for (InetAddress dns : lp.getDnsServers()) {
                ips.add(dns.getHostAddress());
            }
            return ips;
        } catch (Exception e) {
            LogBuffer.w(TAG, "could not read active-network DNS servers: " + e.getMessage());
            return List.of();
        }
    }


    /**
     * Render the whole cause chain, deepest cause included. Library wrappers
     * (e.g. Caffeine throwing {@code IllegalStateException(className)} around a
     * reflective failure) otherwise mask the real Android-incompatibility under
     * a misleading top-level message.
     */
    private static String unwrap(Throwable t) {
        StringBuilder sb = new StringBuilder();
        java.util.Set<Throwable> seen =
                java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Throwable c = t; c != null && seen.add(c); c = c.getCause()) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
        }
        return sb.toString();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The system may redeliver onStartCommand (e.g. repeated taps, or a
        // restart race with stopService). Guard so we don't boot two copies
        // of the node racing for the same UDP/TCP ports.
        if (!RUNNING.compareAndSet(false, true)) {
            LogBuffer.i(TAG, "start requested but node is already running");
            return START_NOT_STICKY;
        }
        // Failure forensics: report how the PREVIOUS process died (OOM-kill vs crash
        // vs clean), then start the health heartbeat. This is what makes an on-device
        // sync failure diagnosable instead of a silent "it doesn't work".
        ProcessHealthDiag.logLastExitReason(this);
        startHealthHeartbeat();
        startRustLogPump();
        // API 34+ requires the foregroundServiceType to be passed here and
        // to match the manifest's <service android:foregroundServiceType="...">
        // declaration. API 29-33 ignore the third arg. minSdk is 29.
        String[] tt0 = notificationText();
        synchronized (notifLock) {   // the field's documented guard — keep the prime
            notifiedContent = tt0[0] + "\n" + tt0[1];   // ordered with any concurrent diff-and-notify
        }
        startForeground(NOTIFICATION_ID, buildNotification(tt0[0], tt0[1]),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        startIdleTicker();
        registerNotifNetworkCallback();

        // Boot every enabled network as its own stack (Step 9). Each Netty/libp2p boot is
        // blocking-ish, so build + start each on its own worker; they bind distinct ports
        // (NetworkConfig.defaultElPort/Discv5Port/RpcPort) so they never collide.
        for (String n : enabledNetworks(this)) {
            spawnBoot(n, stopGen(n), null, "ethp2p-boot-" + n);
        }
        return START_NOT_STICKY;
    }

    /**
     * Build and start one network's engine stack, register its handle in
     * {@link #handles}, and capture its boot-time cached-peer counts. The engine owns
     * discv4/discv5/beacon/RPC + the snap-peer maintainer and serializes start()/shutdown()
     * internally, so a fast disable→enable (or rebootNetwork) of the same chain waits for
     * its own ports to free. Stops the service only if the very last stack fails to come up.
     */
    private void buildAndStart(String netName, long gen) {
        String n = canonicalNetwork(netName);
        ChainHandle created = null;
        try {
            int rpcPort = rpcPortFor(this, n);
            // Mirror the native-BLS toggle into the process-wide BlsBackends selection (set the
            // property + select() the backend). The Settings switch also applies it live on
            // toggle; re-applying here keeps a freshly (re)started stack consistent. (This is
            // an internal engine seam, not part of the api — deliberate.)
            String blsChoice = applyBlsBackend(this);
            // Same idea for the engine choice: the Settings toggle also applies it on flip,
            // re-applying here makes a freshly (re)started network honor the current setting.
            String engineChoice = applyEngineChoice(this);
            LogBuffer.i(TAG, "[" + n + "] booting (snap target " + snapTarget(this)
                    + ", rpc port " + rpcPort
                    + ", state-freshness " + (strictStateFreshness(this) ? "strict" : "relaxed")
                    + ", bls " + blsChoice
                    + ", engine " + engineChoice + ")");

            // create() + start() under the per-network bootLock: a Stop→Start / disable→enable
            // has this boot wait for the old instance's teardown (which holds the same lock) to
            // free the ports AND unregister from the engine (create() throws on a still-hosted
            // network). A whole-service Stop, a per-network disable, or a runtime stopNetwork
            // (which bumps the stop generation instead of the enabled flag) could race this
            // boot, so bail if any says the chain is no longer wanted — re-checked after
            // start() too, since start() blocks and the race window spans it. spawnBoot's worker fires
            // the service-stop check after every bail/return path.
            synchronized (bootLock(n)) {
                if (!RUNNING.get() || !isNetworkEnabled(this, n) || stopGen(n) != gen) {
                    LogBuffer.i(TAG, "[" + n + "] stop/disable raced boot; skipping");
                    forgetStack(n);
                    return;
                }
                if (ENGINE.get(n) != null) {
                    // Already hosted: a genuine double-enable, or a teardown we raced won the
                    // lock first and hasn't unregistered yet (it holds this lock, so by the
                    // time we're here it HAS — this branch is then a plain double-enable).
                    // Log it so an enabled-but-dead chain is diagnosable, and make the UI map
                    // consistent with the engine either way.
                    LogBuffer.i(TAG, "[" + n + "] boot skipped: already hosted by the engine");
                    ChainHandle existing = ENGINE.get(n);
                    if (existing != null) handles.putIfAbsent(n, existing);
                    return;
                }

                // Build the caches HERE — inside the lock, after every bail check — so an
                // early bail can never orphan a freshly-started cache writer thread, and the
                // maps can never be clobbered while a live stack still uses the previous
                // instances (the engine owns these via the port adapters from create() on).
                // Reconstructible network state lives in getCacheDir() so "Clear cache" wipes
                // the peer caches + sync snapshot while identity / query history in
                // getFilesDir() survive.
                AndroidPeerCache pc = new AndroidPeerCache(netCacheFor(n, "peers", ".cache").toPath());
                AndroidCLPeerCache cl = new AndroidCLPeerCache(netCacheFor(n, "cl-peers", ".cache").toPath());
                cachedElCounts.put(n, pc.load().size());
                cachedClCounts.put(n, cl.load().size());
                elCaches.put(n, pc);
                clCaches.put(n, cl);

                // EL/discv5 ports use the engine's per-network defaults (0); the RPC port is
                // the user-configurable one. The snap maintainer keeps snap peers topped up
                // (the discv4-independent path NAT'd mobile needs); Android supplies the
                // active network's DNS servers for EIP-1459 resolution.
                EngineConfig config = new EngineConfig(
                        n, 0, 0, rpcPort,
                        netCacheFor(n, "sync-state", ".snapshot").getAbsolutePath(),
                        /*gossipsub*/ false,
                        snapTarget(this),
                        strictStateFreshness(this),
                        // Reconstructible engine-owned state belongs with the other network
                        // caches so "Clear cache" wipes it too.
                        getCacheDir().getAbsolutePath());
                EnginePorts ports = new EnginePorts(
                        // Identity: legacy mainnet keeps nodekey.hex; other chains get a
                        // per-network key so two chains never share an identity.
                        new AndroidNodeKeyStore(getFilesDir()),
                        new AndroidPeerCacheAdapter(pc),
                        new AndroidClPeerCacheAdapter(cl),
                        this::activeNetworkDnsServers,
                        new com.jaeckel.ethp2p.android.ens.AndroidCcipGateway(),
                        null, null); // engine default logger/clock

                ChainHandle handle = ENGINE.create(config, ports);
                created = handle;
                // Drop the previous run's start stamps BEFORE publishing the handle: the
                // UI poll renders a snapshot as soon as handles has an entry, and start()
                // below blocks for seconds — a stale stamp would show the old run's
                // uptime (plus downtime) until the fresh stamp lands. Removed-then-
                // restamped, a mid-boot snapshot reads 0s instead.
                stackStartMs.remove(n);
                stackStartNano.remove(n);
                // Apply the Settings served-block window (before start(), so the very first
                // eth/69 Status advertises the configured size) and publish the handle under
                // the handles monitor, with the pref read INSIDE it: setServedBlockWindow's
                // Save fan-out takes the same monitor, so either its iteration sees this
                // handle in the map, or our pref read observes its already-persisted value.
                // Without this pairing a Save landing between our pref read and handles.put
                // would leave the live window one Save behind the pref.
                synchronized (handles) {
                    handle.setServedBlockWindow(servedBlockWindow(this));
                    handles.put(n, handle);
                }
                if (!handle.start()) {
                    LogBuffer.e(TAG, "[" + n + "] node stack failed to start");
                    forgetStack(n);
                    try { ENGINE.stop(n); } catch (Throwable ignored) {}
                    return;
                }
                if (!RUNNING.get() || !isNetworkEnabled(this, n) || stopGen(n) != gen) {
                    LogBuffer.i(TAG, "[" + n + "] stop/disable raced start; tearing down");
                    forgetStack(n);
                    try { ENGINE.stop(n); } catch (Throwable ignored) {}
                    return;
                }
                // A freshly-booted stack gets a full idle window before the controller
                // may pause it (its engine activity clock starts at 0). Stamped INSIDE the
                // bootLock: written outside it, a racing stopNetwork's forgetStack could
                // remove the stamp first and have this put leak it back for a dead network.
                stackStartMs.put(n, System.currentTimeMillis());
                stackStartNano.put(n, System.nanoTime());   // monotonic clock for the sync-run ceiling
            }
            updateNotification();
            LogBuffer.i(TAG, "[" + n + "] node stack started (RPC " + rpcPort + ")");
        } catch (Exception e) {
            LogBuffer.e(TAG, "[" + n + "] node boot failed", e);
            // Clean up ONLY this attempt's state, under the lock. The exception released
            // the bootLock, so a racing enable may already have registered a fresh healthy
            // instance — an unconditional forgetStack here would wipe that instance's
            // handle + stamps (and before the lock was even taken, an early throw would
            // wipe a previous healthy run's bookkeeping). Tear down iff the registered
            // handle is still OURS, or nothing is registered (then only stale cache/count
            // bookkeeping from this attempt can remain).
            synchronized (bootLock(n)) {
                ChainHandle current = handles.get(n);
                if (created != null ? current == created : current == null) {
                    forgetStack(n);
                    if (created != null && ENGINE.get(n) == created) {
                        try { ENGINE.stop(n); } catch (Throwable ignored) {}
                    }
                }
            }
            // service-stop check happens in the boot worker's finally, after the in-flight count drops
        }
    }

    /** Node-identity storage over getFilesDir(): one hex file per network, byte-compatible
     *  with the files NodeKey.loadOrGenerate has always written (identities carry over). */
    private static final class AndroidNodeKeyStore implements NodeKeyStore {
        private final java.io.File filesDir;
        AndroidNodeKeyStore(java.io.File filesDir) { this.filesDir = filesDir; }
        private Path fileFor(String network) {
            return new java.io.File(filesDir,
                    network.equals("mainnet") ? "nodekey.hex" : "nodekey-" + network + ".hex").toPath();
        }
        @Override public byte[] load(String networkName) {
            Path file = fileFor(networkName);
            if (!Files.exists(file)) return null;
            try {
                String hex = new String(Files.readAllBytes(file),
                        java.nio.charset.StandardCharsets.UTF_8).strip();
                if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
                // Hand-rolled hex: java.util.HexFormat is API 34 and NOT covered by
                // core-library desugaring, so it would crash at runtime on minSdk 29.
                if (hex.length() % 2 != 0) throw new IllegalArgumentException("odd-length hex");
                byte[] out = new byte[hex.length() / 2];
                for (int i = 0; i < out.length; i++) {
                    int hi = Character.digit(hex.charAt(i * 2), 16);
                    int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
                    if (hi < 0 || lo < 0) throw new IllegalArgumentException("non-hex character");
                    out[i] = (byte) ((hi << 4) | lo);
                }
                return out;
            } catch (Exception e) {
                throw new RuntimeException("failed to read node key " + file + ": " + e.getMessage(), e);
            }
        }
        @Override public void store(String networkName, byte[] secret32) {
            Path file = fileFor(networkName);
            try {
                StringBuilder sb = new StringBuilder(2 + secret32.length * 2);
                sb.append("0x");
                for (byte b : secret32) {
                    sb.append(Character.forDigit((b >> 4) & 0xF, 16))
                      .append(Character.forDigit(b & 0xF, 16));
                }
                Files.write(file, sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new RuntimeException("failed to write node key " + file + ": " + e.getMessage(), e);
            }
        }
    }

    /**
     * Tear down the node from the UI.
     * <p>
     * {@code stopService()} alone does not shut us down, because MainActivity
     * holds a binding with {@code BIND_AUTO_CREATE}: Android keeps the service
     * alive as long as such a binding exists, even after stopService. So we
     * close networking here and drop the foreground notification immediately;
     * the service instance may linger until the activity unbinds, but the node
     * is no longer running.
     */
    public void shutdown() {
        LogBuffer.i(TAG, "shutdown requested from UI");
        // Flip RUNNING + clear the foreground notification synchronously so
        // the UI button flips and the notification disappears immediately.
        // The expensive close chain (libp2p host.stop().join(), Netty
        // shutdownGracefully, syncThread.join) runs on a worker — doing it
        // on the UI thread blocks main for seconds and ANRs.
        RUNNING.set(false);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
        new Thread(this::doShutdown, "ethp2p-shutdown").start();
    }

    /**
     * Worker-thread close chain for a whole-service Stop: tears down every live stack. The
     * {@code synchronized} keeps two whole-service teardowns from overlapping; the cross-instance
     * Stop→Start port race is handled per network by {@link #bootLock} (held around each stack's
     * shutdown() here and around the new instance's start() in {@link #buildAndStart}), so a fast
     * Stop→Start blocks the new boot until the old stack's ports are released instead of failing
     * with bind-in-use.
     */
    private synchronized void doShutdown() {
        // Stop and drop every network. Iterate the ENGINE's registry (not this instance's
        // mirror map): with a process-global engine, "stop everything" must be scoped to
        // what the engine actually hosts, or a handles/engine divergence would leak a stack.
        for (String n : ENGINE.hostedNetworks()) {
            // Hold the per-network lock so a racing buildAndStart for the same chain can't start a
            // new instance while we're tearing the old one down (would race for the same ports).
            synchronized (bootLock(n)) {
                try { ENGINE.stop(n); } catch (Throwable ignored) {}
            }
        }
        handles.clear();
        cachedElCounts.clear();
        cachedClCounts.clear();
        elCaches.clear();
        clCaches.clear();
        // Safe to clear: a Stop->Start just re-runs the SYNCED-once gate until the restarted
        // stack re-observes SYNCED — fast off the warm store, no freeze. stackStartMs is
        // deliberately NOT cleared here (it's static, per-network, and owned by boots): a
        // whole-service stop may leave stale entries, but they're invisible — handles was
        // cleared above so no snapshot is rendered — and the next boot of each network
        // removes its stamp before publishing the handle, then re-stamps after start()
        // succeeds. Clearing here would race a quick Stop->Start's fresh boot (the old
        // service-global startTimeMs had exactly that clobber bug).
        reachedSynced.clear();
        LogBuffer.i(TAG, "node shutdown complete");
    }

    /**
     * Wipe the in-memory backoff + blacklist sets and delete the on-disk peer
     * cache. Safe to call while the node is running; the next discv4 hit will
     * refill backoff/blacklist from scratch, and {@link AndroidPeerCache} will
     * recreate the file on the next successful RLPx handshake.
     *
     * <p>Does not touch {@code attempted} — those are live in-flight dials, not
     * a cache, and clearing them would race with the per-peer close callback.
     */
    public void clearCaches(String network) {
        String n = canonicalNetwork(network);
        LogBuffer.i(TAG, "[" + n + "] clearing peer caches from UI");
        // File deletes are fast in the happy case but still IO; keep the UI
        // thread off them so a slow flash + cache-file fsync can't ANR.
        new Thread(() -> doClearCaches(n), "ethp2p-clear-caches-" + n).start();
    }

    private void doClearCaches(String n) {
        // Backoff/blacklist live in the engine; clear them through the API so "Clear caches"
        // gives discovery a fresh slate (the on-disk peer caches are wiped below).
        ChainHandle h = handles.get(n);
        if (h != null) { try { h.clearPeerState(); } catch (Throwable ignored) {} }
        cachedElCounts.put(n, 0);
        cachedClCounts.put(n, 0);
        // Clear the live cache instance when the chain is up (also wipes the file); when it's
        // stopped no live instance exists, so delete the on-disk file directly.
        AndroidPeerCache pc = elCaches.get(n);
        if (pc != null) {
            pc.clear();
        } else {
            java.io.File cacheFile = netCacheFor(n, "peers", ".cache");
            if (cacheFile.exists() && !cacheFile.delete()) {
                LogBuffer.w(TAG, "failed to delete " + cacheFile);
            }
        }
        AndroidCLPeerCache clpc = clCaches.get(n);
        if (clpc != null) {
            clpc.clear();
        } else {
            java.io.File clCacheFile = netCacheFor(n, "cl-peers", ".cache");
            if (clCacheFile.exists() && !clCacheFile.delete()) {
                LogBuffer.w(TAG, "failed to delete " + clCacheFile);
            }
        }
    }

    /**
     * Delete a network's persisted sync-committee snapshot so the next start re-bootstraps
     * from the embedded checkpoint and re-runs the full catch-up. For debugging the
     * bootstrap/catch-up path without wiping peer caches. The running store keeps its
     * in-memory state; this only affects the NEXT start.
     */
    public void resetSyncState(String network) {
        String n = canonicalNetwork(network);
        LogBuffer.i(TAG, "[" + n + "] resetting persisted sync state from UI");
        new Thread(() -> {
            java.io.File snap = netCacheFor(n, "sync-state", ".snapshot");
            if (snap.exists() && !snap.delete()) {
                LogBuffer.w(TAG, "failed to delete " + snap);
            } else {
                LogBuffer.i(TAG, "[" + n + "] sync snapshot cleared; restart to re-bootstrap from checkpoint");
            }
        }, "ethp2p-reset-sync-" + n).start();
    }

    /** Per-network snapshots, one entry per live stack, keyed by network name (chip per entry). */
    public Map<String, Snapshot> snapshots() {
        Map<String, Snapshot> out = new java.util.LinkedHashMap<>();
        for (String n : liveNetworks()) {
            ChainHandle h = handles.get(n);
            if (h != null) out.put(n, snapshotOf(n, h));
        }
        return out;
    }

    /** Back-compat: snapshot of the primary enabled network (null when nothing is live). */
    public Snapshot snapshot() {
        String n = primaryNetwork(this);
        ChainHandle h = handles.get(n);
        return h != null ? snapshotOf(n, h) : null;
    }

    /** Build the UI snapshot for one network from the engine's status surfaces. Tolerates a
     *  stack mid-boot — the engine reads those as zeros / STARTING (mapped to STOPPED here,
     *  the string this UI has always shown pre-beacon). */
    private Snapshot snapshotOf(String network, ChainHandle h) {
        boolean running = RUNNING.get();
        // Uptime is per-ENGINE-START, not per-service-start: stackStartMs is removed when a
        // fresh boot publishes its handle and re-stamped once its start() succeeds (and
        // removed again on per-network teardown), so a network restart — including an
        // engine-toggle reboot — restarts the UI's uptime counter from zero, reading 0s
        // while the new stack is still starting. A service-global stamp would keep
        // counting across chain restarts.
        long chainStartMs = stackStartMs.getOrDefault(network, 0L);
        StatusSnapshot s = h.status();
        BeaconStatus bs = h.beaconStatus();
        // Live counts from the cache FILES (mtime-memoized): the files are the
        // cross-engine truth — the Rust engine writes them directly, so the
        // boot-time cachedElCounts/cachedClCounts maps go stale mid-run.
        CacheFileStats.ElStats elCache = CacheFileStats.el(netCacheFor(network, "peers", ".cache").toPath());
        CacheFileStats.ClStats clCache = CacheFileStats.cl(netCacheFor(network, "cl-peers", ".cache").toPath());
        String beaconState = bs.state() == BeaconState.STARTING ? "STOPPED" : bs.state().name();
        // Catch-up progress: preserve the historical -1-until-known convention (the engine
        // API defaults these to 0 pre-beacon) for the UI's determinate progress bar.
        boolean preBeacon = bs.state() == BeaconState.STARTING;
        long syncCurrent = preBeacon ? -1 : s.syncCurrentPeriod();
        long syncTarget = preBeacon ? -1 : s.syncTargetPeriod();
        String lifecycle = s.lifecycle() != null ? s.lifecycle().name() : "STOPPED";
        if (!running || !s.running()) {
            // Covers both a stopped stack and a PAUSED one (running=false, warm state
            // retained) — the lifecycle string lets the UI tell them apart.
            return new Snapshot(running, lifecycle, chainStartMs, 0, 0, 0, 0, /*snapServing*/0,
                    elCache.total(), elCache.snapOk(), elCache.snapBad(), s.attemptedDials(), s.backedOffPeers(),
                    s.blacklistedPeers(), s.discv5TableSize(), 0,
                    beaconState, bs.bootstrapped(), bs.connectedPeers(), (int) bs.lightClientPeers(),
                    bs.servedPeersLastMinute(), clCache.total(), clCache.proven(), clCache.nolc(),
                    bs.finalizedSlot(), bs.executionBlockNumber(), bs.executionBlockHashHex(),
                    s.syncStartPeriod(), syncCurrent, syncTarget,
                    Long.MAX_VALUE, List.of(), network,
                    s.pauseCount(), s.totalPausedMs(), s.lastPauseEpochMs(),
                    s.lastResumeEpochMs(), s.lastWakeReason(), s.lcHunting());
        }
        return new Snapshot(true, lifecycle, chainStartMs,
                s.discoveredPeers(), s.connectedPeers(), s.readyPeers(),
                s.snapPeers(), s.snapServingPeers(),
                elCache.total(), elCache.snapOk(), elCache.snapBad(), s.attemptedDials(), s.backedOffPeers(),
                s.blacklistedPeers(), s.discv5TableSize(), 0,
                beaconState, bs.bootstrapped(), bs.connectedPeers(), (int) bs.lightClientPeers(),
                bs.servedPeersLastMinute(), clCache.total(), clCache.proven(), clCache.nolc(),
                bs.finalizedSlot(), bs.executionBlockNumber(), bs.executionBlockHashHex(),
                s.syncStartPeriod(), syncCurrent, syncTarget,
                s.verifiedHeadAgeMs(), s.readyPeerList(), network,
                s.pauseCount(), s.totalPausedMs(), s.lastPauseEpochMs(),
                s.lastResumeEpochMs(), s.lastWakeReason(), s.lcHunting());
    }

    // ---- Failure forensics (see ProcessHealthDiag) ----

    /** How often the health line is emitted. Cheap; the info is time-series (you want
     *  the trajectory of memory + sync + snap-peers as it approaches the failure). */
    private static final long HEARTBEAT_INTERVAL_MS = 20_000;
    /** The heartbeat thread for THIS service instance, interrupted in {@link #onDestroy}
     *  so it stops WITH the instance (no NodeService leak) and restarts cleanly on the
     *  next service start. An OOM-kill is a SIGKILL with no onDestroy, so on that path the
     *  thread runs until the kill — the last emitted line is the clue we want. */
    private volatile Thread healthThread;

    /** Rust-engine log pump for THIS service instance — same lifecycle contract
     *  as {@link #healthThread}. Pumps the engine's drainable tracing ring into
     *  {@link LogBuffer} (Logs tab + logcat) every 5 s; before this seam every
     *  Rust-side incident on a phone had to be diagnosed blind. Runs on EVERY
     *  build type (unlike the heartbeat): a 5 s poll of an in-memory ring is
     *  nearly free, and the ring is empty unless the Rust engine is active. */
    private volatile Thread rustLogThread;

    private static final long RUST_LOG_DRAIN_MS = 5_000;
    private static final int RUST_LOG_DRAIN_MAX = 500;

    private void startRustLogPump() {
        if (rustLogThread != null) return;
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String batch = io.myotis.engines.Engines.drainRustLogs(RUST_LOG_DRAIN_MAX);
                    if (!batch.isEmpty()) {
                        for (String line : batch.split("\n")) {
                            // Preserve severity: tracing's fmt layer puts the
                            // level first (time disabled) — "ERROR …"/"WARN …".
                            String trimmed = line.trim();
                            if (trimmed.startsWith("ERROR")) LogBuffer.e("rust", line);
                            else if (trimmed.startsWith("WARN")) LogBuffer.w("rust", line);
                            else LogBuffer.i("rust", line);
                        }
                    }
                } catch (Throwable ignored) {
                    // Observability must never take the process down. But an
                    // interrupt is a cancellation request, not a drain failure —
                    // restore the flag and exit the drain thread promptly.
                    if (ignored instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                // Sleep OUTSIDE the try above: a persistently-throwing drain
                // (e.g. a failed Engines static init) must stay a 5 s poll,
                // never an unthrottled busy loop pinning a core.
                try {
                    Thread.sleep(RUST_LOG_DRAIN_MS);
                } catch (InterruptedException e) {
                    return; // onDestroy interrupted us
                }
            }
        }, "ethp2p-rust-logs");
        t.setDaemon(true);
        rustLogThread = t;
        t.start();
    }

    /**
     * Emit one consolidated health line every {@link #HEARTBEAT_INTERVAL_MS}: process
     * memory, CL sync progress, and EL snap-peer pool state. When the node fails on a
     * phone, the last few of these + the next launch's prior-exit line pin the mode
     * (OOM vs CL-wedge vs snap-never-warm).
     */
    private void startHealthHeartbeat() {
        // Debuggable builds only: the 20s Debug.getMemoryInfo poll is diagnostic
        // overhead a shipping user shouldn't pay. The one-shot prior-exit log and the
        // event-driven onTrimMemory warning stay on in every build (cheap + valuable).
        boolean debuggable = (getApplicationInfo().flags
                & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        if (!debuggable || healthThread != null) return;
        // Monotonic baseline captured here, not read from wall-clock, so an NTP step
        // can't skew the reported uptime.
        final long startNano = System.nanoTime();
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    LogBuffer.i(ProcessHealthDiag.TAG, buildHealthLine(startNano));
                    Thread.sleep(HEARTBEAT_INTERVAL_MS);
                } catch (InterruptedException e) {
                    return; // onDestroy interrupted us
                } catch (Throwable ignored) {
                    // Diagnostics must never take the process down.
                }
            }
        }, "ethp2p-health");
        t.setDaemon(true);
        healthThread = t;
        t.start();
    }

    private String buildHealthLine(long startNano) {
        long upSec = (System.nanoTime() - startNano) / 1_000_000_000L;
        String mem = ProcessHealthDiag.memorySummary(this);
        String cl = "cl: (not running)";
        String el = "";
        try {
            String n = primaryNetwork(this);
            ChainHandle h = handles.get(n);
            if (h != null) {
                StatusSnapshot s = h.status();
                // CL: is catch-up progressing toward the wall-clock period, and how
                // stale is the verified head?
                cl = "cl: period=" + s.syncCurrentPeriod() + "/" + s.wallClockPeriod()
                        + " fin=" + s.finalizedSlot()
                        + " headAge=" + headAge(s.verifiedHeadAgeMs());
                // EL: the snap-peer pool is what gates verified reads. snapServing==0
                // over time = the "snap peers never warm" failure mode.
                el = " | el: conn=" + s.connectedPeers()
                        + " snap=" + s.snapPeers()
                        + " serving=" + s.snapServingPeers()
                        + " backoff=" + s.backedOffPeers()
                        + " blacklist=" + s.blacklistedPeers()
                        + " discv5=" + s.discv5TableSize()
                        + " elBlock=" + s.executionBlockNumber();
            }
        } catch (Throwable t) {
            cl = "cl: (status read failed: " + t.getClass().getSimpleName() + ")";
        }
        return "up=" + upSec + "s | mem: " + mem + " | " + cl + el;
    }

    private static String headAge(long ms) {
        return ms == Long.MAX_VALUE ? "n/a" : (ms / 1000) + "s";
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        // The system sends this under memory pressure; RUNNING_CRITICAL / COMPLETE are
        // the "you're about to be OOM-killed" warning — the last thing logged before a
        // silent SIGKILL. Pair with the next launch's prior-exit=LOW_MEMORY line.
        LogBuffer.w(ProcessHealthDiag.TAG, "onTrimMemory " + ProcessHealthDiag.trimLevelName(level)
                + " | " + ProcessHealthDiag.memorySummary(this));
        // About to be OOM-killed: pause any stack that's been idle even briefly.
        // A pause frees the big consumers (Netty buffers, evm pools, libp2p) while
        // keeping the warm beacon store — far better than dying and cold-starting.
        if (level >= TRIM_MEMORY_RUNNING_CRITICAL && RUNNING.get()) {
            // Emergency pass: bypass the SYNCED-once / charging gates. Freeing the big consumers
            // beats getting OOM-killed and cold-starting, even mid-initial-sync or while charging.
            idleTick(60_000L, false);
        }
    }

    @Override
    public void onDestroy() {
        LogBuffer.i(TAG, "Stopping node (onDestroy)");
        // Stop the heartbeat with the instance so it doesn't leak this NodeService and
        // restarts cleanly on the next start.
        Thread hb = healthThread;
        if (hb != null) {
            hb.interrupt();
            healthThread = null;
        }
        Thread rl = rustLogThread;
        if (rl != null) {
            rl.interrupt();
            rustLogThread = null;
        }
        stopIdleTicker();
        // Same fire-and-forget pattern as shutdown(): the system gives us a
        // brief window to return from onDestroy and we don't want to spend
        // it blocking on libp2p host shutdown / Netty graceful drain. doShutdown()
        // tears every stack down under each network's bootLock, so a subsequent
        // service start can't race with a half-finished close.
        RUNNING.set(false);
        unregisterNotifNetworkCallback();
        new Thread(this::doShutdown, "ethp2p-shutdown").start();
        super.onDestroy();
    }

    private Notification buildNotification(String title, String text) {
        // Guard the channel creation like updateNotification() treats the manager as nullable —
        // this also runs on the startForeground() path, which isn't wrapped in try/catch, so a
        // (practically impossible) null manager must not NPE the service start.
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "ethp2p node",
                    NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(channel);
        }
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setOngoing(true)
                .build();
    }
}
