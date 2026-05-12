package io.myotis.ens.integration;

import io.myotis.ens.EnsResolver;
import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.CcipReadEvmExecutor;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.PrefetchingEvmExecutor;
import io.myotis.evm.ccipread.CcipGateway;
import io.myotis.evm.ccipread.CcipReadHandler;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapBackedStateOracle;
import io.myotis.evm.world.SnapPeer;
import com.jaeckel.ethp2p.app.testing.MainnetPeerBootstrap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 3 acceptance test: forward and reverse ENS resolution against
 * mainnet. The corpus is the ~10-name curated set the original plan calls
 * out — well-known classic on-chain names, no CCIP-Read.
 *
 * <p>Same env-gating as {@code MainnetCallViewIT} / {@code MainnetPrefetchBenchmarkIT}:
 * <ul>
 *   <li>{@code MYOTIS_MAINNET=1}
 *   <li>{@code MYOTIS_INTEGRATION_PEER_ENODE} — snap/1 peer
 *   <li>{@code MYOTIS_INTEGRATION_STATE_ROOT} — recent verified state root
 *   <li>{@code MYOTIS_INTEGRATION_BLOCK_NUMBER}, {@code _BLOCK_TIMESTAMP},
 *       {@code _BASE_FEE_WEI}
 * </ul>
 *
 * <p>Same {@code connectToMainnetPeer()} stub as the Phase 1/2 ITs — all
 * three light up when the {@code :app:Main} bootstrap helper is extracted.
 */
@EnabledIfEnvironmentVariable(named = "MYOTIS_MAINNET", matches = "1")
class MainnetEnsResolutionIT {

    private static volatile MainnetPeerBootstrap.Session session;
    private static final Object SESSION_LOCK = new Object();

    /**
     * Curated corpus of classic on-chain names. Each entry is
     * {@code (ens-name → expected-address)}. Picked from names that are
     * publicly documented and don't (currently) use CCIP-Read.
     */
    private static final Map<String, Address> FORWARD_CORPUS = Map.of(
            "vitalik.eth",     Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            "nick.eth",        Address.fromHex("0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5"),
            "ens.eth",         Address.fromHex("0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"),
            "brantly.eth",     Address.fromHex("0x983110309620D911731Ac0932219af06091b6744"),
            "rainbow.eth",     Address.fromHex("0xB39E1f7C18BB4D119DB60c5bC4D34dca7DDE0B41"),
            "alisha.eth",      Address.fromHex("0x6dfdfb43E91A6BcB95dCb8e95df42b80E7E5Ec5C"),
            "khori.eth",       Address.fromHex("0xe4F0d8C84e4Da9Eb37b06aA7E33b1cdaaCbA80F8"),
            "luc.eth",         Address.fromHex("0x9D2454c64a17f6Db5e1Ac0eDb6593D5DA52F6d12"),
            "noun.eth",        Address.fromHex("0xc8eAfa6E51c0C68A26d44a26F95B12F58c0B66f0"),
            "ricmoo.eth",      Address.fromHex("0xb3eC2BB47CD37c8e6Bd72ee2D60fE5fEcC5e5121"));

    @Test
    void forwardResolutionForCorpus() throws Exception {
        EnsResolver resolver = mainnetResolver();
        BlockContext ctx = mainnetBlockContext();

        for (Map.Entry<String, Address> entry : FORWARD_CORPUS.entrySet()) {
            Optional<Address> resolved = resolver.resolveAddress(entry.getKey(), ctx)
                    .get(120, TimeUnit.SECONDS);
            assertEquals(Optional.of(entry.getValue()), resolved,
                    "forward resolution mismatch for " + entry.getKey());
        }
    }

    @Test
    void reverseResolutionForVitalik() throws Exception {
        EnsResolver resolver = mainnetResolver();
        BlockContext ctx = mainnetBlockContext();

        Address vitalik = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        Optional<String> name = resolver.resolveName(vitalik, ctx)
                .get(120, TimeUnit.SECONDS);
        assertTrue(name.isPresent(),
                "vitalik's reverse record should resolve");
        assertEquals("vitalik.eth", name.get());
    }

    /**
     * CCIP-Read corpus: names whose resolvers delegate to off-chain
     * gateways via ERC-3668. These work only when the executor is
     * wrapped in {@link CcipReadEvmExecutor} and a working
     * {@link CcipGateway} is plumbed in.
     *
     * <p>Specific addresses aren't pinned because gateway-served records
     * can change without an on-chain transaction. The smoke test just
     * verifies the names resolve to <em>some</em> non-empty address
     * within the timeout.
     */
    private static final List<String> CCIP_READ_CORPUS = List.of(
            // Coinbase IDs (resolver delegates to a Coinbase gateway).
            "ens.cb.id",
            // Uniswap names (resolver uses Uniswap's CCIP-Read gateway).
            "ens.uni.eth",
            // Base subnames (resolver uses Base's gateway).
            "ens.base.eth");

    @Test
    void ccipReadNamesResolve() throws Exception {
        EnsResolver resolver = mainnetResolver();
        BlockContext ctx = mainnetBlockContext();

        for (String name : CCIP_READ_CORPUS) {
            Optional<Address> resolved = resolver.resolveAddress(name, ctx)
                    .get(120, TimeUnit.SECONDS);
            assertTrue(resolved.isPresent(),
                    "CCIP-Read resolution returned empty for " + name
                            + " — gateway may have rotated, name unregistered, "
                            + "or CCIP-Read flow is broken");
            System.out.printf("[ens-it] %-24s -> %s%n", name, resolved.get().toHex());
        }
    }

    @Test
    void absentNameReturnsEmpty() throws Exception {
        EnsResolver resolver = mainnetResolver();
        BlockContext ctx = mainnetBlockContext();

        // A made-up name that almost certainly isn't registered.
        String bogus = "this-name-should-not-exist-" + System.nanoTime() + ".eth";
        Optional<Address> resolved = resolver.resolveAddress(bogus, ctx)
                .get(120, TimeUnit.SECONDS);
        assertTrue(resolved.isEmpty(),
                "unregistered name should resolve to empty");
    }

    // ---- Wiring ------------------------------------------------------------

    private static EnsResolver mainnetResolver() {
        SnapPeer peer = connectToMainnetPeer();
        var inner = new DefaultEvmExecutor(
                new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()),
                BytecodeCache.inMemory(),
                java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "myotis-ens-it");
                    t.setDaemon(true);
                    return t;
                }));
        // Stack: prefetch on the inside, CCIP-Read on the outside. Order
        // matters — CCIP-Read needs to observe OffchainLookup reverts at
        // the call boundary, which only the outer wrapper sees.
        var prefetched = new PrefetchingEvmExecutor(inner);
        var ccipReady = new CcipReadEvmExecutor(prefetched,
                new CcipReadHandler(new JavaHttpCcipGateway()));
        return new EnsResolver(ccipReady);
    }

    /**
     * IT-only {@link CcipGateway} backed by {@code java.net.http.HttpClient}.
     * The wallet's Android-side implementation will use Ktor per
     * {@code CLAUDE.md}'s platform direction; this one is fine for the
     * JVM integration test which only runs on developer/CI machines, not
     * on Android.
     */
    private static final class JavaHttpCcipGateway implements CcipGateway {
        private final HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        @Override
        public CompletableFuture<String> request(Method method, String url, String body) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/json");
            HttpRequest request = (method == Method.POST)
                    ? builder.header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    body == null ? "" : body, StandardCharsets.UTF_8))
                            .build()
                    : builder.GET().build();
            return client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenApply(response -> {
                        if (response.statusCode() / 100 != 2) {
                            throw new RuntimeException("gateway " + url
                                    + " returned status " + response.statusCode());
                        }
                        return response.body();
                    });
        }
    }

    private static SnapPeer connectToMainnetPeer() {
        if (session == null) {
            synchronized (SESSION_LOCK) {
                if (session == null) {
                    String enode = System.getenv("MYOTIS_INTEGRATION_PEER_ENODE");
                    assertNotNull(enode,
                            "MYOTIS_INTEGRATION_PEER_ENODE must be set; "
                                    + "see MainnetCallViewIT (in :myotis-evm) Javadoc for the contract");
                    try {
                        session = MainnetPeerBootstrap.dial(enode, Duration.ofSeconds(30));
                    } catch (Exception e) {
                        throw new RuntimeException(
                                "Failed to bootstrap mainnet peer: " + e.getMessage(), e);
                    }
                }
            }
        }
        return session.peer();
    }

    @AfterAll
    static void closePeerSession() {
        synchronized (SESSION_LOCK) {
            if (session != null) {
                session.close();
                session = null;
            }
        }
    }

    private static BlockContext mainnetBlockContext() {
        byte[] stateRoot = parseHex32(env("MYOTIS_INTEGRATION_STATE_ROOT"));
        long blockNumber = Long.parseLong(env("MYOTIS_INTEGRATION_BLOCK_NUMBER"));
        long timestamp = Long.parseLong(env("MYOTIS_INTEGRATION_BLOCK_TIMESTAMP"));
        BigInteger baseFee = new BigInteger(env("MYOTIS_INTEGRATION_BASE_FEE_WEI"));
        return new BlockContext(stateRoot, blockNumber, timestamp, baseFee,
                Address.ZERO, new byte[32], BigInteger.ONE, 30_000_000L);
    }

    private static String env(String name) {
        String v = System.getenv(name);
        assertNotNull(v, name + " must be set; see class Javadoc");
        return v;
    }

    private static byte[] parseHex32(String hex) {
        String s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if (s.length() != 64) {
            throw new IllegalArgumentException(
                    "expected 32-byte hex (64 chars), got " + s.length() + ": " + hex);
        }
        return HexFormat.of().parseHex(s);
    }
}
