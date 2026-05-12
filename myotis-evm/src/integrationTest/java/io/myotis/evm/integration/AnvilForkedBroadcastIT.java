package io.myotis.evm.integration;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.UnsignedTransaction;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapBackedStateOracle;
import io.myotis.evm.world.SnapPeer;
import com.jaeckel.ethp2p.app.testing.MainnetPeerBootstrap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Phase 5 headline acceptance test, per
 * {@code docs/phase5-design.md}:
 *
 * <blockquote>
 *   "An end-to-end IT demonstrates that an [Uniswap-swap-style]
 *    transaction built with a locally-estimated gas limit executes
 *    successfully without out-of-gas when broadcast (against a
 *    forked-mainnet Anvil)."
 * </blockquote>
 *
 * <p>This is the unique acceptance signal beyond
 * {@link MainnetGasEstimationIT}: that IT asserts the local estimate
 * is within 5% of {@code eth_estimateGas}, which catches under- and
 * over-estimation alike. This IT instead asserts that <em>broadcasting
 * with the local estimate as the gas limit actually succeeds without
 * OOG</em> — the property the 15% safety buffer specifically exists
 * to guarantee, and that the 5%-of-reference assertion alone cannot
 * prove (a 5%-low estimate would pass the cross-check but OOG live).
 *
 * <h2>Operator setup</h2>
 *
 * <p>Anvil must be forking mainnet at the same block as the
 * {@link MainnetCallViewIT} env contract, with auto-impersonation on
 * so we can send transactions as a known mainnet holder without
 * signing:
 *
 * <pre>{@code
 *   anvil --fork-url <mainnet-rpc> \
 *         --fork-block-number $MYOTIS_INTEGRATION_BLOCK_NUMBER \
 *         --auto-impersonate &
 * }</pre>
 *
 * <p>Then set the JSON-RPC URL alongside the standard mainnet IT env
 * (peer + block context):
 *
 * <pre>{@code
 *   export MYOTIS_INTEGRATION_ANVIL_URL=http://127.0.0.1:8545
 * }</pre>
 *
 * <p>The test is gated on {@code MYOTIS_INTEGRATION_ANVIL_URL} being
 * set; without it, JUnit skips the case rather than failing.
 *
 * <h2>Why not sign locally?</h2>
 *
 * <p>We don't have the holder's private key — that's the entire
 * point of running against a fork rather than mainnet. Anvil's
 * {@code anvil_impersonateAccount} cheatcode lets us submit
 * transactions as if they came from any address. The receipt then
 * reflects the real on-chain gas cost the wallet would pay if it had
 * signed and broadcast on live mainnet.
 */
@EnabledIfEnvironmentVariable(named = "MYOTIS_MAINNET", matches = "1")
class AnvilForkedBroadcastIT {

    private static volatile MainnetPeerBootstrap.Session session;
    private static final Object SESSION_LOCK = new Object();

    /**
     * One executor shared across the test methods in this class, shut
     * down in {@link #closePeerSession()}. Previously this was a fresh
     * {@code newSingleThreadExecutor} per {@code mainnetExecutor()} call
     * — daemon threads kept the JVM exit-clean, but each call still
     * leaked an {@code ExecutorService} (worker thread + queue).
     */
    private static final java.util.concurrent.ExecutorService EVM_POOL =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "myotis-evm-anvil-it");
                t.setDaemon(true);
                return t;
            });

    private static final Address VITALIK = Address.fromHex(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    private static final Address USDC = Address.fromHex(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

    /**
     * Estimate {@code USDC.transfer(recipient, 1_000_000)} locally
     * (against real mainnet state via SNAP), then broadcast the
     * transaction against Anvil with exactly the estimated gas as the
     * limit. Asserts:
     *
     * <ul>
     *   <li>The receipt {@code status} is 1 (success — no revert, no OOG).
     *   <li>{@code gasUsed <= localEstimate} — the buffer was sufficient.
     * </ul>
     *
     * <p>If either fails, the 15% safety buffer is too tight for this
     * shape of transaction; revisit the buffer constant before shipping.
     */
    @Test
    void usdcTransferEstimateActuallyExecutesWithoutOog() throws Exception {
        String anvilUrl = System.getenv("MYOTIS_INTEGRATION_ANVIL_URL");
        assumeTrue(anvilUrl != null && !anvilUrl.isBlank(),
                "MYOTIS_INTEGRATION_ANVIL_URL not set — skipping Anvil broadcast acceptance test");

        // 1. Local estimate against real mainnet state.
        EvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        FunctionSignature transfer = FunctionSignature.of("transfer(address,uint256)");
        Address recipient = Address.fromHex("0x1111111111111111111111111111111111111111");
        byte[] calldata = AbiEncoder.encodeCall(transfer,
                AbiEncoder.address(recipient),
                AbiEncoder.uint256(1_000_000L));

        var tx = new UnsignedTransaction(VITALIK, USDC, BigInteger.ZERO, calldata, null);
        long localEstimate = executor.estimateGas(tx, ctx).get(60, TimeUnit.SECONDS);
        System.out.printf("[anvil-it] local estimate for USDC.transfer: %d%n", localEstimate);

        // 2. Broadcast against Anvil, asking it to impersonate VITALIK so
        //    the transfer can succeed against forked state (VITALIK holds
        //    USDC on mainnet at any recent block).
        AnvilRpcClient anvil = new AnvilRpcClient(URI.create(anvilUrl));
        anvil.call("anvil_impersonateAccount", "[\"" + VITALIK + "\"]");

        String txHash = anvil.sendTransaction(VITALIK, USDC, calldata, localEstimate);
        System.out.printf("[anvil-it] broadcast hash: %s%n", txHash);

        Receipt receipt = anvil.waitForReceipt(txHash, Duration.ofSeconds(30));

        // 3. Acceptance checks.
        assertTrue(receipt.status == 1,
                "Anvil broadcast reverted (status=0). " +
                        "gasUsed=" + receipt.gasUsed + " of localEstimate=" + localEstimate +
                        ". If gasUsed == localEstimate, the EVM ran out of gas and the buffer is too tight.");
        assertTrue(receipt.gasUsed <= localEstimate,
                "gasUsed " + receipt.gasUsed + " exceeded localEstimate " + localEstimate +
                        " — the 15% safety buffer is insufficient for this tx shape.");
        System.out.printf("[anvil-it] PASS: gasUsed=%d, localEstimate=%d, slack=%d%n",
                receipt.gasUsed, localEstimate, localEstimate - receipt.gasUsed);
    }

    // ---- Wiring shared with MainnetGasEstimationIT --------------------------

    private static EvmExecutor mainnetExecutor() {
        SnapPeer peer = connectToMainnetPeer();
        return new DefaultEvmExecutor(
                new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()),
                BytecodeCache.inMemory(),
                EVM_POOL);
    }

    private static SnapPeer connectToMainnetPeer() {
        if (session == null) {
            synchronized (SESSION_LOCK) {
                if (session == null) {
                    String enode = System.getenv("MYOTIS_INTEGRATION_PEER_ENODE");
                    assertNotNull(enode,
                            "MYOTIS_INTEGRATION_PEER_ENODE must be set; "
                                    + "see MainnetCallViewIT Javadoc");
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
        EVM_POOL.shutdownNow();
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

    // ---- Receipt struct ----------------------------------------------------

    /** The two receipt fields the acceptance test cares about. */
    private record Receipt(long status, long gasUsed) {}

    // ---- Minimal JSON-RPC client -------------------------------------------

    /**
     * The narrowest possible JSON-RPC client over {@link HttpClient} —
     * just enough to drive Anvil for this one test. Hand-rolled string
     * parsing in the same spirit as {@code app.DaemonClient} (no
     * external JSON library); the response shape is well-known and
     * stable so an extracted regex per field is fine here.
     */
    private static final class AnvilRpcClient {
        /**
         * JSON-RPC error responses always shape as {@code "error":{code,message,...}}.
         * Match the start of that object — discriminates between a real error and
         * a literal {@code "error"} substring that could in principle appear
         * inside a result payload. {@code \\s*} tolerates pretty-printed responses.
         */
        private static final Pattern ERROR_OBJECT =
                Pattern.compile("\"error\"\\s*:\\s*\\{");
        /** Whitespace-tolerant {@code "result":null}. */
        private static final Pattern NULL_RESULT =
                Pattern.compile("\"result\"\\s*:\\s*null");

        private final URI endpoint;
        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        private final AtomicLong nextId = new AtomicLong(1);

        AnvilRpcClient(URI endpoint) {
            this.endpoint = endpoint;
        }

        /** Generic call. {@code paramsJson} is a JSON array string. */
        String call(String method, String paramsJson) throws IOException, InterruptedException {
            long id = nextId.getAndIncrement();
            String body = "{\"jsonrpc\":\"2.0\",\"id\":" + id
                    + ",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
            HttpRequest req = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IOException("Anvil RPC " + method + " HTTP " + resp.statusCode()
                        + ": " + resp.body());
            }
            String s = resp.body();
            if (ERROR_OBJECT.matcher(s).find()) {
                throw new IOException("Anvil RPC " + method + " error: " + s);
            }
            return s;
        }

        /**
         * {@code eth_sendTransaction} with an impersonated {@code from}.
         * Returns the transaction hash. The gas limit is set explicitly
         * to {@code gasLimit} — that's the property under test.
         */
        String sendTransaction(Address from, Address to, byte[] data, long gasLimit)
                throws IOException, InterruptedException {
            String params = "[{"
                    + "\"from\":\"" + from + "\","
                    + "\"to\":\"" + to + "\","
                    + "\"data\":\"0x" + HexFormat.of().formatHex(data) + "\","
                    + "\"gas\":\"0x" + Long.toHexString(gasLimit) + "\""
                    + "}]";
            String resp = call("eth_sendTransaction", params);
            return extractJsonString(resp, "result");
        }

        /**
         * Poll {@code eth_getTransactionReceipt} until it's non-null or
         * the deadline elapses. Anvil typically mines instantly so this
         * returns within a single poll, but the loop guards against
         * configurations with mining delays.
         */
        Receipt waitForReceipt(String txHash, Duration timeout)
                throws IOException, InterruptedException {
            long deadlineNanos = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadlineNanos) {
                String resp = call("eth_getTransactionReceipt", "[\"" + txHash + "\"]");
                if (!NULL_RESULT.matcher(resp).find()) {
                    long status = parseHexLong(extractJsonString(resp, "status"));
                    long gasUsed = parseHexLong(extractJsonString(resp, "gasUsed"));
                    return new Receipt(status, gasUsed);
                }
                Thread.sleep(200);
            }
            fail("Anvil did not mine " + txHash + " within " + timeout);
            throw new AssertionError("unreachable");
        }

        /**
         * Extract a string-typed JSON field value. Whitespace-tolerant
         * (pretty-printed responses) and handles standard JSON string
         * escapes inside the value via {@code [^"\\\\]|\\\\.} —
         * indispensable if the field's value happens to contain a
         * quoted character.
         */
        private static String extractJsonString(String json, String field) {
            Pattern p = Pattern.compile(
                    "\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            Matcher m = p.matcher(json);
            if (!m.find()) {
                throw new IllegalStateException(
                        "field '" + field + "' not in JSON (or not a string): " + json);
            }
            return m.group(1);
        }

        private static long parseHexLong(String hex) {
            String s = hex.startsWith("0x") ? hex.substring(2) : hex;
            return s.isEmpty() ? 0 : Long.parseLong(s, 16);
        }
    }
}
