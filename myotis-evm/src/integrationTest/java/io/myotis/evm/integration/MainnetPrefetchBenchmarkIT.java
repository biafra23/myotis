package io.myotis.evm.integration;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.EvmExecutor;
import io.myotis.evm.PrefetchingEvmExecutor;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;
import io.myotis.evm.prefetch.ConvergenceTracker;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapBackedStateOracle;
import io.myotis.evm.world.SnapPeer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 2 benchmark — measures convergence iterations and end-to-end latency
 * for the corpus listed in the original plan, with results going into
 * {@code docs/prefetch-benchmarks.md} for review.
 *
 * <p>Acceptance criteria the benchmark validates:
 * <ul>
 *   <li>All cases converge in ≤ 3 iterations.
 *   <li>p95 latency under 2 s on simulated good network conditions.
 * </ul>
 *
 * <p>Same env-gating as {@link MainnetCallViewIT}: tests run only when
 * {@code MYOTIS_MAINNET=1} and the supporting peer / state-root env vars
 * are set. The benchmark depends on the same {@code connectToMainnetPeer()}
 * helper that {@code MainnetCallViewIT} does — currently a stub awaiting
 * a reusable {@code EthHandler} bootstrap factored out of {@code :app:Main}.
 *
 * <p>Methodology per call type:
 * <ol>
 *   <li>Warm-up call: 1 iteration discarded (loads bytecode into the
 *       process-local cache so the timed runs measure prefetch behavior,
 *       not first-touch I/O).
 *   <li>{@code N} timed iterations (default 10): record wall-clock
 *       latency per call and the convergence iteration count for that
 *       call.
 *   <li>Print min/p50/p95/max latency and the iteration histogram.
 *   <li>Assert convergence ≤ 3 and p95 ≤ 2 s.
 * </ol>
 *
 * <p>Two execution modes are compared per call to make the prefetch win
 * visible: {@code DefaultEvmExecutor} alone (Phase 1 baseline) and
 * {@code PrefetchingEvmExecutor} (Phase 2). Numbers go in the markdown
 * table in {@code docs/prefetch-benchmarks.md}.
 */
@EnabledIfEnvironmentVariable(named = "MYOTIS_MAINNET", matches = "1")
class MainnetPrefetchBenchmarkIT {

    private static final int TIMED_ITERATIONS = 10;
    private static final int WARMUP_ITERATIONS = 1;

    private static final Address USDC = Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    private static final Address DAI  = Address.fromHex("0x6B175474E89094C44Da98b954EedeAC495271d0F");
    private static final Address ENS_PUBLIC_RESOLVER =
            Address.fromHex("0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");
    private static final Address VITALIK =
            Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    @Test
    void usdcBalanceOfBenchmark() throws Exception {
        runBenchmark("USDC.balanceOf(vitalik)", USDC, balanceOfCalldata(VITALIK));
    }

    @Test
    void daiBalanceOfBenchmark() throws Exception {
        runBenchmark("DAI.balanceOf(vitalik)", DAI, balanceOfCalldata(VITALIK));
    }

    @Test
    void ensResolverAddrBenchmark() throws Exception {
        byte[] node = Namehash.of("vitalik.eth");
        FunctionSignature addr = FunctionSignature.of("addr(bytes32)");
        byte[] calldata = AbiEncoder.encodeCall(addr, AbiEncoder.bytes32(node));
        runBenchmark("ENS.addr(vitalik.eth)", ENS_PUBLIC_RESOLVER, calldata);
    }

    /**
     * Run the timed loop for one call, printing the result so it can be
     * pasted into the markdown table.
     */
    private void runBenchmark(String label, Address target, byte[] calldata) throws Exception {
        var peer = connectToMainnetPeer();
        var ctx = mainnetBlockContext();

        var convergenceTracker = new ConvergenceTracker();
        var inner = new DefaultEvmExecutor(
                new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()),
                BytecodeCache.inMemory(),
                java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "myotis-evm-bench");
                    t.setDaemon(true);
                    return t;
                }));
        var prefetched = new PrefetchingEvmExecutor(inner,
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, convergenceTracker);

        // Warm-up runs (untimed)
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            prefetched.callView(target, calldata, ctx).get(60, TimeUnit.SECONDS);
        }

        // Baseline: DefaultEvmExecutor (no prefetch)
        long[] baselineNs = timeRuns(inner, target, calldata, ctx);
        // Phase 2: with prefetch
        long[] prefetchNs = timeRuns(prefetched, target, calldata, ctx);

        var iterCounts = convergenceTracker.snapshot();

        Stats baselineStats = Stats.of(baselineNs);
        Stats prefetchStats = Stats.of(prefetchNs);

        System.out.printf(
                "[bench] %-32s | baseline p50=%,9d µs p95=%,9d µs | prefetch p50=%,9d µs p95=%,9d µs | "
                        + "iterations(min/max)=%d/%d%n",
                label,
                baselineStats.p50 / 1000, baselineStats.p95 / 1000,
                prefetchStats.p50 / 1000, prefetchStats.p95 / 1000,
                iterCounts.stream().mapToInt(Integer::intValue).min().orElse(0),
                iterCounts.stream().mapToInt(Integer::intValue).max().orElse(0));

        assertTrue(convergenceTracker.max() <= 3,
                label + " converged in more than 3 iterations: max=" + convergenceTracker.max());
        long p95Ms = prefetchStats.p95 / 1_000_000;
        assertTrue(p95Ms <= 2000,
                label + " p95 latency " + p95Ms + " ms exceeds 2 s acceptance criterion");
    }

    private long[] timeRuns(EvmExecutor exec, Address target, byte[] calldata, BlockContext ctx)
            throws Exception {
        long[] ns = new long[TIMED_ITERATIONS];
        for (int i = 0; i < TIMED_ITERATIONS; i++) {
            long start = System.nanoTime();
            exec.callView(target, calldata, ctx).get(60, TimeUnit.SECONDS);
            ns[i] = System.nanoTime() - start;
        }
        return ns;
    }

    private static SnapPeer connectToMainnetPeer() {
        String enode = System.getenv("MYOTIS_INTEGRATION_PEER_ENODE");
        assertNotNull(enode,
                "MYOTIS_INTEGRATION_PEER_ENODE must be set; see MainnetCallViewIT Javadoc");
        // TODO(phase1.commit5+): same bootstrap helper as MainnetCallViewIT.
        // Both ITs share the gap; both light up at once when the helper lands.
        throw new UnsupportedOperationException(
                "EthHandler bootstrap from a test is not yet implemented; "
                        + "see TODO in MainnetCallViewIT.connectToMainnetPeer.");
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
        assertNotNull(v, name + " must be set");
        return v;
    }

    private static byte[] parseHex32(String hex) {
        String s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        return HexFormat.of().parseHex(s);
    }

    private static byte[] balanceOfCalldata(Address holder) {
        return AbiEncoder.encodeCall(
                FunctionSignature.of("balanceOf(address)"),
                AbiEncoder.address(holder));
    }

    /** Quick latency stats. */
    private record Stats(long p50, long p95, long min, long max) {
        static Stats of(long[] ns) {
            long[] sorted = Arrays.copyOf(ns, ns.length);
            Arrays.sort(sorted);
            return new Stats(
                    sorted[sorted.length / 2],
                    sorted[(int) Math.ceil(sorted.length * 0.95) - 1],
                    sorted[0],
                    sorted[sorted.length - 1]);
        }
    }
}
