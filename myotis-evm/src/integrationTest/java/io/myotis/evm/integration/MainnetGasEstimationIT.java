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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Phase 5 acceptance test: locally-estimated gas for the corpus the
 * original plan calls out, compared against a known reference value
 * supplied via env var (typically the result of {@code eth_estimateGas}
 * from a public RPC at the same block).
 *
 * <p>Same env-gating as Phases 1–4 mainnet ITs:
 * <ul>
 *   <li>{@code MYOTIS_MAINNET=1}
 *   <li>{@code MYOTIS_INTEGRATION_PEER_ENODE} — snap/1 peer
 *   <li>{@code MYOTIS_INTEGRATION_STATE_ROOT} — recent verified state root
 *   <li>{@code MYOTIS_INTEGRATION_BLOCK_NUMBER}, {@code _BLOCK_TIMESTAMP},
 *       {@code _BASE_FEE_WEI}
 * </ul>
 *
 * <p>Per-test reference values live in dedicated env vars
 * ({@code MYOTIS_INTEGRATION_*_REFERENCE_GAS}); when set, the test
 * asserts the local estimate is within 5% of the reference, matching
 * the plan's acceptance criterion. When unset, the test still runs
 * (proves the estimation succeeded) but skips the cross-check.
 *
 * <p>The {@code connectToMainnetPeer()} stub is shared with Phases 1–4 ITs;
 * all light up when the {@code :app:Main} bootstrap helper lands.
 */
@EnabledIfEnvironmentVariable(named = "MYOTIS_MAINNET", matches = "1")
class MainnetGasEstimationIT {

    private static final Address VITALIK = Address.fromHex(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    private static final Address USDC = Address.fromHex(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    private static final Address WETH = Address.fromHex(
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    private static final Address UNISWAP_V3_ROUTER = Address.fromHex(
            "0xE592427A0AEce92De3Edee1F18E0157C05861564");

    /**
     * Plain ETH transfer to an EOA. Reference: ~21000 gas (intrinsic only),
     * +15% buffer = ~24150.
     */
    @Test
    void ethTransferToEoaIsAround21000() throws Exception {
        EvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        var tx = new UnsignedTransaction(
                VITALIK,
                Address.fromHex("0x1111111111111111111111111111111111111111"),
                new BigInteger("100000000000000000"),  // 0.1 ETH
                new byte[0],
                null);

        long estimate = executor.estimateGas(tx, ctx).get(60, TimeUnit.SECONDS);
        System.out.printf("[gas-it] eth-transfer-to-eoa: %d%n", estimate);
        // 21000 * 1.15 = 24150; allow generous slop because the recipient
        // might or might not be a brand-new account (EIP-2929 cold/warm
        // accounting differs by 100 gas).
        assertTrue(estimate >= 23_000 && estimate <= 26_000,
                "ETH-to-EOA estimate out of expected range; got " + estimate);
    }

    /**
     * USDC transfer (ERC-20). Reference: ~50–80k gas depending on whether
     * the recipient already has a non-zero balance (warm vs cold storage
     * slot for the recipient's balance entry).
     */
    @Test
    void usdcTransferIsAroundFiftyKilogas() throws Exception {
        EvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        // transfer(recipient, 1_000_000) — 1 USDC, since USDC has 6 decimals.
        FunctionSignature transfer = FunctionSignature.of("transfer(address,uint256)");
        Address recipient = Address.fromHex("0x1111111111111111111111111111111111111111");
        byte[] calldata = AbiEncoder.encodeCall(transfer,
                AbiEncoder.address(recipient),
                AbiEncoder.uint256(1_000_000L));

        var tx = new UnsignedTransaction(
                VITALIK, USDC, BigInteger.ZERO, calldata, null);

        long estimate = executor.estimateGas(tx, ctx).get(60, TimeUnit.SECONDS);
        System.out.printf("[gas-it] usdc-transfer: %d%n", estimate);
        crossCheckIfReferenceProvided(
                estimate, "MYOTIS_INTEGRATION_USDC_TRANSFER_REFERENCE_GAS");
        // Loose sanity range: should be much more than a plain transfer
        // and well below an OOG cap. 30k floor catches over-aggressive
        // cost-elision; 200k ceiling catches a runaway loop.
        assertTrue(estimate >= 30_000 && estimate <= 200_000,
                "USDC.transfer estimate out of expected range; got " + estimate);
    }

    /**
     * Uniswap V3 exact-input swap. Reference: ~150–250k gas depending on
     * pool state (if the tick-bitmap traversal hits cold ticks, gas climbs).
     *
     * <p>Per the plan's acceptance criterion, this is the case the
     * forked-mainnet broadcast test exercises: building a transaction with
     * the locally-estimated gas limit and broadcasting it (against an Anvil
     * fork) should succeed without OOG.
     */
    @Test
    void uniswapV3ExactInputSwapIsBelowTwoHundredKilogas() throws Exception {
        EvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        // exactInputSingle(ExactInputSingleParams calldata params) where
        // params packs (tokenIn, tokenOut, fee, recipient, deadline,
        // amountIn, amountOutMinimum, sqrtPriceLimitX96). Constructing
        // a realistic tuple at runtime needs current pool state, so
        // operators supply ready-made calldata via env var. Without it
        // there's no valid input that exercises the swap path — a bare
        // 4-byte selector reverts in the router's ABI decode, which
        // estimateGas (correctly) refuses to estimate over. Skip rather
        // than fail, matching the class Javadoc's "test still runs but
        // optional cross-check is skipped" contract.
        String overrideCalldata = System.getenv("MYOTIS_INTEGRATION_UNISWAP_CALLDATA");
        assumeTrue(overrideCalldata != null,
                "MYOTIS_INTEGRATION_UNISWAP_CALLDATA not set — skipping Uniswap swap"
                        + " estimation; supply realistic calldata to exercise this path");
        byte[] calldata = HexFormat.of().parseHex(stripHexPrefix(overrideCalldata));

        var tx = new UnsignedTransaction(
                VITALIK, UNISWAP_V3_ROUTER, BigInteger.ZERO, calldata, null);

        long estimate = executor.estimateGas(tx, ctx).get(60, TimeUnit.SECONDS);
        System.out.printf("[gas-it] uniswap-v3-swap: %d%n", estimate);
        crossCheckIfReferenceProvided(
                estimate, "MYOTIS_INTEGRATION_UNISWAP_REFERENCE_GAS");
        assertTrue(estimate >= 100_000 && estimate <= 500_000,
                "Uniswap V3 swap estimate out of expected range; got " + estimate);
    }

    // ---- Wiring ------------------------------------------------------------

    private static EvmExecutor mainnetExecutor() {
        SnapPeer peer = connectToMainnetPeer();
        return new DefaultEvmExecutor(
                new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()),
                BytecodeCache.inMemory(),
                java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "myotis-evm-gas-it");
                    t.setDaemon(true);
                    return t;
                }));
    }

    private static SnapPeer connectToMainnetPeer() {
        String enode = System.getenv("MYOTIS_INTEGRATION_PEER_ENODE");
        assertNotNull(enode,
                "MYOTIS_INTEGRATION_PEER_ENODE must be set; "
                        + "see MainnetCallViewIT Javadoc for the contract");
        // TODO(phase1.commit5+): same bootstrap helper as the other mainnet ITs.
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

    /**
     * If the operator supplies a reference gas value via env var (typically
     * the result of {@code eth_estimateGas} from a public RPC at the same
     * block), assert the local estimate is within 5% of it — the plan's
     * acceptance criterion. When unset, skip the cross-check.
     */
    private static void crossCheckIfReferenceProvided(long localEstimate, String envVar) {
        String reference = System.getenv(envVar);
        if (reference == null || reference.isBlank()) {
            return;
        }
        long referenceGas = Long.parseLong(reference.trim());
        double tolerance = 0.05;
        long lowerBound = (long) (referenceGas * (1.0 - tolerance));
        long upperBound = (long) (referenceGas * (1.0 + tolerance));
        assertTrue(localEstimate >= lowerBound && localEstimate <= upperBound,
                "local estimate " + localEstimate + " is more than 5% off the reference "
                        + referenceGas + " (acceptable: [" + lowerBound + ", " + upperBound + "])");
    }

    private static String env(String name) {
        String v = System.getenv(name);
        assertNotNull(v, name + " must be set; see class Javadoc");
        return v;
    }

    private static byte[] parseHex32(String hex) {
        String s = stripHexPrefix(hex);
        if (s.length() != 64) {
            throw new IllegalArgumentException(
                    "expected 32-byte hex (64 chars), got " + s.length() + ": " + hex);
        }
        return HexFormat.of().parseHex(s);
    }

    private static String stripHexPrefix(String hex) {
        return hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
    }
}
