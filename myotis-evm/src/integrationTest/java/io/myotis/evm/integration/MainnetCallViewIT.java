package io.myotis.evm.integration;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.ens.Namehash;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.SnapBackedStateOracle;
import io.myotis.evm.world.SnapPeer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 1 acceptance test — closes the loop on the original Phase 1 plan:
 *
 * <blockquote>
 *   "Run callView against mainnet for USDC balanceOf(vitalik.eth), DAI
 *    balanceOf(vitalik.eth), ENS Public Resolver addr(namehash("vitalik.eth")).
 *    Confirm results match RPC eth_call. Acceptance criteria: integration
 *    tests pass, executed against a real SNAP peer."
 * </blockquote>
 *
 * <p>The test is env-gated:
 *
 * <ul>
 *   <li>{@code MYOTIS_MAINNET=1} — flip the kill switch
 *   <li>{@code MYOTIS_INTEGRATION_PEER_ENODE} — enode URL of a snap/1 peer
 *   <li>{@code MYOTIS_INTEGRATION_STATE_ROOT} — 0x-prefixed 32-byte hex,
 *       a recent verified mainnet state root (the operator picks one
 *       finalised by sync committee; the test does not re-derive it)
 *   <li>{@code MYOTIS_INTEGRATION_BLOCK_NUMBER} — block number for that root
 *   <li>{@code MYOTIS_INTEGRATION_BLOCK_TIMESTAMP} — Unix seconds for fork
 *       selection in {@code EvmFactory.buildForBlock}
 *   <li>{@code MYOTIS_INTEGRATION_BASE_FEE_WEI} — block base fee
 *   <li>{@code MYOTIS_INTEGRATION_VITALIK_USDC_BALANCE} (optional) —
 *       expected USDC balance for cross-checking against eth_call output
 *       from a public RPC at the same block
 * </ul>
 *
 * <p>The test suite is intentionally <em>not</em> wired into
 * {@code ./gradlew check}; operators run it explicitly via
 * {@code ./gradlew :myotis-evm:integrationTest} after supplying the env vars.
 */
@EnabledIfEnvironmentVariable(named = "MYOTIS_MAINNET", matches = "1")
class MainnetCallViewIT {

    private static final Address USDC = Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    private static final Address DAI  = Address.fromHex("0x6B175474E89094C44Da98b954EedeAC495271d0F");
    /**
     * ENS Public Resolver v2 (the common one most names point at).
     * vitalik.eth → 0xd8da6BF26964aF9D7eEd9e03E53415D37aA96045 should resolve via this.
     */
    private static final Address ENS_PUBLIC_RESOLVER =
            Address.fromHex("0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63");

    private static final Address VITALIK = Address.fromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    @Test
    void usdcBalanceOfVitalik() throws Exception {
        DefaultEvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        FunctionSignature balanceOf = FunctionSignature.of("balanceOf(address)");
        byte[] calldata = AbiEncoder.encodeCall(balanceOf, AbiEncoder.address(VITALIK));

        byte[] result = executor.callView(USDC, calldata, ctx)
                .get(60, TimeUnit.SECONDS);
        assertEquals(32, result.length, "balanceOf must return one uint256");
        BigInteger balance = AbiDecoder.uint256(result, 0);
        assertTrue(balance.signum() >= 0, "balance is non-negative");

        String expected = System.getenv("MYOTIS_INTEGRATION_VITALIK_USDC_BALANCE");
        if (expected != null && !expected.isBlank()) {
            assertEquals(new BigInteger(expected), balance,
                    "USDC.balanceOf(vitalik.eth) does not match the expected value " +
                    "set via MYOTIS_INTEGRATION_VITALIK_USDC_BALANCE");
        }
    }

    @Test
    void daiBalanceOfVitalik() throws Exception {
        DefaultEvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        FunctionSignature balanceOf = FunctionSignature.of("balanceOf(address)");
        byte[] calldata = AbiEncoder.encodeCall(balanceOf, AbiEncoder.address(VITALIK));

        byte[] result = executor.callView(DAI, calldata, ctx)
                .get(60, TimeUnit.SECONDS);
        assertEquals(32, result.length);
        BigInteger balance = AbiDecoder.uint256(result, 0);
        assertTrue(balance.signum() >= 0);
    }

    @Test
    void ensPublicResolverAddrForVitalikEth() throws Exception {
        DefaultEvmExecutor executor = mainnetExecutor();
        BlockContext ctx = mainnetBlockContext();

        // Classic on-chain ENS path (no CCIP-Read): call addr(node) on the
        // public resolver. node = namehash("vitalik.eth").
        byte[] node = Namehash.of("vitalik.eth");
        FunctionSignature addr = FunctionSignature.of("addr(bytes32)");
        byte[] calldata = AbiEncoder.encodeCall(addr, AbiEncoder.bytes32(node));

        byte[] result = executor.callView(ENS_PUBLIC_RESOLVER, calldata, ctx)
                .get(60, TimeUnit.SECONDS);
        assertEquals(32, result.length, "addr(bytes32) returns one address");
        Address resolved = AbiDecoder.address(result, 0);
        assertEquals(VITALIK, resolved,
                "ENS public resolver should map vitalik.eth → " + VITALIK);
    }

    // ---- Wiring ------------------------------------------------------------

    /**
     * Build a {@link DefaultEvmExecutor} backed by a real SNAP peer.
     *
     * <p>This stub is deliberately incomplete: standing up a discv4-discovered,
     * eth/68- and snap/1-handshaked {@code EthHandler} from inside a test is a
     * non-trivial reproduction of {@code :app}'s {@code Main}. The simplest
     * path for an operator is to run the daemon via
     * {@code ./gradlew :app:run} until it has at least one snap-capable peer,
     * then expose that peer's {@code EthHandler} (or an enode-addressable
     * connection helper) here.
     *
     * <p>For now this method throws {@code UnsupportedOperationException} so
     * the test fails fast with a clear pointer to what's missing — and so the
     * compile path is exercised on every build, catching API drift in the
     * adapter / oracle / executor before it lands.
     */
    private static DefaultEvmExecutor mainnetExecutor() {
        SnapPeer peer = connectToMainnetPeer();
        return new DefaultEvmExecutor(
                new SnapBackedStateOracle(() -> peer, BytecodeCache.inMemory()),
                BytecodeCache.inMemory(),
                java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "myotis-evm-it");
                    t.setDaemon(true);
                    return t;
                }));
    }

    private static SnapPeer connectToMainnetPeer() {
        String enode = System.getenv("MYOTIS_INTEGRATION_PEER_ENODE");
        assertNotNull(enode,
                "MYOTIS_INTEGRATION_PEER_ENODE must be set; see class Javadoc");
        // TODO(phase1.commit5+): stand up an EthHandler against the configured
        // enode and wrap it with com.jaeckel.ethp2p.app.snap.EthHandlerSnapPeer.
        // Reuse :app's RLPxConnector / ChainHead glue once it's factored out
        // of Main into a reusable test fixture.
        throw new UnsupportedOperationException(
                "EthHandler bootstrap from a test is not yet implemented; "
                        + "see TODO in MainnetCallViewIT.connectToMainnetPeer.");
    }

    private static BlockContext mainnetBlockContext() {
        byte[] stateRoot = parseHex32(env("MYOTIS_INTEGRATION_STATE_ROOT"));
        long blockNumber = Long.parseLong(env("MYOTIS_INTEGRATION_BLOCK_NUMBER"));
        long timestamp = Long.parseLong(env("MYOTIS_INTEGRATION_BLOCK_TIMESTAMP"));
        BigInteger baseFee = new BigInteger(env("MYOTIS_INTEGRATION_BASE_FEE_WEI"));
        return new BlockContext(
                stateRoot,
                blockNumber,
                timestamp,
                baseFee,
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
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
