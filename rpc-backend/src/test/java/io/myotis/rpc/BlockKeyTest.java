package io.myotis.rpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.evm.Address;
import io.myotis.evm.BlockContext;
import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The block half of the eth_call and eth_estimateGas cache keys
 * ({@code VerifiedRpcBackend.blockKey}): one block gives one key, and every
 * block input the EVM reads gives its own. A key on the state root alone
 * would replay an answer computed at one base fee, number or timestamp in a
 * block that shares the root but not the rest (#523 review).
 */
class BlockKeyTest {

    private static final BigInteger MAINNET = BigInteger.ONE;

    private static byte[] filled(int b) {
        byte[] a = new byte[32];
        Arrays.fill(a, (byte) b);
        return a;
    }

    private static Address address(int b) {
        byte[] a = new byte[20];
        Arrays.fill(a, (byte) b);
        return Address.of(a);
    }

    private static BlockContext block() {
        return new BlockContext(filled(1), 23_000_000L, 1_760_000_000L, BigInteger.valueOf(7),
                address(2), filled(3), MAINNET, 36_000_000L);
    }

    @Test
    void oneBlockGivesOneKey() {
        assertEquals(VerifiedRpcBackend.blockKey(block()), VerifiedRpcBackend.blockKey(block()));
    }

    @Test
    void everyBlockInputGivesItsOwnKey() {
        BlockContext b = block();
        Map<String, BlockContext> sameRootUnlessNamed = new LinkedHashMap<>();
        sameRootUnlessNamed.put("as is", b);
        sameRootUnlessNamed.put("state root", new BlockContext(filled(9), b.blockNumber(), b.timestamp(),
                b.baseFeePerGas(), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("number", new BlockContext(b.stateRoot(), b.blockNumber() + 1, b.timestamp(),
                b.baseFeePerGas(), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("timestamp", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp() + 12,
                b.baseFeePerGas(), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("base fee", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                BigInteger.valueOf(8), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("no base fee", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                null, b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("coinbase", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                b.baseFeePerGas(), address(4), b.prevRandao(), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("prevRandao", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                b.baseFeePerGas(), b.coinbase(), filled(5), b.chainId(), b.gasLimit()));
        sameRootUnlessNamed.put("chain id", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                b.baseFeePerGas(), b.coinbase(), b.prevRandao(), BigInteger.valueOf(100), b.gasLimit()));
        sameRootUnlessNamed.put("gas limit", new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                b.baseFeePerGas(), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit() + 1));

        Map<String, String> owner = new LinkedHashMap<>();
        sameRootUnlessNamed.forEach((what, block) -> {
            String previous = owner.put(VerifiedRpcBackend.blockKey(block), what);
            assertTrue(previous == null, "'" + what + "' and '" + previous + "' share a key");
        });
    }

    /** blockKey names BlockContext's components one by one. A component added
     *  later has to be keyed too, or two contexts differing only there would
     *  share cached answers: this fails until it is. */
    @Test
    void blockKeyNamesEveryBlockContextComponent() {
        Set<String> keyed = Set.of("stateRoot", "blockNumber", "timestamp", "baseFeePerGas",
                "gasLimit", "coinbase", "prevRandao", "chainId");
        Set<String> components = Arrays.stream(BlockContext.class.getRecordComponents())
                .map(RecordComponent::getName).collect(Collectors.toSet());
        assertEquals(keyed, components,
                "BlockContext changed: key every component in VerifiedRpcBackend.blockKey, then update this list");
    }

    /** The keys the caches actually use start from the block: the same call or
     *  estimate in a block that shares the state root but not the base fee is
     *  another entry, and the same request in the same block is the same one. */
    @Test
    void callAndEstimateKeysTellSameRootBlocksApart() {
        BlockContext b = block();
        BlockContext higherBaseFee = new BlockContext(b.stateRoot(), b.blockNumber(), b.timestamp(),
                BigInteger.valueOf(8), b.coinbase(), b.prevRandao(), b.chainId(), b.gasLimit());
        byte[] from = address(6).toByteArray();
        byte[] to = address(7).toByteArray();
        byte[] data = {0x12, 0x34};
        BigInteger value = BigInteger.ONE;
        BigInteger feeCap = BigInteger.TEN;

        assertEquals(VerifiedRpcBackend.callFlightKey(b, from, to, value, data),
                VerifiedRpcBackend.callFlightKey(block(), from, to, value, data));
        assertNotEquals(VerifiedRpcBackend.callFlightKey(b, from, to, value, data),
                VerifiedRpcBackend.callFlightKey(higherBaseFee, from, to, value, data));

        assertEquals(VerifiedRpcBackend.estimateKey(b, from, to, data, value, 100_000L, feeCap, null),
                VerifiedRpcBackend.estimateKey(block(), from, to, data, value, 100_000L, feeCap, null));
        assertNotEquals(VerifiedRpcBackend.estimateKey(b, from, to, data, value, 100_000L, feeCap, null),
                VerifiedRpcBackend.estimateKey(higherBaseFee, from, to, data, value, 100_000L, feeCap, null));
    }
}
