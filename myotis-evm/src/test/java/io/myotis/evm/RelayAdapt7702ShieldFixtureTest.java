package io.myotis.evm;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.SnapStateOracle;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Replays the mainnet RelayAdapt7702 shield (#509 stage 2, part 3) on the Java
 * engine. {@code rust/testdata/evm/relayadapt7702-shield.json} is the world the
 * live Rust engine read while estimating a RAILGUN "shield ETH" through a fresh
 * EIP-7702 account, recorded with throwaway keys by
 * {@code rust/myotis-net/examples/record_shield_fixture.rs}.
 *
 * <p>This engine refuses an authorization list ({@code VerifiedRpcBackend}
 * points the caller at the Rust engine), so it replays the variant it serves:
 * the retry from the account the failed first attempt left delegated, a plain
 * call into real RAILGUN code. It must answer exactly what the Rust engine
 * answers (the recorder's {@code retryFromDelegatedEstimate}, which the Rust
 * replay pins too).
 *
 * <p>The oracle serves the recorded world only, and a read the recording did
 * not make fails the test. Set {@code MYOTIS_SHIELD_FIXTURE} to replay another
 * recording.
 */
class RelayAdapt7702ShieldFixtureTest {

    private static final Path FIXTURE = Paths.get("..", "rust", "testdata", "evm", "relayadapt7702-shield.json");

    @Test
    void theRetryFromTheDelegatedAccountIsEstimatedAsTheRustEngineEstimatesIt() throws Exception {
        String override = System.getenv("MYOTIS_SHIELD_FIXTURE");
        Fixture f = Fixture.load(override != null ? Paths.get(override) : FIXTURE);
        JsonObject shield = f.meta.get("shield").asObject();
        Address ephemeral = Address.fromHex(shield.getString("ephemeral", null));
        Address delegate = Address.fromHex(shield.getString("delegate", null));
        // The account as the failed first attempt left it: delegated, nonce 1.
        byte[] designator = Bytes.concatenate(Bytes.fromHexString("0xef0100"), Bytes.wrap(delegate.toByteArray())).toArrayUnsafe();
        f.accounts.put(ephemeral, new AccountState(ephemeral, 1, BigInteger.ZERO, keccak(designator)));
        f.code.put(Bytes.wrap(keccak(designator)), designator);

        JsonObject retry = f.meta.get("variants").asObject().get("retryFromDelegated").asObject();
        assertTrue(retry.get("authorizationList") == null, "the retry is a plain call");
        UnsignedTransaction tx = new UnsignedTransaction(
                Address.fromHex(retry.getString("from", null)),
                Address.fromHex(retry.getString("to", null)),
                quantity(retry.get("value")),
                Bytes.fromHexString(retry.getString("data", null)).toArrayUnsafe(),
                null);

        DefaultEvmExecutor executor = new DefaultEvmExecutor(f);
        long estimate = executor.estimateGas(tx, f.block).get(60, TimeUnit.SECONDS);
        assertEquals(f.measured("retryFromDelegatedEstimate"), estimate,
                "the Java engine must answer what the Rust engine answers");
        UnsignedTransaction atEstimate = new UnsignedTransaction(tx.from(), tx.to(), tx.value(), tx.data(), estimate);
        executor.callTx(atEstimate, f.block).get(60, TimeUnit.SECONDS);
        assertTrue(f.misses.isEmpty(), "reads the recording never made: " + f.misses);
    }

    private static byte[] keccak(byte[] data) {
        CryptoProviders.ensureRegistered();
        return Hash.keccak256(Bytes.wrap(data)).toArrayUnsafe();
    }

    private static BigInteger quantity(JsonValue v) {
        return new BigInteger(v.asString().substring(2), 16);
    }

    /** The recorded world as an oracle; an unrecorded read is a test failure. */
    private static final class Fixture implements SnapStateOracle {
        final JsonObject meta;
        final JsonObject measured;
        final BlockContext block;
        /** null value = recorded ABSENT. */
        final Map<Address, AccountState> accounts = new HashMap<>();
        final Map<Address, Map<BigInteger, BigInteger>> storage = new HashMap<>();
        final Map<Bytes, byte[]> code = new HashMap<>();
        final List<String> misses = new ArrayList<>();

        private Fixture(JsonObject file) {
            assertEquals("myotis-evm-fixture/1", file.getString("format", null));
            meta = file.get("meta").asObject();
            measured = file.get("measured").asObject();
            JsonObject b = file.get("block").asObject();
            block = new BlockContext(
                    Bytes.fromHexString(b.getString("stateRoot", null)).toArrayUnsafe(),
                    quantity(b.get("number")).longValue(),
                    quantity(b.get("timestamp")).longValue(),
                    quantity(b.get("baseFeePerGas")),
                    Address.fromHex(b.getString("coinbase", null)),
                    Bytes.fromHexString(b.getString("prevRandao", null)).toArrayUnsafe(),
                    quantity(b.get("chainId")),
                    quantity(b.get("gasLimit")).longValue());
            for (JsonObject.Member m : file.get("accounts").asObject()) {
                Address address = Address.fromHex(m.getName());
                if (m.getValue().isNull()) {
                    accounts.put(address, null);
                    continue;
                }
                JsonObject a = m.getValue().asObject();
                accounts.put(address, new AccountState(address, quantity(a.get("nonce")).longValue(),
                        quantity(a.get("balance")), Bytes.fromHexString(a.getString("codeHash", null)).toArrayUnsafe()));
            }
            for (JsonObject.Member m : file.get("storage").asObject()) {
                Map<BigInteger, BigInteger> slots = new HashMap<>();
                for (JsonObject.Member s : m.getValue().asObject()) {
                    slots.put(new BigInteger(s.getName().substring(2), 16), quantity(s.getValue()));
                }
                storage.put(Address.fromHex(m.getName()), slots);
            }
            for (JsonObject.Member m : file.get("code").asObject()) {
                code.put(Bytes.fromHexString(m.getName()), Bytes.fromHexString(m.getValue().asString()).toArrayUnsafe());
            }
            // The state override every replay applies: the synthetic sender's funds.
            for (JsonObject.Member m : file.get("stateOverride").asObject()) {
                Address address = Address.fromHex(m.getName());
                AccountState onChain = accounts.get(address);
                accounts.put(address, new AccountState(address, onChain == null ? 0 : onChain.nonce(),
                        quantity(m.getValue().asObject().get("balance")),
                        onChain == null ? keccak(new byte[0]) : onChain.codeHash()));
            }
        }

        static Fixture load(Path path) throws IOException {
            return new Fixture(Json.parse(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)).asObject());
        }

        long measured(String key) {
            return quantity(measured.get(key)).longValue();
        }

        private void root(byte[] stateRoot) {
            assertTrue(Bytes.wrap(stateRoot).equals(Bytes.wrap(block.stateRoot())), "a read at a foreign state root");
        }

        @Override
        public CompletableFuture<AccountState> fetchAccount(byte[] stateRoot, Address address) {
            root(stateRoot);
            if (!accounts.containsKey(address)) {
                misses.add("account " + address);
                throw new AssertionError("the fixture never read account " + address + "; re-record it");
            }
            AccountState a = accounts.get(address);
            return CompletableFuture.completedFuture(
                    a != null ? a : new AccountState(address, 0, BigInteger.ZERO, keccak(new byte[0])));
        }

        @Override
        public CompletableFuture<BigInteger> fetchStorage(byte[] stateRoot, Address address, BigInteger slot) {
            root(stateRoot);
            Map<BigInteger, BigInteger> slots = storage.get(address);
            if (slots == null || !slots.containsKey(slot)) {
                misses.add("slot 0x" + slot.toString(16) + " of " + address);
                throw new AssertionError("the fixture never read slot 0x" + slot.toString(16) + " of " + address);
            }
            return CompletableFuture.completedFuture(slots.get(slot));
        }

        @Override
        public CompletableFuture<byte[]> fetchBytecode(byte[] codeHash) {
            byte[] bytes = code.get(Bytes.wrap(codeHash));
            if (bytes == null) {
                if (Bytes.wrap(codeHash).equals(Bytes.wrap(keccak(new byte[0])))) {
                    return CompletableFuture.completedFuture(new byte[0]);
                }
                misses.add("code " + Bytes.wrap(codeHash));
                throw new AssertionError("the fixture never read the bytecode " + Bytes.wrap(codeHash));
            }
            return CompletableFuture.completedFuture(bytes.clone());
        }
    }
}
