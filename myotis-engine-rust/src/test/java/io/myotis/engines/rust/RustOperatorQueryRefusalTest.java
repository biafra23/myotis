package io.myotis.engines.rust;

import io.myotis.api.EngineException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the refusal the Rust engine gives the Java-engine operator queries. The hosts'
 * Query-tab block lookup (io.myotis.ui.isOperatorQueryRefusal, desktop and Android)
 * recognises it by its "not available on the Rust engine" prefix and falls back to the
 * verified eth_getBlockByNumber read — a reworded message would silently drop that
 * fallback, so a reword must fail here. No native call is made: the refusal comes first.
 */
class RustOperatorQueryRefusalTest {

    private static final String HOST_MATCHED_PREFIX = "not available on the Rust engine";

    private final RustChainHandle handle = new RustChainHandle(0L, "mainnet", 1L, 8545, false);

    @Test
    void getBlockVerifiedRefusalKeepsTheHostMatchedPrefix() {
        EngineException e = assertThrows(EngineException.class, () -> handle.getBlockVerified(21_000_000L));
        assertTrue(e.getMessage().startsWith(HOST_MATCHED_PREFIX), e.getMessage());
    }
}
