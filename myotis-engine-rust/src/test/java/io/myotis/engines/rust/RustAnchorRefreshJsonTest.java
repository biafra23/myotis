package io.myotis.engines.rust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.api.AnchorRefresh;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The JVM half of {@code refresh_anchor_from_checkpointz}'s JSON contract: the
 * literals of host.rs {@code anchor_refresh_json_shape}, decoded as the iOS
 * side's {@code EngineDecodingTest} decodes them.
 */
class RustAnchorRefreshJsonTest {

    @Test
    void appliedDecodes() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh(
                "{\"applied\":true,\"root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\","
                        + "\"slot\":15626560,\"epoch\":488330,\"operators\":[\"attestant.io\",\"sigp.io\"],"
                        + "\"confirmedBy\":[\"pinned 12D3Ko…abcdef\"],\"unconfirmed\":false}");
        assertTrue(r.applied());
        assertEquals("0x" + "11".repeat(32), r.root());
        assertEquals(15626560L, r.slot());
        assertEquals(488330L, r.epoch());
        assertEquals(List.of("attestant.io", "sigp.io"), r.operators());
        assertEquals(List.of("pinned 12D3Ko…abcdef"), r.confirmedBy());
        assertFalse(r.unconfirmed());
        assertNull(r.error());
    }

    @Test
    void refusedCarriesItsReason() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh(
                "{\"applied\":false,\"error\":\"unknown handle\",\"unconfirmed\":false}");
        assertFalse(r.applied());
        assertEquals("unknown handle", r.error());
        assertTrue(r.operators().isEmpty());
        assertFalse(r.unconfirmed());
    }

    @Test
    void anUnconfirmedRefusalIsFlagged() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh(
                "{\"applied\":false,\"error\":\"UNCONFIRMED: …\",\"unconfirmed\":true}");
        assertFalse(r.applied());
        assertTrue(r.unconfirmed());
        assertTrue(r.error().startsWith("UNCONFIRMED"));
    }

    /** The ordinals ARE the engine's codes (myotis-net `StalePolicy`): pinned. */
    @Test
    void stalePolicyOrdinalsAreTheEngineCodes() {
        assertEquals(0, io.myotis.api.StaleAnchorPolicy.ASK.ordinal());
        assertEquals(1, io.myotis.api.StaleAnchorPolicy.CHECKPOINT.ordinal());
        assertEquals(2, io.myotis.api.StaleAnchorPolicy.CONTINUE.ordinal());
    }

    @Test
    void malformedIsARefusalNotACrash() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh("not json");
        assertFalse(r.applied());
        assertTrue(r.error().startsWith("malformed engine answer"));
    }
}
