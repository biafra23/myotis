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
                        + "\"slot\":15626560,\"epoch\":488330,\"operators\":[\"attestant.io\",\"sigp.io\"]}");
        assertTrue(r.applied());
        assertEquals("0x" + "11".repeat(32), r.root());
        assertEquals(15626560L, r.slot());
        assertEquals(488330L, r.epoch());
        assertEquals(List.of("attestant.io", "sigp.io"), r.operators());
        assertNull(r.error());
    }

    @Test
    void refusedCarriesItsReason() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh("{\"applied\":false,\"error\":\"unknown handle\"}");
        assertFalse(r.applied());
        assertEquals("unknown handle", r.error());
        assertTrue(r.operators().isEmpty());
    }

    @Test
    void zkReleaseDecodes() {
        io.myotis.api.ZkRelease r = RustChainHandle.parseZkRelease("{\"applied\":true,\"period\":1907}");
        assertTrue(r.applied());
        assertEquals(1907L, r.period());
        assertNull(r.error());
        io.myotis.api.ZkRelease no = RustChainHandle.parseZkRelease("{\"applied\":false,\"error\":\"unknown handle\"}");
        assertFalse(no.applied());
        assertEquals("unknown handle", no.error());
    }

    @Test
    void malformedIsARefusalNotACrash() {
        AnchorRefresh r = RustChainHandle.parseAnchorRefresh("not json");
        assertFalse(r.applied());
        assertTrue(r.error().startsWith("malformed engine answer"));
    }
}
