package io.myotis.engines.go;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.api.AnchorRefresh;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The JVM half of {@code refresh_anchor_from_checkpointz}'s JSON contract on the
 * GO side — the mirror of {@code RustAnchorRefreshJsonTest} (same cases, same
 * literals where the engines agree), plus the Go library's own refusal string
 * ({@code go/internal/capi}'s {@code AnchorRefreshUnsupported}). The parse must
 * never produce a half-built applied record: an applied-shaped answer with an
 * unreadable member is a REFUSAL, because the record's contract is
 * {@code error: null when applied} (PR #877 round-2).
 */
class GoAnchorRefreshJsonTest {

    @Test
    void appliedDecodes() {
        AnchorRefresh r = GoChainHandle.parseAnchorRefresh(
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
        AnchorRefresh r = GoChainHandle.parseAnchorRefresh(
                "{\"applied\":false,\"error\":\"unknown handle\",\"unconfirmed\":false}");
        assertFalse(r.applied());
        assertEquals("unknown handle", r.error());
        assertTrue(r.operators().isEmpty());
        assertFalse(r.unconfirmed());
    }

    @Test
    void theGoLibrarysOwnRefusalDecodes() {
        // The literal AnchorRefreshUnsupported writes today (ABI 58 refusal,
        // applied:false in the contract's key set) — if the Go side ever
        // rewords it past this prefix, the host still shows the engine's word.
        AnchorRefresh r = GoChainHandle.parseAnchorRefresh(
                "{\"applied\":false,\"error\":\"go engine: checkpoint-anchor refresh "
                        + "(myotis_refresh_anchor_from_checkpointz) is not implemented by this engine; "
                        + "the stale anchor stays parked — myotis_accept_stale_anchor still applies\","
                        + "\"unconfirmed\":false}");
        assertFalse(r.applied());
        assertTrue(r.error().startsWith("go engine: checkpoint-anchor refresh"), r.error());
        assertTrue(r.error().contains("myotis_accept_stale_anchor still applies"));
        assertFalse(r.unconfirmed());
    }

    @Test
    void malformedIsARefusalNotACrash() {
        AnchorRefresh r = GoChainHandle.parseAnchorRefresh("not json");
        assertFalse(r.applied());
        assertTrue(r.error().startsWith("malformed engine answer"));
    }

    @Test
    void anAppliedShapedAnswerWithBadMembersIsARefusal() {
        // The divergence round-2 caught in the first copy: applied:true with a
        // member the record cannot carry must NOT come back
        // applied=true-with-error.
        AnchorRefresh wrongTypeRoot = GoChainHandle.parseAnchorRefresh(
                "{\"applied\":true,\"root\":123,\"slot\":1,\"epoch\":1,"
                        + "\"operators\":[],\"confirmedBy\":[],\"unconfirmed\":false}");
        assertFalse(wrongTypeRoot.applied());
        assertTrue(wrongTypeRoot.error().startsWith("malformed engine answer"));
        AnchorRefresh nonStringMember = GoChainHandle.parseAnchorRefresh(
                "{\"applied\":true,\"root\":\"0x11\",\"slot\":1,\"epoch\":1,"
                        + "\"operators\":[7],\"confirmedBy\":[],\"unconfirmed\":false}");
        assertFalse(nonStringMember.applied());
        assertTrue(nonStringMember.error().startsWith("malformed engine answer"));
    }
}
