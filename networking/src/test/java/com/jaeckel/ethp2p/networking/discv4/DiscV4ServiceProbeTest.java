package com.jaeckel.ethp2p.networking.discv4;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The probe dedup/rate-limit decision (no socket needed — {@code shouldProbe}
 *  is pure bookkeeping; the send path is exercised by live runs). */
class DiscV4ServiceProbeTest {

    private static DiscV4Service service() {
        return new DiscV4Service(NodeKey.generate(), List.of(), entry -> { });
    }

    @Test
    void firstProbePassesRepeatWithinWindowIsDeduped() {
        DiscV4Service s = service();
        long t0 = 1_000_000L;
        assertTrue(s.shouldProbe("1.2.3.4:30303", t0), "first probe must pass");
        assertFalse(s.shouldProbe("1.2.3.4:30303", t0 + 1), "immediate repeat deduped");
        assertFalse(s.shouldProbe("1.2.3.4:30303", t0 + 59 * 60 * 1000L), "still inside 1h window");
        assertTrue(s.shouldProbe("1.2.3.4:30303", t0 + 61 * 60 * 1000L), "window expired → re-probe");
        assertTrue(s.shouldProbe("5.6.7.8:30303", t0), "different endpoint independent");
    }

    @Test
    void oversizedMapIsDroppedAllowingEarlyReprobe() {
        DiscV4Service s = service();
        long t0 = 1_000_000L;
        assertTrue(s.shouldProbe("target:1", t0));
        for (int i = 0; i < 1025; i++) {
            s.shouldProbe("filler:" + i, t0);
        }
        // The clear-on-overflow lost the history — an early re-probe is the
        // documented worst case, not an error.
        assertTrue(s.shouldProbe("target:1", t0 + 1));
    }
}
