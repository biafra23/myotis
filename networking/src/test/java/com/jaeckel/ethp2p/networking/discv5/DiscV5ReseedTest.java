package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The empty-table re-seed counter ({@link DiscV5Service#reseedDue}): the live
 * table wedging empty must trigger a bootnode re-ping every 4th consecutive
 * empty poll, and any live node must reset the streak. (The wedge itself —
 * bootnodes pinged only inside the library's start() — is a live-network
 * behavior; this pins the recovery-decision logic around it.)
 */
class DiscV5ReseedTest {

    private DiscV5Service service() {
        // The ENR is only checked for presence by the counter; parsing happens
        // lazily at re-seed time, which these tests never reach.
        return new DiscV5Service(NodeKey.generate(), List.of("enr:-placeholder"), enr -> { });
    }

    @Test
    void reseedFiresOnFourthConsecutiveEmptyPoll() {
        DiscV5Service s = service();
        assertFalse(s.reseedDue(0));
        assertFalse(s.reseedDue(0));
        assertFalse(s.reseedDue(0));
        assertTrue(s.reseedDue(0), "4th consecutive empty poll must be due");
    }

    @Test
    void liveNodesResetTheStreak() {
        DiscV5Service s = service();
        s.reseedDue(0);
        s.reseedDue(0);
        s.reseedDue(0);
        assertFalse(s.reseedDue(5), "a live table must reset the streak");
        // Streak restarts from zero: three more empties are not enough...
        assertFalse(s.reseedDue(0));
        assertFalse(s.reseedDue(0));
        assertFalse(s.reseedDue(0));
        // ...the fourth is.
        assertTrue(s.reseedDue(0));
    }

    @Test
    void noBootnodesMeansNeverDue() {
        // A network with no pinned CL bootnodes: with nothing to ping, a
        // re-seed must never fire (it would log "re-pinged 0 bootnode(s)"
        // every minute forever, reading as recovery where none is possible).
        DiscV5Service s = new DiscV5Service(NodeKey.generate(), List.of(), enr -> { });
        for (int i = 0; i < 10; i++) {
            assertFalse(s.reseedDue(0), "no bootnodes: never due (poll " + i + ")");
        }
    }

    @Test
    void reseedRepeatsWhileTableStaysEmpty() {
        DiscV5Service s = service();
        for (int i = 0; i < 3; i++) assertFalse(s.reseedDue(0));
        assertTrue(s.reseedDue(0));
        // Counter reset on firing: the NEXT due point is 4 empty polls later,
        // so a persistent wedge keeps re-seeding instead of firing once.
        for (int i = 0; i < 3; i++) assertFalse(s.reseedDue(0));
        assertTrue(s.reseedDue(0));
    }
}
