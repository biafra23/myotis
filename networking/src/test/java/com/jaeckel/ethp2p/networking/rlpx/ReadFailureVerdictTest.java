package com.jaeckel.ethp2p.networking.rlpx;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector.ReadFailureVerdict;
import org.junit.jupiter.api.Test;

/**
 * The verified-read failure ladder (twin of the Rust engine's
 * {@code read_failure_verdict}, rust/myotis-net/src/el/pool.rs): the sole
 * serving peer is shielded (no strike, no bench — benching it flaps the
 * serving pool between 0 and 1, and an empty response there is likelier OUR
 * stale root); otherwise consecutive failures bench until the
 * {@code READ_FAILS_EVICT}th, which evicts so the maintainer can refill the
 * slot. Pinned here because the 2026-09-02 stale-pool incident was exactly a
 * pool that benching alone could never rotate out.
 */
class ReadFailureVerdictTest {

    @Test
    void soleServingPeerIsShieldedRegardlessOfStreak() {
        assertEquals(ReadFailureVerdict.SHIELD, RLPxConnector.readFailureVerdict(false, 1));
        assertEquals(ReadFailureVerdict.SHIELD, RLPxConnector.readFailureVerdict(false, 99));
    }

    @Test
    void failuresBelowTheThresholdBench() {
        for (int fails = 1; fails < RLPxConnector.READ_FAILS_EVICT; fails++) {
            assertEquals(ReadFailureVerdict.BENCH, RLPxConnector.readFailureVerdict(true, fails));
        }
    }

    @Test
    void theThresholdFailureEvicts() {
        assertEquals(ReadFailureVerdict.EVICT,
            RLPxConnector.readFailureVerdict(true, RLPxConnector.READ_FAILS_EVICT));
        assertEquals(ReadFailureVerdict.EVICT,
            RLPxConnector.readFailureVerdict(true, RLPxConnector.READ_FAILS_EVICT + 1));
    }

    @Test
    void thresholdMatchesTheRustEngine() {
        // rust/myotis-net/src/el/pool.rs READ_FAILS_EVICT — the two engines
        // must rotate at the same rate (the caches' DENIED threshold equality
        // is pinned by PeerCacheTest, which sees both classes).
        assertEquals(3, RLPxConnector.READ_FAILS_EVICT);
    }
}
