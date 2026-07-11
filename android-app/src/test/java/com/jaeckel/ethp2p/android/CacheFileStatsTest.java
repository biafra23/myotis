package com.jaeckel.ethp2p.android;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * The cache-file counters behind the Status "CL cache" / "EL cache" rows —
 * parse the exact token formats the Java AND Rust engines write (the files are
 * the shared cross-engine truth, so these counts must be format-accurate).
 */
public class CacheFileStatsTest {

    @Test
    public void clCountsProvenRangesLegacyFloorsAndNolc() {
        CacheFileStats.ClStats s = CacheFileStats.parseCl(List.of(
                "/ip4/1.1.1.1/tcp/9000/p2p/16Ua\t1770-1795\tb1480\tlc",   // proven (range)
                "/ip4/2.2.2.2/tcp/9000/p2p/16Ub\t1777",                    // proven (legacy bare floor)
                "/ip4/3.3.3.3/tcp/9000/p2p/16Uc\tnolc",
                "/ip4/4.4.4.4/tcp/9000/p2p/16Ud\tb1480\tlc",              // proven (bootstrap-served + lc)
                "/ip4/5.5.5.5/tcp/9000/p2p/16Ue",                          // untried (no verdict tokens)
                // Multi-token line the loader accepts by WIDENING into one
                // range — must count as ONE proven peer, never two (the
                // per-token bug showed proven > total).
                "/ip4/6.6.6.6/tcp/9000/p2p/16Uf\t1770-1795\t1777",
                // Conflict line: buckets are mutually exclusive, proven wins —
                // the status row's three buckets must always sum to total.
                "/ip4/7.7.7.7/tcp/9000/p2p/16Ug\t1770-1795\tnolc",
                // Bare bootstrap token: served a light_client_bootstrap ⇒ proven,
                // not "untried" (bootstrap IS a light-client protocol).
                "/ip4/8.8.8.8/tcp/9000/p2p/16Uh\tb1500",
                "# comment / stray line",
                ""));
        assertEquals(8, s.total());
        assertEquals(6, s.proven());
        assertEquals(1, s.nolc());
        // untried = total - proven - nolc, the row's derived third bucket
        assertEquals(1, s.total() - s.proven() - s.nolc());
    }

    @Test
    public void elCountsSnapQualityTokensWithLoaderParity() {
        CacheFileStats.ElStats s = CacheFileStats.parseEl(List.of(
                "1.2.3.4\t30303\tabcdef\t1\tsnapok",
                "5.6.7.8\t30303\t123456\t0",
                "9.9.9.9\t30303\tfedcba\t1\tsnapbad",
                // Quality token at index 3 (no snap flag): the loader treats
                // index 3 strictly as the flag, so this peer is UNKNOWN quality
                // — counted in total only.
                "8.8.8.8\t30303\taaaaaa\tsnapok",
                // Both tokens present: LAST wins (loader parity).
                "7.7.7.7\t30303\tbbbbbb\t1\tsnapok\tsnapbad",
                "bad\tline",   // < 3 fields — skipped
                ""));
        assertEquals(5, s.total());
        assertEquals(1, s.snapOk());
        assertEquals(2, s.snapBad());
    }
}
