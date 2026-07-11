package com.jaeckel.ethp2p.android;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Live peer-cache counts for the Status UI, computed by parsing the cache FILES
 * (not the in-memory cache objects): the files are the single source of truth
 * shared across engines — the Rust engine reads/writes them directly, bypassing
 * the host's in-memory {@link AndroidCLPeerCache}/{@link AndroidPeerCache}
 * instances, which therefore go stale for Rust-hosted chains. Parsing is
 * memoized on (mtime, size), so the steady-state 2 s status poll costs a
 * single stat() per file.
 *
 * <p>Formats (see the cache classes for the authoritative docs):
 * EL {@code ip\tport\tpubkey[\tsnap][\tsnapok|\tsnapbad]}; CL
 * {@code multiaddr[\t<low>-<high>][\tb<period>][\tlc|\tnolc]} — only lines
 * starting with {@code /} are CL peers, ranges mark proven catch-up servers.
 */
final class CacheFileStats {

    /** CL: total cached peers, proven LC servers (served-range or {@code lc} token),
     *  nolc-flagged. Buckets are mutually exclusive (proven wins over nolc), so
     *  {@code total - proven - nolc} is the untried remainder the UI shows. */
    record ClStats(int total, int proven, int nolc) {
        static final ClStats EMPTY = new ClStats(0, 0, 0);
    }

    /** EL: total cached peers, snap-serving confirmed (snapok), denied (snapbad). */
    record ElStats(int total, int snapOk, int snapBad) {
        static final ElStats EMPTY = new ElStats(0, 0, 0);
    }

    private record Memo(long mtime, long size, Object stats) {}

    private static final Map<Path, Memo> MEMO = new ConcurrentHashMap<>();

    private CacheFileStats() {}

    static ClStats cl(Path file) {
        return (ClStats) memoized(file, ClStats.EMPTY, CacheFileStats::parseCl);
    }

    static ElStats el(Path file) {
        return (ElStats) memoized(file, ElStats.EMPTY, CacheFileStats::parseEl);
    }

    private interface Parser {
        Object parse(List<String> lines);
    }

    private static Object memoized(Path file, Object empty, Parser parser) {
        Memo memo = MEMO.get(file);
        try {
            if (!Files.isRegularFile(file)) {
                MEMO.remove(file);
                return empty;
            }
            long mtime = Files.getLastModifiedTime(file).toMillis();
            long size = Files.size(file);
            if (memo != null && memo.mtime() == mtime && memo.size() == size) {
                return memo.stats();
            }
            Object stats = parser.parse(Files.readAllLines(file));
            // Re-stat AFTER the read: the Java cache writers rewrite in place
            // (truncate + write, not atomic rename), so a read racing a rewrite
            // can parse a torn file. Only memoize when the identity held across
            // the read; a torn parse is returned once (next poll re-reads) but
            // never sticks in the memo.
            if (Files.getLastModifiedTime(file).toMillis() == mtime && Files.size(file) == size) {
                MEMO.put(file, new Memo(mtime, size, stats));
            }
            return stats;
        } catch (Exception e) {
            // Racing rewrite / transient IO: show the last-known counts rather
            // than flashing zeros; cosmetic surface, never throw.
            return memo != null ? memo.stats() : empty;
        }
    }

    static ClStats parseCl(List<String> lines) {
        int total = 0;
        int proven = 0;
        int nolc = 0;
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("/")) continue;
            total++;
            // Per-PEER flags, not per-token: the loader merges multiple
            // range/legacy tokens on one line into a single served range
            // (widening), so counting per token could show proven > total.
            // Proven now includes Identify-confirmed `lc` peers, not just
            // catch-up servers — and beats nolc — so the three buckets
            // (proven / nolc / untried-remainder) always sum to total.
            boolean hasLcSignal = false;
            boolean hasNolc = false;
            String[] tokens = trimmed.split("\t");
            for (int i = 1; i < tokens.length; i++) {
                String tok = tokens[i];
                if (tok.equals("nolc")) hasNolc = true;
                else if (tok.equals("lc") || isServedRange(tok)) hasLcSignal = true;
            }
            if (hasLcSignal) proven++;
            else if (hasNolc) nolc++;
        }
        return new ClStats(total, proven, nolc);
    }

    static ElStats parseEl(List<String> lines) {
        int total = 0;
        int snapOk = 0;
        int snapBad = 0;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String[] tokens = trimmed.split("\t");
            // Tab format needs host+port+pubkey; the daemon's legacy colon form
            // never occurs in this app's cache dir, so it isn't counted here.
            if (tokens.length < 3) continue;
            total++;
            // Loader parity (AndroidPeerCache): index 3 is the snap capability
            // flag; quality tokens are recognized from index 4, LAST one wins.
            String quality = null;
            for (int i = 4; i < tokens.length; i++) {
                if (tokens[i].equals("snapok") || tokens[i].equals("snapbad")) {
                    quality = tokens[i];
                }
            }
            if ("snapok".equals(quality)) snapOk++;
            else if ("snapbad".equals(quality)) snapBad++;
        }
        return new ElStats(total, snapOk, snapBad);
    }

    /** A proven catch-up served range: {@code <low>-<high>} with numeric halves
     *  (legacy bare integers also mark proven servers, per the cache parsers). */
    private static boolean isServedRange(String tok) {
        if (tok.isEmpty()) return false;
        int dash = tok.indexOf('-');
        if (dash < 0) return allDigits(tok); // legacy bare floor
        return dash > 0 && dash < tok.length() - 1
                && allDigits(tok.substring(0, dash)) && allDigits(tok.substring(dash + 1));
    }

    private static boolean allDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // ASCII only — Character.isDigit accepts any Unicode digit class,
            // which the strictly-ASCII cache format never contains.
            if (c < '0' || c > '9') return false;
        }
        return true;
    }
}
