package io.myotis.engines.common;

import io.myotis.api.DataUsage;
import io.myotis.api.NetworkMetering;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One network's data usage by local day — the Java engine's twin of the Rust
 * engine's {@code usage::UsageLedger} (docs/data-usage.md), with the same file.
 *
 * <p>The byte counts come from a {@link Meter} that only ever grows. Each
 * {@link #tick} adds its growth since the previous tick to the current LOCAL day,
 * and to that day's metered figures too while the host's last word was
 * {@link NetworkMetering#METERED}. Today's figures survive a restart in
 * {@code data-usage[-net].json} beside the sync snapshot; a previous day's file
 * is ignored.
 */
public final class DataUsageLedger {

    private static final Logger log = LoggerFactory.getLogger(DataUsageLedger.class);

    /** How often a busy ledger writes its file at most, outside a forced tick
     *  and a new day (the Rust ledger's {@code WRITE_EVERY}). */
    static final long WRITE_EVERY_MS = 5 * 60_000L;

    /** The meter: {@code {elIn, elOut, clIn, clOut}}, monotonic. */
    @FunctionalInterface
    public interface Meter {
        long[] snapshot();
    }

    private static volatile NetworkMetering metering = NetworkMetering.UNKNOWN;

    /** The metering the host reported last (process-wide: the device's network). */
    public static NetworkMetering metering() {
        return metering;
    }

    /** Record the host's report. Tick every ledger FIRST, so the bytes moved
     *  before the change keep the label they were moved under. */
    public static void setMetering(NetworkMetering m) {
        if (m == null) throw new IllegalArgumentException("metering is required");
        metering = m;
    }

    private final Meter meter;
    private final Path file;
    private long[] seen;
    private LocalDate day;
    private long rx, tx, meteredRx, meteredTx;
    private boolean dirty;
    private long lastWriteMs = -1;

    /**
     * @param meter the network's byte counts; everything already counted is
     *              treated as accounted for
     * @param file  {@code data-usage[-net].json}, or null for memory only
     */
    public DataUsageLedger(Meter meter, Path file) {
        this(meter, file, LocalDate.now());
    }

    DataUsageLedger(Meter meter, Path file, LocalDate today) {
        this.meter = meter;
        this.file = file;
        this.seen = meter.snapshot();
        this.day = today;
        long[] stored = file != null ? read(file, today) : null;
        if (stored != null) {
            rx = stored[0];
            tx = stored[1];
            meteredRx = stored[2];
            meteredTx = stored[3];
        }
    }

    /** {@code file}'s name for a network: bare on mainnet, suffixed otherwise
     *  (the other per-network files' convention). */
    public static String fileName(String network) {
        return "mainnet".equals(network) ? "data-usage.json" : "data-usage-" + network + ".json";
    }

    /** Account the growth (see the class doc) and write the file when
     *  {@code force}, on a new day, or when {@link #WRITE_EVERY_MS} has passed. */
    public DataUsage tick(boolean force) {
        return tick(LocalDate.now(), metering, force, System.currentTimeMillis());
    }

    synchronized DataUsage tick(LocalDate today, NetworkMetering m, boolean force, long nowMs) {
        long[] now = meter.snapshot();
        long dIn = Math.max(0, (now[0] + now[2]) - (seen[0] + seen[2]));
        long dOut = Math.max(0, (now[1] + now[3]) - (seen[1] + seen[3]));
        seen = now;
        boolean newDay = !today.equals(day);
        if (newDay) {
            // The growth since the last tick lands on the new day: ticks are a
            // minute apart, so at most a minute's bytes cross midnight.
            day = today;
            rx = tx = meteredRx = meteredTx = 0;
            dirty = true;
        }
        if (dIn > 0 || dOut > 0) {
            rx += dIn;
            tx += dOut;
            if (m == NetworkMetering.METERED) {
                meteredRx += dIn;
                meteredTx += dOut;
            }
            dirty = true;
        }
        boolean due = lastWriteMs < 0 || nowMs - lastWriteMs >= WRITE_EVERY_MS;
        if (dirty && file != null && (force || newDay || due)) {
            try {
                write(file, day, rx, tx, meteredRx, meteredTx);
                dirty = false;
                lastWriteMs = nowMs;
            } catch (IOException e) {
                log.debug("[usage] writing {} failed: {}", file, e.toString());
            }
        }
        return new DataUsage(
                now[0] + now[2], now[1] + now[3],
                now[0], now[1], now[2], now[3],
                day.toString(), rx, tx, meteredRx, meteredTx);
    }

    // ---- the file: {"version":1,"day":"YYYY-MM-DD","bytesIn":…,"bytesOut":…,
    //      "meteredBytesIn":…,"meteredBytesOut":…} — the Rust ledger's ----

    private static final Pattern NUM = Pattern.compile("\"(\\w+)\"\\s*:\\s*(\\d+)");
    private static final Pattern DAY = Pattern.compile("\"day\"\\s*:\\s*\"(\\d{4}-\\d{2}-\\d{2})\"");

    /** Today's stored figures {@code {in, out, meteredIn, meteredOut}}, or null
     *  for a missing, damaged or other day's file. */
    static long[] read(Path file, LocalDate today) {
        String s;
        try {
            s = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
        Matcher d = DAY.matcher(s);
        if (!d.find() || !today.toString().equals(d.group(1))) return null;
        Long version = null, in = null, out = null, mIn = null, mOut = null;
        Matcher m = NUM.matcher(s);
        try {
            while (m.find()) {
                long v = Long.parseLong(m.group(2));
                switch (m.group(1)) {
                    case "version" -> version = v;
                    case "bytesIn" -> in = v;
                    case "bytesOut" -> out = v;
                    case "meteredBytesIn" -> mIn = v;
                    case "meteredBytesOut" -> mOut = v;
                    default -> { }
                }
            }
        } catch (NumberFormatException overflow) {
            return null;
        }
        if (version == null || version != 1 || in == null || out == null || mIn == null || mOut == null) {
            return null;
        }
        return new long[] {in, out, mIn, mOut};
    }

    /** Via a temp file + atomic move, so a crash mid-write leaves the old file (or, on
     *  a power loss before the data reached the disk, a damaged one, which is ignored:
     *  today restarts from zero — these are display figures, not state). */
    static void write(Path file, LocalDate day, long in, long out, long mIn, long mOut)
            throws IOException {
        String body = "{\"version\":1,\"day\":\"" + day + "\",\"bytesIn\":" + in
                + ",\"bytesOut\":" + out + ",\"meteredBytesIn\":" + mIn
                + ",\"meteredBytesOut\":" + mOut + "}";
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.write(tmp, body.getBytes(StandardCharsets.UTF_8));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
