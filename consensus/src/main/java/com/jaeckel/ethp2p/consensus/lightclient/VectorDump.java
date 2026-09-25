package com.jaeckel.ethp2p.consensus.lightclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Conformance-vector capture: when {@code -Dmyotis.lc.dumpVectors=<dir>} is set, every
 * raw light-client SSZ message the client is about to decode (bootstrap, catch-up
 * update, finality update) is also written to {@code <dir>} verbatim. The committed
 * vectors under {@code rust/testdata/lc/} were captured this way from live mainnet;
 * the Java replay test and (from plan PR 4) the Rust light client must reach identical
 * verdicts on them.
 *
 * <p>Off by default and effectively free when off (one static null check). Never
 * throws: a capture failure logs and drops the vector — it must not disturb a live
 * sync, which is the source of truth being observed. Writes are handed to a
 * single-threaded background writer: some capture sites run on libp2p callback /
 * catch-up executor threads, which must not eat disk latency even in debug runs.
 * The sequence number is taken synchronously, so file order = capture order.
 */
public final class VectorDump {

    private static final Logger log = LoggerFactory.getLogger(VectorDump.class);
    private static final Path DIR;
    private static final AtomicInteger SEQ = new AtomicInteger();
    /** Daemon thread: capture must never keep a shutting-down JVM alive. */
    private static final ExecutorService WRITER = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "lc-vector-dump");
        t.setDaemon(true);
        return t;
    });

    static {
        String dir = System.getProperty("myotis.lc.dumpVectors");
        Path p = null;
        if (dir != null && !dir.isBlank()) {
            try {
                // Per-run subdirectory: SEQ restarts at 1 in every JVM, so dumping runs
                // into one flat dir would overwrite/interleave sessions — a curation
                // footgun for the committed corpus. Each run gets its own dir instead.
                p = Paths.get(dir).resolve("run-" + (System.currentTimeMillis() / 1000L));
                Files.createDirectories(p);
                log.info("[lc-dump] capturing light-client SSZ vectors to {}", p.toAbsolutePath());
            } catch (Exception e) {
                log.warn("[lc-dump] cannot create dump dir {}: {}", dir, e.getMessage());
                p = null;
            }
        }
        DIR = p;
    }

    private VectorDump() {}

    /**
     * Write one raw SSZ message as {@code <seq>-<kind>.ssz}. {@code kind} is one of
     * {@code bootstrap}, {@code update}, {@code finality}. No-op unless enabled.
     */
    public static void maybeDump(String kind, byte[] ssz) {
        if (DIR == null || ssz == null) return;
        // Sequence assigned on the CALLING thread so filename order matches the order
        // the client actually observed the messages, regardless of writer scheduling.
        int seq = SEQ.incrementAndGet();
        byte[] copy = ssz.clone(); // caller may reuse/mutate its buffer after we return
        WRITER.execute(() -> {
            try {
                Files.write(DIR.resolve(String.format("%04d-%s.ssz", seq, kind)), copy);
            } catch (Exception e) {
                log.warn("[lc-dump] failed to write {} vector: {}", kind, e.getMessage());
            }
        });
    }
}
