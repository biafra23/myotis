package com.jaeckel.ethp2p.android.log;

import androidx.annotation.GuardedBy;
import androidx.annotation.Nullable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-process bounded ring buffer of log records, fed by both
 * {@code android.util.Log} (via the public tee helpers on this class) and
 * SLF4J (via {@link AppSlf4jProvider}). Read by the in-app Logs tab.
 *
 * <p>Reads are O(n) snapshot copies; writes are constant-time. A monotonic
 * version counter is bumped on every mutation so the UI can poll cheaply
 * for change without comparing buffer contents.
 */
public final class LogBuffer {

    /** Capacity of the ring buffer. ~3 MB at typical 600-char lines. */
    public static final int MAX_LINES = 5000;

    /**
     * @param sequence monotonic id assigned at append time. Stable across
     *                 ring-buffer rotation — used by the in-app viewer as
     *                 the LazyColumn item key so scroll position survives
     *                 entries falling off the front.
     */
    public record Entry(long sequence, long timestampMillis, char level,
                        String tag, String message) {}

    private static final Object LOCK = new Object();
    @GuardedBy("LOCK")
    private static final ArrayDeque<Entry> BUFFER = new ArrayDeque<>(MAX_LINES);
    private static final AtomicLong VERSION = new AtomicLong();
    private static final AtomicLong SEQUENCE = new AtomicLong();

    private LogBuffer() {}

    /** Monotonic counter; bumps on every append or clear. */
    public static long version() {
        return VERSION.get();
    }

    /** Snapshot of the buffer in chronological (oldest-first) order. */
    public static List<Entry> snapshot() {
        synchronized (LOCK) {
            return new ArrayList<>(BUFFER);
        }
    }

    public static void clear() {
        synchronized (LOCK) {
            BUFFER.clear();
        }
        VERSION.incrementAndGet();
    }

    /** Append a record. Called from the SLF4J provider and the Log tee helpers. */
    public static void append(char level, String tag, String message, @Nullable Throwable t) {
        String full = (t == null) ? message
                : message + "\n" + android.util.Log.getStackTraceString(t);
        Entry entry = new Entry(SEQUENCE.incrementAndGet(),
                System.currentTimeMillis(), level, tag, full);
        synchronized (LOCK) {
            BUFFER.addLast(entry);
            while (BUFFER.size() > MAX_LINES) BUFFER.pollFirst();
        }
        VERSION.incrementAndGet();
    }

    // -------- tee helpers replacing android.util.Log inside the app -------
    //
    // Call sites that previously used `android.util.Log` switch to
    // `LogBuffer` so their output appears in both logcat and the in-app
    // Logs tab. Logger output from the consensus/networking modules
    // (slf4j) is captured by AppSlf4jProvider directly — there's no need
    // to touch those call sites.

    public static void v(String tag, String msg) {
        android.util.Log.v(tag, msg);
        append('V', tag, msg, null);
    }
    public static void d(String tag, String msg) {
        android.util.Log.d(tag, msg);
        append('D', tag, msg, null);
    }
    public static void i(String tag, String msg) {
        android.util.Log.i(tag, msg);
        append('I', tag, msg, null);
    }
    public static void w(String tag, String msg) {
        android.util.Log.w(tag, msg);
        append('W', tag, msg, null);
    }
    public static void w(String tag, String msg, Throwable t) {
        android.util.Log.w(tag, msg, t);
        append('W', tag, msg, t);
    }
    public static void e(String tag, String msg) {
        android.util.Log.e(tag, msg);
        append('E', tag, msg, null);
    }
    public static void e(String tag, String msg, Throwable t) {
        android.util.Log.e(tag, msg, t);
        append('E', tag, msg, t);
    }
}
