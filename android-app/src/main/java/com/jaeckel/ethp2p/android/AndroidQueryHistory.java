package com.jaeckel.ethp2p.android;

import com.jaeckel.ethp2p.android.log.LogBuffer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Persistent most-recent-first history of Query-tab inputs (addresses and ENS
 * names), so the user can re-run a past query with one tap instead of retyping.
 *
 * <p>Follows the {@link AndroidPeerCache} pattern: a filesDir-rooted file,
 * tab-separated UTF-8 lines, synchronized writes. Neither hex addresses nor ENS
 * names contain tabs or newlines, so the format stays unambiguous.
 *
 * <p>Record format: {@code timestampMs\tinput\tlabel\n}. {@code label} is the
 * last thing the input resolved to (e.g. an ENS name's address) or empty for a
 * plain address; it's display sugar only — re-running uses {@code input}.
 */
public final class AndroidQueryHistory {

    private static final String TAG = "ethp2p.qhistory";
    private static final char SEP = '\t';
    /** Cap so the file (and the UI list) can't grow without bound. */
    private static final int MAX_ENTRIES = 50;

    /** One past query. {@code label} may be empty (never null). */
    public record Entry(String input, long timestampMs, String label) {}

    private final Path file;
    // Most-recent-first. Guarded by `this`.
    private final List<Entry> entries = new ArrayList<>();
    private boolean loaded = false;

    public AndroidQueryHistory(Path file) {
        this.file = file;
    }

    /**
     * Record a query input, moving it to the front (de-duplicated by input,
     * case-insensitively — ENS names are case-insensitive and addresses are
     * compared in their hex form). Rewrites the file.
     */
    public synchronized void add(String input, String label) {
        ensureLoaded();
        String trimmed = input == null ? "" : input.strip();
        if (trimmed.isEmpty()) return;
        String safeLabel = label == null ? "" : label.strip();
        entries.removeIf(e -> e.input().equalsIgnoreCase(trimmed));
        entries.add(0, new Entry(trimmed, System.currentTimeMillis(), safeLabel));
        while (entries.size() > MAX_ENTRIES) {
            entries.remove(entries.size() - 1);
        }
        rewrite();
    }

    /** Snapshot of history, most-recent-first. */
    public synchronized List<Entry> list() {
        ensureLoaded();
        return new ArrayList<>(entries);
    }

    public synchronized void clear() {
        entries.clear();
        loaded = true;
        if (!file.toFile().delete() && file.toFile().exists()) {
            LogBuffer.w(TAG, "failed to delete history file " + file);
        }
    }

    private void ensureLoaded() {
        if (loaded) return;
        loaded = true;
        if (!file.toFile().exists()) return;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(file.toFile()), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                int firstSep = line.indexOf(SEP);
                if (firstSep < 0) continue;
                int secondSep = line.indexOf(SEP, firstSep + 1);
                try {
                    long ts = Long.parseLong(line.substring(0, firstSep));
                    String input;
                    String label;
                    if (secondSep < 0) {
                        input = line.substring(firstSep + 1);
                        label = "";
                    } else {
                        input = line.substring(firstSep + 1, secondSep);
                        label = line.substring(secondSep + 1);
                    }
                    if (!input.isEmpty()) entries.add(new Entry(input, ts, label));
                } catch (Exception e) {
                    LogBuffer.w(TAG, "skipping malformed history line");
                }
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "read failed: " + e.getMessage());
        }
    }

    private void rewrite() {
        try (FileOutputStream out = new FileOutputStream(file.toFile(), false)) {
            StringBuilder sb = new StringBuilder();
            for (Entry e : entries) {
                sb.append(e.timestampMs()).append(SEP)
                  .append(e.input()).append(SEP)
                  .append(e.label()).append('\n');
            }
            out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            LogBuffer.w(TAG, "write failed: " + e.getMessage());
        }
    }
}
