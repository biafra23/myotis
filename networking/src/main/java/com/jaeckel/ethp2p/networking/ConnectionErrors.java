package com.jaeckel.ethp2p.networking;

import java.io.IOException;
import java.net.PortUnreachableException;
import java.nio.channels.ClosedChannelException;
import java.util.Locale;

/**
 * Classifies the routine peer-churn disconnects that flood the wire handlers' {@code
 * exceptionCaught} at ERROR-with-stacktrace even though nothing is wrong. Peers drop constantly
 * during normal discovery/sync — {@code java.net.SocketException: Connection reset}, broken pipe,
 * a half-open socket timing out, a UDP port-unreachable — and each currently prints a full
 * stacktrace at ERROR. Those should be a one-line DEBUG instead, leaving ERROR for genuinely
 * unexpected failures.
 */
public final class ConnectionErrors {

    private ConnectionErrors() {}

    /** Bound the cause-chain walk so a pathological cyclic chain can't hang the event loop. */
    private static final int MAX_CAUSE_DEPTH = 32;

    /**
     * True if {@code t} (or any cause in its chain) is a benign transport-level disconnect —
     * connection reset / reset by peer, broken pipe, a connection/read timeout, the OS forcibly
     * closing the socket, a closed channel, or a UDP port-unreachable. Genuine protocol/decode
     * failures return false so they keep logging at ERROR with a stacktrace.
     *
     * <p>The message substrings are JDK/OS wording (not API contract), so this is best-effort —
     * but it's gated on {@link IOException}, so a wording drift only mis-classifies a transport
     * error, never a protocol/logic bug.
     */
    public static boolean isBenignDisconnect(Throwable t) {
        int depth = 0;
        for (Throwable c = t; c != null && depth < MAX_CAUSE_DEPTH; c = c.getCause(), depth++) {
            if (c instanceof ClosedChannelException) return true;
            if (c instanceof PortUnreachableException) return true;
            if (c instanceof IOException) {   // SocketException / SocketTimeoutException are IOExceptions
                String m = c.getMessage();
                if (m != null) {
                    String lm = m.toLowerCase(Locale.ROOT);
                    if (lm.contains("connection reset")
                            || lm.contains("reset by peer")
                            || lm.contains("broken pipe")
                            || lm.contains("timed out")            // ETIMEDOUT + SocketTimeoutException
                            || lm.contains("connection or inbound has closed")
                            || lm.contains("forcibly closed")) {   // Windows wording
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * A short, single-line description of {@code t} for DEBUG logging — the root cause's message
     * (e.g. "Connection reset"), falling back to its simple class name when there is no message.
     * No stacktrace. The walk is depth-bounded so a cyclic cause chain can't loop forever.
     */
    public static String describe(Throwable t) {
        Throwable root = t;
        int depth = 0;
        while (root.getCause() != null && root.getCause() != root && depth < MAX_CAUSE_DEPTH) {
            root = root.getCause();
            depth++;
        }
        String m = root.getMessage();
        return m != null ? m : root.getClass().getSimpleName();
    }
}
