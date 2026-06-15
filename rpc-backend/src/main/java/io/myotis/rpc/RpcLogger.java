package io.myotis.rpc;

/**
 * Logging seam for the shared RPC backend. Each host routes it to its own sink:
 * {@code :android-app} to its in-app {@code LogBuffer} (so RPC lines show in the
 * Logs tab), the {@code :app} daemon to slf4j. Keeps the shared backend free of
 * any Android ({@code android.util.Log}) or daemon-specific logging dependency.
 *
 * <p>Methods take a tag + message (and optional throwable) mirroring the common
 * subset of both sinks; levels below info are folded into {@link #info} by
 * default-method, since the backend only emits info/warn in practice.
 */
public interface RpcLogger {

    void info(String message);

    void warn(String message);

    /** Default: route to a no-tag slf4j-style logger that prints nothing. */
    static RpcLogger noop() {
        return new RpcLogger() {
            @Override public void info(String message) { }
            @Override public void warn(String message) { }
        };
    }
}
