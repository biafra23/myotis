package com.jaeckel.ethp2p.android.log;

import org.slf4j.ILoggerFactory;
import org.slf4j.IMarkerFactory;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.BasicMDCAdapter;
import org.slf4j.helpers.BasicMarkerFactory;
import org.slf4j.helpers.LegacyAbstractLogger;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.spi.MDCAdapter;
import org.slf4j.spi.SLF4JServiceProvider;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * SLF4J 2.x service provider that captures every log call from the
 * consensus / networking / libp2p stack. Each call is teed to:
 * <ul>
 *   <li>{@code android.util.Log} — so {@code adb logcat} keeps working,</li>
 *   <li>{@link LogBuffer} — so the in-app Logs tab can render it.</li>
 * </ul>
 *
 * <p>Registered via {@code META-INF/services/org.slf4j.spi.SLF4JServiceProvider}.
 * Replaces the previous {@code slf4j-simple} runtime binding (which wrote
 * to stderr — invisible on Android and unreachable from the UI process).
 */
public final class AppSlf4jProvider implements SLF4JServiceProvider {

    /** Must be a prefix of the slf4j-api version on the classpath. */
    public static final String REQUESTED_API_VERSION = "2.0.99";

    /**
     * Minimum level captured (logcat + {@link LogBuffer}); calls below it are dropped. TRACE is
     * always suppressed regardless (libp2p floods it). Defaults to DEBUG — capture everything
     * above trace, matching the historical behavior — and the Logs tab can raise it to quiet the
     * ring. Volatile: read on every log call, written from the UI thread.
     */
    private static volatile Level minLevel = Level.DEBUG;

    /** Set the minimum captured level (from the Logs tab). Ignores null so the volatile can never
     *  go null and NPE the hot-path read on the next log call. */
    public static void setMinLevel(Level level) { if (level != null) minLevel = level; }

    /** The current minimum captured level. */
    public static Level minLevel() { return minLevel; }

    private final ILoggerFactory loggerFactory = new AppLoggerFactory();
    private final IMarkerFactory markerFactory = new BasicMarkerFactory();
    private final MDCAdapter mdcAdapter = new BasicMDCAdapter();

    @Override public ILoggerFactory getLoggerFactory() { return loggerFactory; }
    @Override public IMarkerFactory getMarkerFactory() { return markerFactory; }
    @Override public MDCAdapter getMDCAdapter() { return mdcAdapter; }
    @Override public String getRequestedApiVersion() { return REQUESTED_API_VERSION; }
    @Override public void initialize() { /* nothing to bootstrap */ }

    static final class AppLoggerFactory implements ILoggerFactory {
        private final ConcurrentMap<String, Logger> cache = new ConcurrentHashMap<>();
        @Override public Logger getLogger(String name) {
            return cache.computeIfAbsent(name, AppLogger::new);
        }
    }

    static final class AppLogger extends LegacyAbstractLogger {
        private static final long serialVersionUID = 1L;

        AppLogger(String name) {
            this.name = name;
        }

        // Level gating is a single process-wide threshold (minLevel), adjustable live from the
        // Logs tab. TRACE is *always* suppressed because libp2p is very chatty at trace level and
        // would dominate the ring buffer.
        @Override public boolean isTraceEnabled() { return false; }
        @Override public boolean isDebugEnabled() { return enabled(Level.DEBUG); }
        @Override public boolean isInfoEnabled()  { return enabled(Level.INFO); }
        @Override public boolean isWarnEnabled()  { return enabled(Level.WARN); }
        @Override public boolean isErrorEnabled() { return enabled(Level.ERROR); }

        private static boolean enabled(Level level) {
            return level != Level.TRACE && level.toInt() >= minLevel.toInt();
        }

        @Override
        protected String getFullyQualifiedCallerName() {
            return AppLogger.class.getName();
        }

        @Override
        protected void handleNormalizedLoggingCall(Level level, Marker marker,
                                                   String messagePattern,
                                                   Object[] arguments,
                                                   Throwable throwable) {
            // Belt-and-suspenders: LegacyAbstractLogger already gates on isXEnabled(), but drop
            // anything below the threshold (or TRACE) here too so no path bypasses it.
            if (level == Level.TRACE || level.toInt() < minLevel.toInt()) return;
            String formatted = MessageFormatter.basicArrayFormat(messagePattern, arguments);

            // Tee to logcat so `adb logcat` continues to work.
            int prio = switch (level) {
                case TRACE -> android.util.Log.VERBOSE;
                case DEBUG -> android.util.Log.DEBUG;
                case INFO  -> android.util.Log.INFO;
                case WARN  -> android.util.Log.WARN;
                case ERROR -> android.util.Log.ERROR;
            };
            String shortTag = shortenTagForLogcat(name);
            if (throwable != null) {
                android.util.Log.println(prio, shortTag,
                        formatted + "\n" + android.util.Log.getStackTraceString(throwable));
            } else {
                android.util.Log.println(prio, shortTag, formatted);
            }

            // Ring buffer keeps the full logger name so the in-app viewer
            // can show "BeaconLightClient" rather than the truncated tag.
            char ch = switch (level) {
                case TRACE -> 'V';
                case DEBUG -> 'D';
                case INFO  -> 'I';
                case WARN  -> 'W';
                case ERROR -> 'E';
            };
            LogBuffer.append(ch, name, formatted, throwable);
        }

        /**
         * Logcat tags are capped at 23 chars on API 25 and earlier; some
         * device manufacturers still enforce that on newer versions.
         * Strip the package and truncate.
         */
        private static String shortenTagForLogcat(String loggerName) {
            int dot = loggerName.lastIndexOf('.');
            String simple = dot >= 0 ? loggerName.substring(dot + 1) : loggerName;
            return simple.length() > 23 ? simple.substring(0, 23) : simple;
        }
    }
}
