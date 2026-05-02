package org.apache.logging.log4j;

/**
 * Minimal stand-in for log4j-api's {@code LogManager}. The real one's
 * {@code getLogger()} no-args overload uses {@link java.lang.StackWalker}
 * to derive the caller class name, and on Android the walker returns null
 * {@code getDeclaringClass()} for some frames — so log4j throws
 * {@code UnsupportedOperationException} during static init of every
 * discovery class that has a {@code static final Logger LOG = LogManager.getLogger();}.
 *
 * <p>Here {@code getLogger()} just defaults to a fixed name and skips the
 * stack walk entirely. Names are routed to slf4j (which the Android app
 * already binds to slf4j-simple).
 */
public final class LogManager {

    private LogManager() {}

    public static Logger getLogger() {
        return new Slf4jBackedLogger(org.slf4j.LoggerFactory.getLogger("log4j-default"));
    }

    public static Logger getLogger(Class<?> clazz) {
        return new Slf4jBackedLogger(org.slf4j.LoggerFactory.getLogger(
                clazz != null ? clazz : LogManager.class));
    }

    public static Logger getLogger(String name) {
        return new Slf4jBackedLogger(org.slf4j.LoggerFactory.getLogger(
                name != null ? name : "log4j-default"));
    }
}
