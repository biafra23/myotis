package org.apache.logging.log4j;

import org.apache.logging.log4j.util.Supplier;

/**
 * Routes {@link Logger} calls to slf4j. Lazy {@link Supplier} args are
 * resolved only when the corresponding level is enabled, matching log4j-api's
 * own behaviour.
 *
 * <p>log4j 2 and slf4j both use {@code "{}"} placeholders, so format strings
 * pass through unchanged.
 */
final class Slf4jBackedLogger implements Logger {

    private final org.slf4j.Logger inner;

    Slf4jBackedLogger(org.slf4j.Logger inner) {
        this.inner = inner;
    }

    // ----- TRACE -----
    @Override public void trace(String msg) { inner.trace(msg); }
    @Override public void trace(String fmt, Object a) { inner.trace(fmt, a); }
    @Override public void trace(String fmt, Object a, Object b) { inner.trace(fmt, a, b); }
    @Override public void trace(String msg, Throwable t) { inner.trace(msg, t); }
    @Override public void trace(Supplier<?> msgSupplier) {
        if (inner.isTraceEnabled()) inner.trace(String.valueOf(msgSupplier.get()));
    }
    @Override public void trace(Supplier<?> msgSupplier, Throwable t) {
        if (inner.isTraceEnabled()) inner.trace(String.valueOf(msgSupplier.get()), t);
    }

    // ----- DEBUG -----
    @Override public void debug(String msg) { inner.debug(msg); }
    @Override public void debug(String fmt, Object a) { inner.debug(fmt, a); }
    @Override public void debug(String fmt, Object a, Object b) { inner.debug(fmt, a, b); }
    @Override public void debug(String fmt, Object a, Object b, Object c) { inner.debug(fmt, a, b, c); }
    @Override public void debug(String msg, Throwable t) { inner.debug(msg, t); }
    @Override public void debug(String fmt, Supplier<?>... args) {
        if (!inner.isDebugEnabled()) return;
        inner.debug(fmt, resolve(args));
    }
    @Override public void debug(Supplier<?> msgSupplier) {
        if (inner.isDebugEnabled()) inner.debug(String.valueOf(msgSupplier.get()));
    }

    // ----- INFO -----
    @Override public void info(String msg) { inner.info(msg); }
    @Override public void info(String fmt, Object a) { inner.info(fmt, a); }

    // ----- WARN -----
    @Override public void warn(String msg) { inner.warn(msg); }
    @Override public void warn(String fmt, Object a, Object b) { inner.warn(fmt, a, b); }
    @Override public void warn(String fmt, Object a, Object b, Object c) { inner.warn(fmt, a, b, c); }

    // ----- ERROR -----
    @Override public void error(String fmt, Object a) { inner.error(fmt, a); }
    @Override public void error(String msg, Throwable t) { inner.error(msg, t); }

    private static Object[] resolve(Supplier<?>[] args) {
        if (args == null) return new Object[0];
        Object[] out = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            out[i] = args[i] == null ? null : args[i].get();
        }
        return out;
    }
}
