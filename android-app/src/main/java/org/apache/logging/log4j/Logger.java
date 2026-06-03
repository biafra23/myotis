package org.apache.logging.log4j;

import org.apache.logging.log4j.util.Supplier;

/**
 * Minimal stand-in for log4j-api's {@code Logger}. Only the method overloads
 * actually invoked by the consensys discovery 26.4.0 jar are declared.
 *
 * <p>Implementations should treat {@code "{}"} placeholders the same way slf4j
 * does (which happens to match log4j 2 message format) so existing call sites
 * just work when their bytecode is dexed against this interface.
 */
public interface Logger {

    void trace(String msg);
    void trace(String fmt, Object a);
    void trace(String fmt, Object a, Object b);
    void trace(String msg, Throwable t);
    void trace(Supplier<?> msgSupplier);
    void trace(Supplier<?> msgSupplier, Throwable t);

    void debug(String msg);
    void debug(String fmt, Object a);
    void debug(String fmt, Object a, Object b);
    void debug(String fmt, Object a, Object b, Object c);
    void debug(String msg, Throwable t);
    void debug(String fmt, Supplier<?>... args);
    void debug(Supplier<?> msgSupplier);

    void info(String msg);
    void info(String fmt, Object a);

    void warn(String msg);
    void warn(String fmt, Object a, Object b);
    void warn(String fmt, Object a, Object b, Object c);

    void error(String fmt, Object a);
    void error(String msg, Throwable t);
}
