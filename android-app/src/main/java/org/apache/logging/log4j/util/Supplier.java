package org.apache.logging.log4j.util;

/**
 * Stand-in for log4j-api's {@code Supplier}. Only present so we can compile
 * and load the discovery library without dragging in the full log4j-api jar
 * — log4j's {@code LogManager.getLogger()} no-args overload uses
 * {@link java.lang.StackWalker} to derive a logger name, and Android returns
 * null {@code getDeclaringClass()} for some frames so the call throws.
 */
@FunctionalInterface
public interface Supplier<T> {
    T get();
}
