package io.myotis.api.ports;

/** The engine's log sink (Android routes to its in-app buffer, desktop to slf4j). */
public interface EngineLogger {

    void info(String message);

    void warn(String message);

    void error(String message);
}
