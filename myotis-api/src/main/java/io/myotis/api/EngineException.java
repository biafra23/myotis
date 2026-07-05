package io.myotis.api;

/**
 * The only exception type the engine API throws — reserved for programmer/state
 * errors (unknown network, malformed address, network not running). Verification
 * failures are never exceptions; they surface as {@code failReason}/{@code error}
 * fields on result records.
 */
public class EngineException extends RuntimeException {

    public EngineException(String message) {
        super(message);
    }

    public EngineException(String message, Throwable cause) {
        super(message, cause);
    }
}
