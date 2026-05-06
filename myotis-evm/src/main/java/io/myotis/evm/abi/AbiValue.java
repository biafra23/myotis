package io.myotis.evm.abi;

/**
 * Pre-encoded ABI value. {@code dynamic} marks values that occupy variable
 * space in the tail of a head/tail layout.
 *
 * <p>Constructed via the static factories on {@link AbiEncoder}. The byte
 * layout differs by case:
 * <ul>
 *   <li>Static value: exactly 32 bytes — written into the head verbatim.
 *   <li>Dynamic value: the full tail encoding (length-prefixed payload, etc.)
 *       — the head receives an offset pointer instead.
 * </ul>
 */
public record AbiValue(boolean dynamic, byte[] encode) {
    public byte[] encode() { return encode; }
}
