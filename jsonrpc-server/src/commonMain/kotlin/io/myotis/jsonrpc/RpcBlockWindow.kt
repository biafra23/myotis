package io.myotis.jsonrpc

/**
 * The block-selector serving window shared by every RpcBackend adapter (the
 * JVM RustVerifiedReads delegates here; the iOS backend calls it directly), so
 * the policy can never drift between hosts: head tags are always servable,
 * `earliest` never is, and a number pin is served from head state only within
 * [BLOCK_NUM_LAG_TOLERANCE] below to [BLOCK_NUM_TOLERANCE] above the anchored
 * head. Sub-second head lag plus a small reorg/announcement margin — outside
 * that, honest data would need historical state we don't hold.
 */
object RpcBlockWindow {

    /** How far ABOVE the anchored head a number-pin is still served. */
    const val BLOCK_NUM_TOLERANCE = 16L

    /** How far BELOW the anchored head a number-pin is still served from head state. */
    const val BLOCK_NUM_LAG_TOLERANCE = 64L

    /**
     * Whether [block] (a JSON-RPC block selector) may be served from head
     * state. [head] is read lazily — only number pins need it; null head =
     * not synced enough to validate a pin.
     */
    fun blockInWindow(block: String?, head: () -> Long?): Boolean {
        if (block.isNullOrBlank()) return true
        val b = block.trim()
        when (b.lowercase()) {
            "latest", "pending", "safe", "finalized" -> return true
            "earliest" -> return false
        }
        val n = if (b.startsWith("0x") || b.startsWith("0X")) {
            b.substring(2).toLongOrNull(16)
        } else {
            b.toLongOrNull()
        } ?: return false
        if (n < 0) return false
        val h = head() ?: return false
        return n >= h - BLOCK_NUM_LAG_TOLERANCE && n <= h + BLOCK_NUM_TOLERANCE
    }
}
