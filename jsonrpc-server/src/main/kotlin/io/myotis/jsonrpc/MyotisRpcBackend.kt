package io.myotis.jsonrpc

/**
 * Host-provided access to Myotis's verified light-client state, used by the
 * verified JSON-RPC handlers. Each host (Android `NodeService`, the CLI daemon)
 * implements this by delegating to the same shared `RLPxConnector` /
 * `BeaconSyncState` / EVM primitives it already runs — so the JSON-RPC module
 * stays host-agnostic.
 *
 * Methods return null when the answer isn't available verified (e.g. the beacon
 * light client isn't synced yet); the router then falls back to the upstream
 * proxy (or a strict-mode error). Grows phase by phase — Phase B starts with
 * chain id + verified head.
 */
interface MyotisRpcBackend {

    /** EVM chain id (e.g. 1 for mainnet). Always available (from config). */
    fun chainId(): Long

    /**
     * Verified head execution block number (the beacon optimistic head), or null
     * if not synced enough to answer. Returned to wallets as `eth_blockNumber`.
     */
    fun headBlockNumber(): Long?

    /** "SYNCING" | "CATCHING_UP" | "SYNCED". */
    fun syncState(): String

    // --- Phase B verified reads -------------------------------------------
    // Each takes a JSON-RPC block tag (e.g. "latest"); implementations may
    // honor only the fresh-head tags ("latest"/"pending") for now and return
    // null for anything they can't answer verified (unsupported tag, no peer,
    // head not beacon-anchored), in which case the router proxies. These are
    // BLOCKING (network + EVM round-trips) — the router calls them off the IO
    // dispatcher, never on a Java `suspend` boundary, so they stay plain.

    /**
     * eth_call: run [data] against contract [to] in a local EVM over verified
     * state, returning the raw ABI return bytes. Null falls through to the proxy.
     */
    fun call(to: ByteArray, data: ByteArray, block: String): ByteArray?

    /** eth_getBalance: account balance in wei, or null to proxy. */
    fun getBalance(address: ByteArray, block: String): java.math.BigInteger?

    /** eth_getTransactionCount: account nonce, or null to proxy. */
    fun getTransactionCount(address: ByteArray, block: String): Long?
}
