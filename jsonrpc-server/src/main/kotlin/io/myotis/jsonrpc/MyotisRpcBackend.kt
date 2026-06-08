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
}
