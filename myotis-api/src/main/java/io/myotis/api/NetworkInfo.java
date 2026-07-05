package io.myotis.api;

/**
 * Static metadata for one embedded network — what a host needs to render network
 * pickers and settings without reaching into engine internals.
 *
 * @param name              canonical lowercase name ({@code mainnet}, {@code gnosis}, …)
 * @param displayName       human-facing name ("Ethereum Mainnet", "Gnosis Chain", …)
 * @param chainId           the EVM chain id
 * @param hasEns            whether ENS resolution is available on this chain
 * @param defaultElPort     default RLPx TCP + discv4 UDP port
 * @param defaultDiscv5Port default CL discv5 UDP port
 * @param defaultRpcPort    default verified JSON-RPC HTTP port
 * @param clGenesisTime     beacon-chain genesis time (unix seconds)
 * @param secondsPerSlot    beacon slot time (mainnet preset 12, Gnosis 5)
 */
public record NetworkInfo(
        String name,
        String displayName,
        long chainId,
        boolean hasEns,
        int defaultElPort,
        int defaultDiscv5Port,
        int defaultRpcPort,
        long clGenesisTime,
        int secondsPerSlot) {
}
