package io.myotis.api;

/**
 * ENS resolution over the local EVM against proof-served state — ENSIP-1 +
 * ENSIP-10 (wildcard) with transparent CCIP-Read (ERC-3668) for off-chain names.
 *
 * <p>All methods are blocking (worker thread; internally timeout-bounded, worst
 * case ~2 min for a cold CCIP name). Resolution failures set the result record's
 * {@code error}; only malformed input / not-running throw {@link EngineException}.
 * {@code verified} is true iff the resolution ran against beacon-finalized state.
 */
public interface EnsApi {

    /** Forward-resolve {@code name} to an address. */
    EnsResolutionResult resolveAddress(String name, EnsRoot root);

    /**
     * Reverse-resolve an address to its primary name, with mandatory
     * forward-verification (the claimed name must resolve back to the address).
     */
    EnsResolutionResult reverseResolve(String hexAddress);

    /** ENSIP-5 text record. */
    EnsTextResult resolveText(String name, String key);

    /** ENSIP-7 contenthash. */
    EnsContenthashResult resolveContenthash(String name);

    /** ENSIP-9 multi-coin address (SLIP-44 coin type). */
    EnsMultiCoinResult resolveMultiCoinAddr(String name, long coinType);

    /** ENSIP-? pubkey record (secp256k1 x/y). */
    EnsPubkeyResult resolvePubkey(String name);

    /** ABI record (ENSIP-4); {@code contentTypes} is the accepted-encodings bitmask. */
    EnsAbiResult resolveAbi(String name, long contentTypes);

    /** DNS record stored in ENS (ENSIP-6). */
    EnsDnsRecordResult resolveDnsRecord(String name, String dnsName, int recordType);

    /** ERC-165 interface implementer record. */
    EnsInterfaceResult resolveInterfaceImplementer(String name, byte[] interfaceId4);

    /**
     * Who holds {@code name} and until when (registry owner and resolver; for a
     * {@code .eth} second-level name the registrar's registrant, expiry and grace
     * period), seen through the NameWrapper where it is the holder. Same root policy
     * as the record reads (finalized first). Default: an engine that has not
     * implemented it answers a refusal in {@code error}, never a guess.
     */
    default EnsOwnershipResult resolveOwnership(String name) {
        return new EnsOwnershipResult(name, null, null, false, null, -1, -1, -1, -1, false,
                "this engine does not read ENS ownership");
    }
}
