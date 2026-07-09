package io.myotis.engines;

import io.myotis.api.EnsAbiResult;
import io.myotis.api.EnsApi;
import io.myotis.api.EnsContenthashResult;
import io.myotis.api.EnsDnsRecordResult;
import io.myotis.api.EnsInterfaceResult;
import io.myotis.api.EnsMultiCoinResult;
import io.myotis.api.EnsPubkeyResult;
import io.myotis.api.EnsResolutionResult;
import io.myotis.api.EnsRoot;
import io.myotis.api.EnsTextResult;

/**
 * The Rust engine's {@link EnsApi}: forward address resolution is served by the
 * native resolver (registry walk + {@code addr}/ENSIP-10 dispatch over verified
 * eth_calls — EL-C-5-1); every other record type returns a graceful
 * "not implemented" error result until its slice lands (reverse+forward-verify
 * EL-C-5-2, CCIP-Read EL-C-5-3, further record types after). Per the
 * {@link EnsApi} contract, failures are reported in the result record's
 * {@code error} — methods never throw.
 *
 * <p>The {@code root} parameter is currently advisory: the native resolver always
 * runs against the beacon-anchored optimistic head (AUTO-like freshness), so
 * {@code verified} is reported {@code false} — the resolution IS proof-verified
 * against the anchored head, but not against a beacon-FINALIZED root, which is
 * what {@code verified} means in this API. Finalized-root pinning is a later
 * refinement.
 */
final class RustEnsApi implements EnsApi {

    private static final String NOT_IMPLEMENTED =
            "not implemented on the rust engine yet (later EL-C-5 slice)";

    private final RustChainHandle handle;

    RustEnsApi(RustChainHandle handle) {
        this.handle = handle;
    }

    @Override
    public EnsResolutionResult resolveAddress(String name, EnsRoot root) {
        if (name == null || name.isBlank()) {
            return new EnsResolutionResult(name, null, -1, false, "empty ENS name");
        }
        try {
            return handle.resolveEnsVerified(name);
        } catch (RuntimeException e) {
            // EngineException (transport / not running) or any unchecked failure:
            // the EnsApi contract reports failures in the record, never throws.
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new EnsResolutionResult(name, null, -1, false, why);
        }
    }

    @Override
    public EnsResolutionResult reverseResolve(String hexAddress) {
        return new EnsResolutionResult(null, hexAddress, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsTextResult resolveText(String name, String key) {
        return new EnsTextResult(name, key, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsContenthashResult resolveContenthash(String name) {
        return new EnsContenthashResult(name, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsMultiCoinResult resolveMultiCoinAddr(String name, long coinType) {
        return new EnsMultiCoinResult(name, coinType, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsPubkeyResult resolvePubkey(String name) {
        return new EnsPubkeyResult(name, null, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsAbiResult resolveAbi(String name, long contentTypes) {
        return new EnsAbiResult(name, 0, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsDnsRecordResult resolveDnsRecord(String name, String dnsName, int recordType) {
        return new EnsDnsRecordResult(name, dnsName, recordType, null, -1, false, NOT_IMPLEMENTED);
    }

    @Override
    public EnsInterfaceResult resolveInterfaceImplementer(String name, byte[] interfaceId4) {
        return new EnsInterfaceResult(name, null, null, -1, false, NOT_IMPLEMENTED);
    }
}
