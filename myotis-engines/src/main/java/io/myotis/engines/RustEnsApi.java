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
 * EL-C-5-2, CCIP-Read EL-C-5-3, further record types after). Resolution failures
 * are reported in the result record's {@code error}; this impl never throws (see
 * the divergence note below).
 *
 * <p>The native resolver always runs against the beacon-anchored optimistic head
 * (AUTO-like freshness), so {@code verified} is reported {@code false} — the
 * resolution IS proof-verified against the anchored head, but not against a
 * beacon-FINALIZED root, which is what {@code verified} means in this API. An
 * explicit {@link EnsRoot#FINALIZED} request is therefore rejected with an error
 * result (never silently downgraded); finalized-root pinning is a later refinement.
 *
 * <p>Deliberate divergence from {@code JavaEnsApi}: that impl throws
 * {@link io.myotis.api.EngineException} for the not-running state (per the EnsApi
 * javadoc), while this one folds EVERY failure — including not-running — into the
 * record's {@code error}. The native layer reports not-running as an error JSON,
 * and distinguishing it by message string would be brittle; IPC consumers handle
 * both shapes identically.
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
        if (root == EnsRoot.FINALIZED) {
            // Fail closed rather than silently serving a weaker root than demanded:
            // this engine resolves against the beacon-anchored OPTIMISTIC head only.
            return new EnsResolutionResult(name, null, -1, false,
                    "finalized-root resolution not supported on the rust engine yet"
                    + " (resolves against the beacon-anchored optimistic head; use AUTO)");
        }
        try {
            return handle.resolveEnsVerified(name);
        } catch (RuntimeException e) {
            // EngineException (transport / not running) or any unchecked failure:
            // THIS impl folds every failure into the record's error (a deliberate
            // divergence from the interface's throw-allowance — class javadoc).
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
        // Echo the queried id like JavaEnsApi does; a malformed id is its own error
        // result (this impl never throws).
        if (interfaceId4 == null || interfaceId4.length != 4) {
            return new EnsInterfaceResult(name, null, null, -1, false,
                    "interfaceId must be exactly 4 bytes");
        }
        StringBuilder hex = new StringBuilder("0x");
        for (byte b : interfaceId4) {
            hex.append(String.format("%02x", b));
        }
        return new EnsInterfaceResult(name, hex.toString(), null, -1, false, NOT_IMPLEMENTED);
    }
}
