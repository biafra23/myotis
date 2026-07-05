package io.myotis.node.api;

import io.myotis.api.EngineException;
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
import io.myotis.node.ChainStack;
import io.myotis.rpc.EnsResolution;
import io.myotis.rpc.VerifiedRpcBackend;

import java.util.concurrent.TimeUnit;

/**
 * The JVM {@link EnsApi}: forward resolution delegates to the backend's shared resolution
 * policy ({@link VerifiedRpcBackend#resolveEns}). The record-type lookups (text, contenthash,
 * multi-coin, …) are wired when the ENS record service moves out of the daemon's
 * CommandHandler into node-core (plan step PR2); nothing calls them until the hosts are
 * rewired in PR3.
 */
final class JavaEnsApi implements EnsApi {

    /** Worst-case forward resolution: peer probing + EVM + CCIP gateway round-trips. */
    private static final long RESOLVE_TIMEOUT_SEC = 150;

    private final ChainStack stack;

    JavaEnsApi(ChainStack stack) {
        this.stack = stack;
    }

    @Override
    public EnsResolutionResult resolveAddress(String name, EnsRoot root) {
        VerifiedRpcBackend backend = stack.rpcBackend();
        if (backend == null) {
            return new EnsResolutionResult(name, null, -1, false, "node not running");
        }
        try {
            EnsResolution r = backend.resolveEns(
                            name, io.myotis.ens.EnsResolutionRoot.valueOf(root.name()))
                    .get(RESOLVE_TIMEOUT_SEC, TimeUnit.SECONDS);
            return new EnsResolutionResult(r.name(), r.addressHex(), r.blockNumber(),
                    r.verified(), r.error());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new EnsResolutionResult(name, null, -1, false, "interrupted");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return new EnsResolutionResult(name, null, -1, false,
                    cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName());
        }
    }

    @Override
    public EnsResolutionResult reverseResolve(String hexAddress) {
        throw notYetWired("reverseResolve");
    }

    @Override
    public EnsTextResult resolveText(String name, String key) {
        throw notYetWired("resolveText");
    }

    @Override
    public EnsContenthashResult resolveContenthash(String name) {
        throw notYetWired("resolveContenthash");
    }

    @Override
    public EnsMultiCoinResult resolveMultiCoinAddr(String name, long coinType) {
        throw notYetWired("resolveMultiCoinAddr");
    }

    @Override
    public EnsPubkeyResult resolvePubkey(String name) {
        throw notYetWired("resolvePubkey");
    }

    @Override
    public EnsAbiResult resolveAbi(String name, long contentTypes) {
        throw notYetWired("resolveAbi");
    }

    @Override
    public EnsDnsRecordResult resolveDnsRecord(String name, String dnsName, int recordType) {
        throw notYetWired("resolveDnsRecord");
    }

    @Override
    public EnsInterfaceResult resolveInterfaceImplementer(String name, byte[] interfaceId4) {
        throw notYetWired("resolveInterfaceImplementer");
    }

    private static EngineException notYetWired(String method) {
        return new EngineException(method
                + ": not yet wired (lands with the engine-logic motion PR)");
    }
}
