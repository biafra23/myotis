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
import org.apache.tuweni.bytes.Bytes;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * The JVM {@link EnsApi}: every lookup delegates to {@link VerifiedRpcBackend}'s shared
 * resolution machinery (peer probe + pinned-root EVM stack + AUTO ladder), so the policy
 * lives once in the engine. This class only blocks on the futures and maps the backend
 * records onto the flat API result shapes.
 */
final class JavaEnsApi implements EnsApi {

    /** Worst-case resolution: peer probing + EVM + CCIP gateway round-trips. */
    private static final long RESOLVE_TIMEOUT_SEC = 150;

    private final ChainStack stack;

    JavaEnsApi(ChainStack stack) {
        this.stack = stack;
    }

    private VerifiedRpcBackend backend() {
        VerifiedRpcBackend backend = stack.rpcBackend();
        if (backend == null) throw new EngineException("node not running (RPC backend not started)");
        return backend;
    }

    /** The backend's internal marker for a successful empty forward resolution. */
    private static final String BACKEND_NO_RECORD = "name does not resolve";

    @Override
    public EnsResolutionResult resolveAddress(String name, EnsRoot root) {
        // backend() throws EngineException when not running — the same state-error
        // convention as every other method here (per the EnsApi contract).
        VerifiedRpcBackend backend = backend();
        try {
            EnsResolution r = backend.resolveEns(name, toEngineRoot(root))
                    .get(RESOLVE_TIMEOUT_SEC, TimeUnit.SECONDS);
            // Normalize to the API's record convention (same as every EnsApi record
            // lookup): a successful "no such record" is value==null && error==null.
            // The backend folds that case into an error string; unfold it HERE so no
            // consumer ever has to match the magic text.
            String error = BACKEND_NO_RECORD.equals(r.error()) ? null : r.error();
            return new EnsResolutionResult(r.name(), r.addressHex(), r.blockNumber(),
                    r.verified(), error);
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
        byte[] addr20;
        try {
            String hex = hexAddress != null && (hexAddress.startsWith("0x") || hexAddress.startsWith("0X"))
                    ? hexAddress.substring(2) : hexAddress;
            if (hex == null || hex.length() != 40) {
                throw new IllegalArgumentException("address must be a 20-byte hex string (40 hex chars)");
            }
            addr20 = Bytes.fromHexString(hex).toArrayUnsafe();
        } catch (Exception e) {
            throw new EngineException(e.getMessage() != null ? e.getMessage() : "invalid address", e);
        }
        VerifiedRpcBackend.EnsRecord<String> r = await(
                backend().reverseResolveEns(addr20, io.myotis.ens.EnsResolutionRoot.AUTO));
        // value = the forward-verified primary name (resolveName enforces ENSIP-3).
        return new EnsResolutionResult(r.value(), hexAddress, r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsTextResult resolveText(String name, String key) {
        VerifiedRpcBackend.EnsRecord<String> r = await(
                backend().resolveEnsText(name, key, io.myotis.ens.EnsResolutionRoot.AUTO));
        return new EnsTextResult(name, key, r.value(), r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsContenthashResult resolveContenthash(String name) {
        VerifiedRpcBackend.EnsRecord<byte[]> r = await(
                backend().resolveEnsContenthash(name, io.myotis.ens.EnsResolutionRoot.AUTO));
        return new EnsContenthashResult(name, hexOrNull(r.value()),
                r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsMultiCoinResult resolveMultiCoinAddr(String name, long coinType) {
        VerifiedRpcBackend.EnsRecord<byte[]> r = await(
                backend().resolveEnsMultiCoinAddr(name, coinType, io.myotis.ens.EnsResolutionRoot.AUTO));
        return new EnsMultiCoinResult(name, coinType, hexOrNull(r.value()),
                r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsPubkeyResult resolvePubkey(String name) {
        VerifiedRpcBackend.EnsRecord<io.myotis.ens.EnsResolver.Pubkey> r = await(
                backend().resolveEnsPubkey(name, io.myotis.ens.EnsResolutionRoot.AUTO));
        io.myotis.ens.EnsResolver.Pubkey pk = r.value();
        return new EnsPubkeyResult(name,
                pk != null ? Bytes.wrap(pk.x()).toHexString() : null,
                pk != null ? Bytes.wrap(pk.y()).toHexString() : null,
                r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsAbiResult resolveAbi(String name, long contentTypes) {
        VerifiedRpcBackend.EnsRecord<io.myotis.ens.EnsResolver.AbiRecord> r = await(
                backend().resolveEnsAbi(name, contentTypes, io.myotis.ens.EnsResolutionRoot.AUTO));
        io.myotis.ens.EnsResolver.AbiRecord rec = r.value();
        return new EnsAbiResult(name,
                rec != null ? rec.contentType() : 0,
                rec != null ? Bytes.wrap(rec.data()).toHexString() : null,
                r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsDnsRecordResult resolveDnsRecord(String name, String dnsName, int recordType) {
        byte[] dnsNameWire;
        try {
            dnsNameWire = io.myotis.ens.DnsEncoder.encode(dnsName);
        } catch (Exception e) {
            throw new EngineException("invalid DNS name: " + e.getMessage(), e);
        }
        VerifiedRpcBackend.EnsRecord<byte[]> r = await(
                backend().resolveEnsDnsRecord(name, dnsNameWire, recordType,
                        io.myotis.ens.EnsResolutionRoot.AUTO));
        return new EnsDnsRecordResult(name, dnsName, recordType, hexOrNull(r.value()),
                r.blockNumber(), r.verified(), r.error());
    }

    @Override
    public EnsInterfaceResult resolveInterfaceImplementer(String name, byte[] interfaceId4) {
        if (interfaceId4 == null || interfaceId4.length != 4) {
            throw new EngineException("interfaceId must be exactly 4 bytes");
        }
        VerifiedRpcBackend.EnsRecord<io.myotis.evm.Address> r = await(
                backend().resolveEnsInterfaceImplementer(name, interfaceId4,
                        io.myotis.ens.EnsResolutionRoot.AUTO));
        return new EnsInterfaceResult(name, Bytes.wrap(interfaceId4).toHexString(),
                r.value() != null ? r.value().toHex() : null,
                r.blockNumber(), r.verified(), r.error());
    }

    /** Block on a backend record future, folding interruption/timeouts into the record's
     *  error convention (never throwing for resolution failures). */
    private static <T> VerifiedRpcBackend.EnsRecord<T> await(
            CompletableFuture<VerifiedRpcBackend.EnsRecord<T>> future) {
        try {
            return future.get(RESOLVE_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new VerifiedRpcBackend.EnsRecord<>(null, -1, false, "interrupted");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return new VerifiedRpcBackend.EnsRecord<>(null, -1, false,
                    cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName());
        }
    }

    private static String hexOrNull(byte[] value) {
        return value == null ? null : Bytes.wrap(value).toHexString();
    }

    private static io.myotis.ens.EnsResolutionRoot toEngineRoot(EnsRoot root) {
        return io.myotis.ens.EnsResolutionRoot.valueOf(
                (root == null ? EnsRoot.AUTO : root).name());
    }
}
