package io.myotis.rpc;

/**
 * Result of a verified ENS forward resolution (name → address), shared by the
 * daemon and the Android UI so the resolution policy lives in one place
 * ({@link VerifiedRpcBackend#resolveEns}).
 *
 * @param name        the (trimmed) name that was resolved
 * @param addressHex  the resolved 0x-address, or {@code null} when unresolved/errored
 * @param blockNumber the execution block the resolution ran against, or -1 when none
 * @param verified    true iff resolved against beacon-verified state (FINALIZED);
 *                    false for a fresher-but-peer-claimed PEER_HEAD answer
 * @param error       a human-readable failure reason, or {@code null} on success
 */
public record EnsResolution(String name, String addressHex, long blockNumber,
                            boolean verified, String error) {}
