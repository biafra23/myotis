package io.myotis.api;

/**
 * The verified eth_* read surface — every method is answered ONLY from
 * cryptographically verified data. {@code null} means "cannot answer verified
 * right now" (not synced / no peer / head not anchored); the host maps that to a
 * JSON-RPC error in strict mode. The engine never proxies an unverified answer.
 *
 * <p>Methods returning JSON strings ({@code getTransactionReceipt},
 * {@code getBlockByNumber}, …) use the tri-state convention: a JSON object, the
 * literal {@code "null"} (a <em>verified</em> "not found" — e.g. an unknown tx on
 * a synced chain), or {@code null} (no verified answer).
 *
 * <p>JSON-string read methods may additionally return a single-key
 * {@code {"error": "..."}} envelope in place of a bare {@code null} when the
 * failure carries a reason worth surfacing to the caller (the RPC router turns
 * it into a -32000 with that reason; {@code getLogs} pioneered the shape for
 * index-coverage errors — that method keeps its own, looser envelope contract).
 * A bare {@code null} stays valid and maps to the generic retryable error.
 * Both engines — and every host backend, iOS included — implement the same
 * convention: diagnostics must not depend on the engine toggle or the host.
 *
 * <p>All methods are blocking; call from a worker thread. Block selectors are
 * strings: {@code "latest"}, {@code "pending"}, or a 0x-hex block number.
 */
public interface VerifiedReads {

    /** The chain id (static config; never null). */
    long chainId();

    /** Beacon optimistic-head block number, or null when not synced enough. */
    Long headBlockNumber();

    /** The beacon light client's sync state. */
    SyncState syncState();

    /**
     * eth_call against proof-served state in the local EVM. {@code from} may be
     * null (zero sender — reverts {@code msg.sender}-gated contracts, as geth
     * does); {@code valueWei} decimal or null for zero.
     *
     * <p>{@code to} may be null: that is CONTRACT CREATION, where {@code data}
     * is init code and the constructor's return data is the result (geth's
     * behaviour for a {@code to}-less call). Engines that cannot serve it must
     * report {@link #supportsContractCreation()} false rather than relying on a
     * null-{@code to} guard, so hosts can refuse without dispatching.
     *
     * @return ABI return bytes, or null when unanswerable verified
     */
    byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block);

    /**
     * Whether this engine can APPLY {@code eth_call} state overrides.
     *
     * <p>Needed because {@link #callWithOverrides} returns {@code null} for two
     * different reasons — "this engine cannot apply overrides" and the ordinary
     * "cannot answer verified right now" (not synced, no peer, out-of-window
     * block, or a plain revert). A host that cannot tell them apart would report
     * a PERMANENT error for a transient condition, and a client that obeys it
     * stops asking for the rest of the session.
     *
     * @return false by default — an engine that does not override
     *     {@link #callWithOverrides} cannot apply them
     */
    default boolean supportsStateOverrides() {
        return false;
    }

    /**
     * Whether this engine can serve CONTRACT CREATION calls — {@code eth_call}
     * with a null {@code to}, where the calldata is init code and the
     * constructor's return data is the answer.
     *
     * <p>Hosts must consult this BEFORE dispatching: an engine that cannot serve
     * it would otherwise be woken, wait for a verified head, and refuse anyway,
     * turning a free refusal into an expensive one — and returning a retryable
     * error for something permanently unanswerable on that build.
     *
     * @return false by default
     */
    default boolean supportsContractCreation() {
        return false;
    }

    /**
     * Whether this engine APPLIES the {@code finalized} block tag — reads state,
     * blocks, receipts and fee history at the beacon-finalized block — on every
     * method that takes a block selector.
     *
     * <p>Hosts consult it BEFORE dispatch and refuse (-32602) a {@code finalized}
     * selector when it is false: an engine that resolved the tag to its head would
     * answer for a different block than the one asked for, and the answer would be
     * indistinguishable from a correct one (#366).
     *
     * @return false by default
     */
    default boolean supportsFinalizedTag() {
        return false;
    }

    /**
     * {@link #call} with the JSON-RPC {@code eth_call} STATE OVERRIDE object
     * (the third parameter) as JSON — caller-supplied code/balance/nonce/storage
     * layered over verified state for this call only.
     *
     * <p>The answer is NOT a chain fact: it is what the call would return under
     * the caller's own hypothesis, over state that is itself verified. Hosts
     * therefore record it separately from a plain verified read.
     *
     * <p>Default: {@code null} — "this engine cannot apply overrides". Returning
     * null rather than ignoring the parameter is deliberate; answering without
     * the overrides would be a well-formed result computed against different
     * state than the caller asked about, which they cannot detect (see the
     * apply-or-refuse rule in CLAUDE.md).
     *
     * @param stateOverridesJson the override object as JSON; null/empty ⇒ none
     * @return ABI return bytes, or null when unanswerable (including "overrides
     *     unsupported by this engine")
     */
    default byte[] callWithOverrides(
            byte[] from,
            byte[] to,
            byte[] data,
            String valueWei,
            String block,
            String stateOverridesJson) {
        return null;
    }

    /**
     * {@link #call} (or {@link #callWithOverrides} when {@code stateOverridesJson}
     * is non-empty) with a three-way outcome, so a contract REVERT — a verified
     * chain answer — is distinguishable from "cannot answer verified right now".
     * Hosts map {@link CallResult.Status#REVERTED} to the standard JSON-RPC
     * execution-reverted error (code 3, revert data attached) instead of the
     * retryable -32000, which wallets misread as a node outage.
     *
     * <p>Default: wraps the nullable methods, so every existing engine keeps its
     * exact behaviour (a revert stays UNAVAILABLE) until it overrides this to
     * surface the revert payload it already has.
     *
     * @param stateOverridesJson override object as JSON; null/empty ⇒ plain call
     */
    default CallResult callDetailed(
            byte[] from,
            byte[] to,
            byte[] data,
            String valueWei,
            String block,
            String stateOverridesJson) {
        byte[] out = (stateOverridesJson == null || stateOverridesJson.isEmpty())
                ? call(from, to, data, valueWei, block)
                : callWithOverrides(from, to, data, valueWei, block, stateOverridesJson);
        return out == null ? CallResult.unavailable(null) : CallResult.ok(out);
    }

    /** Balance in decimal wei, or null. */
    String getBalance(byte[] address, String block);

    /** Account nonce (with the own-tx pending overlay for "pending"), or null. */
    Long getTransactionCount(byte[] address, String block);

    /** Contract bytecode (verified against the proven codeHash), or null. */
    byte[] getCode(byte[] address, String block);

    /** One 32-byte storage word (proof-verified), or null. */
    byte[] getStorageAt(byte[] address, byte[] slot32, String block);

    /**
     * Gossip a signed raw transaction to peers (the engine never signs).
     *
     * @return keccak256(rawTx) — the tx hash — or null when no peer accepted it
     */
    byte[] sendRawTransaction(byte[] rawTx);

    /** Receipt JSON (verified vs receiptsRoot) | "null" literal | null. */
    String getTransactionReceipt(byte[] txHash);

    /** Transaction JSON (verified vs transactionsRoot) | "null" literal | null. */
    String getTransactionByHash(byte[] txHash);

    /** Block JSON (beacon-anchored header) | "null" literal | null. */
    String getBlockByNumber(String block, boolean fullTransactions);

    /** Block JSON | "null" literal | null. */
    String getBlockByHash(byte[] blockHash32, boolean fullTransactions);

    /**
     * Every receipt of one block as a JSON array (each element the
     * {@code getTransactionReceipt} object shape, verified against the anchored
     * header's {@code receiptsRoot}) | {@code "null"} literal (verified
     * unknown/future block, or a block hash this engine never verified) |
     * {@code null}. {@code blockSelector} is a tag, a 0x-hex number, or a
     * 0x-32-byte block hash.
     */
    String getBlockReceipts(String blockSelector);

    /**
     * Verified {@code eth_getLogs} over the engine's opt-in watch-list log
     * index: the log-array JSON, an {@code {"error": ...}} object carrying
     * coverage/config detail, or {@code null} when the engine has no index
     * (the default — the Java engine does not implement the index yet and
     * answers with the strict retryable error).
     */
    default String getLogs(String filterJson) {
        return null;
    }

    /** Legacy gas price in decimal wei (base fee + tip heuristics), or null. */
    String gasPrice();

    /** Suggested priority fee in decimal wei (from verified bodies), or null. */
    String maxPriorityFeePerGas();

    /** eth_feeHistory result JSON, or null. */
    String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles);

    /**
     * Gas estimate via the local EVM (intrinsic + metered + safety buffer), or
     * null. The legacy two-state view: a reverting call yields null here —
     * {@link #estimateGasDetailed} carries the revert payload.
     */
    Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei);

    /**
     * {@link #estimateGas} with a three-way outcome, so the estimated
     * transaction REVERTING — a verified chain answer with a payload — is
     * distinguishable from "cannot answer verified right now". Hosts map
     * {@link EstimateResult.Status#REVERTED} to the standard JSON-RPC
     * execution-reverted error (code 3, revert data attached), exactly as
     * {@link #callDetailed} does for {@code eth_call}.
     *
     * <p>Default: wraps the nullable method, so every existing engine keeps its
     * exact behaviour (a revert stays UNAVAILABLE) until it overrides this to
     * surface the payload it already has.
     */
    default EstimateResult estimateGasDetailed(byte[] from, byte[] to, byte[] data, String valueWei) {
        Long gas = estimateGas(from, to, data, valueWei);
        return gas == null ? EstimateResult.unavailable(null) : EstimateResult.ok(gas);
    }

    /**
     * Whether this engine APPLIES a transaction object's {@code accessList} and
     * EIP-7702 {@code authorizationList} in {@link #estimateGasTx} and
     * {@link #callTx} (#509).
     *
     * <p>Hosts consult it BEFORE dispatch and refuse (-32602) a request carrying
     * either list when it is false: an engine that estimated without them would
     * answer for a different transaction — a type-4 estimate without its
     * authorizations misses the whole delegated execution — and waking a paused
     * stack only to refuse would turn a free refusal into an expensive one.
     *
     * @return false by default
     */
    default boolean supportsTransactionLists() {
        return false;
    }

    /**
     * {@code eth_estimateGas} for the full transaction object (#509) at
     * {@code block} (a JSON-RPC block selector, applied or refused as for
     * {@link #callDetailed}), with a state override when {@code
     * stateOverridesJson} is non-empty (engines that report
     * {@link #supportsStateOverrides()} apply it here too; the answer is then a
     * simulation, not a chain fact). Every field of {@code tx} is applied or the
     * request is {@link EstimateResult.Status#REFUSED}.
     *
     * <p>Default: an engine that has not implemented the transaction object
     * answers exactly the subset it always could — {@code from}/{@code to}/
     * {@code data}/{@code value} at the head, via {@link #estimateGasDetailed} —
     * and REFUSES anything else rather than estimate a transaction the caller
     * did not describe.
     */
    default EstimateResult estimateGasTx(TransactionArgs tx, String block, String stateOverridesJson) {
        if (tx.hasExtendedFields()) {
            return EstimateResult.refused(
                    "this engine does not apply the transaction object's gas, fee or list fields");
        }
        if (stateOverridesJson != null && !stateOverridesJson.isEmpty()) {
            return EstimateResult.refused("this engine does not apply state overrides to eth_estimateGas");
        }
        String tag = block == null ? "" : block.trim().toLowerCase(java.util.Locale.ROOT);
        if (!tag.isEmpty() && !java.util.Set.of("latest", "pending", "safe").contains(tag)) {
            return EstimateResult.refused("this engine estimates only against the head block");
        }
        return estimateGasDetailed(tx.from(), tx.to(), tx.data(), tx.valueWei());
    }

    /**
     * {@code eth_call} for the full transaction object (#509) at {@code block},
     * with a state override when {@code stateOverridesJson} is non-empty — as
     * {@link #callDetailed}, plus every other field of {@code tx} applied as
     * {@link #estimateGasTx} applies it: {@code gas} is the call's limit, a fee
     * is checked against the block's base fee and charged to the sender, the
     * lists are applied — or the request is {@link CallResult.Status#REFUSED}.
     * A call that cannot succeed within the caller's gas, fee cap or funds is
     * {@link CallResult.Status#INFEASIBLE}.
     *
     * <p>Default: an engine that has not implemented the transaction object
     * answers exactly the subset it always could — {@code from}/{@code to}/
     * {@code data}/{@code value}, via {@link #callDetailed} — and REFUSES
     * anything else rather than run a call the caller did not describe.
     */
    default CallResult callTx(TransactionArgs tx, String block, String stateOverridesJson) {
        if (tx.hasExtendedFields()) {
            return CallResult.refused(
                    "this engine does not apply the transaction object's gas, fee or list fields to eth_call");
        }
        return callDetailed(tx.from(), tx.to(), tx.data(), tx.valueWei(), block, stateOverridesJson);
    }
}
