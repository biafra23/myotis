/**
 * The Myotis engine API — the formal, language-neutral boundary between hosts
 * (daemon / desktop / Android / iOS) and the engine (P2P networking, the beacon
 * light client, verification, the EVM, verified reads).
 *
 * <p>The engine is one replaceable unit: the reference implementation is the JVM
 * engine ({@code node-core} + friends); a Rust/Go engine later replaces everything
 * behind this API via an FFI binding implementing the same interfaces. Hosts must
 * consume ONLY the types in this package and {@code io.myotis.api.ports}.
 *
 * <h2>Type conventions (binding-portability rules)</h2>
 * <ol>
 *   <li>Binary values in {@link io.myotis.api.VerifiedReads} (addresses, slots,
 *       hashes, code, calldata, raw txs): {@code byte[]}.</li>
 *   <li>Display/result-record fields: 0x-prefixed lowercase hex {@code String}.</li>
 *   <li>uint256 amounts (wei): decimal {@code String}; {@code BigInteger} never
 *       crosses the boundary.</li>
 *   <li>Gas / nonces / block numbers / slots / periods: {@code long}; boxed
 *       {@code Long} only where {@code null} means "unanswerable".</li>
 *   <li>Endpoints: {@code (String host, int port)} pairs in ports; a single
 *       {@code "host:port"} string only for display.</li>
 *   <li>File locations: {@code String} paths.</li>
 *   <li>No {@code Optional}, no {@code CompletableFuture}, no checked exceptions,
 *       no third-party types. Nullability is documented per method.</li>
 *   <li>Composite JSON-RPC objects (blocks, txs, receipts, feeHistory): pre-built
 *       JSON {@code String} with the tri-state convention — a JSON object, the
 *       literal {@code "null"} (a <em>verified</em> "not found"), or {@code null}
 *       (no verified answer).</li>
 *   <li>Collections: {@code java.util.List} of flat records.</li>
 *   <li>Block selector: {@code String} — {@code "latest"}, {@code "pending"}, or
 *       a 0x-hex block number.</li>
 * </ol>
 *
 * <h2>Threading model</h2>
 * All engine methods are <b>blocking</b> and must be called from a worker thread,
 * never a UI or I/O event-loop thread. Long-running verification queries are
 * internally timeout-bounded (documented per method). Port implementations
 * ({@code io.myotis.api.ports}) are invoked by the engine from its own worker
 * threads and must be thread-safe.
 *
 * <h2>Error model</h2>
 * <ul>
 *   <li>{@link io.myotis.api.VerifiedReads}: {@code null} = "cannot answer
 *       verified right now" (host maps to a JSON-RPC error in strict mode).</li>
 *   <li>Verification queries ({@code requestAccount}, {@code getStorageProof},
 *       ENS, …): always return a flat result record; verification failures set
 *       {@code failReason}/{@code error}, never throw.</li>
 *   <li>Programmer/state errors (unknown network, bad address, not running):
 *       unchecked {@link io.myotis.api.EngineException} — the only exception type
 *       this API throws.</li>
 * </ul>
 */
package io.myotis.api;
