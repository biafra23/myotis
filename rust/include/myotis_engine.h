/*
 * Plain C ABI of the Myotis Rust engine (rust/myotis-engine/src/capi.rs).
 * Consumed by the :app-ios Kotlin/Native cinterop; keep in lockstep with
 * capi.rs and bump MYOTIS_ABI_VERSION expectations on any shape change.
 *
 * Conventions (identical to the hand-JNI surface):
 *  - Compound values cross as JSON strings; schemas are pinned by the golden
 *    tests on both sides of the JNI seam and shared verbatim here.
 *  - Every char* RETURNED by these functions is owned by the caller and must
 *    be released with myotis_string_free (never free(3)).
 *  - Errors are sentinels, not exceptions: negative handle ids from
 *    myotis_create, false from start/pause/resume, "{}" status for an unknown
 *    handle, {"error": "..."} objects from the verified reads.
 *  - Verified reads are BLOCKING with a cooperative ~90 s operation budget.
 *    Cancellation drains started native execution; indivisible native work may
 *    overrun the budget. Call off the UI thread.
 *  - EVM execution admits at most eight actual closures process-wide; further
 *    execution fails immediately with "native execution busy". Hosts must bound
 *    their queues and retry busy reads within their own deadline; there is no
 *    additional native semaphore-wait queue.
 */

#ifndef MYOTIS_ENGINE_H
#define MYOTIS_ENGINE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI version this header describes. Mirrors ABI_VERSION in
 * rust/myotis-engine/src/lib.rs and is pinned to it by a capi.rs unit test
 * (header_pins_the_current_abi_version), so a bump that forgets this file
 * fails `cargo test`. Gate on this macro — do not copy the number. */
#define MYOTIS_ABI_VERSION 31

/* Availability + ABI handshake. Installs the log ring subscriber (idempotent)
 * and returns the engine's ABI version; refuse to call anything else if it
 * differs from MYOTIS_ABI_VERSION. */
int32_t myotis_init(void);

/* Up to `max` buffered tracing lines, oldest first, newline-joined; ""
 * when idle. */
char *myotis_drain_logs(int32_t max);

/* Embedded network catalog as a JSON array of NetworkInfo objects. */
char *myotis_available_networks_json(void);

/* Canonical network name, or NULL for an unknown network/alias. */
char *myotis_canonical_network_name(const char *name_or_alias);

/* Allocate a not-yet-started handle id (>= 1); -1 unknown name / runtime-init
 * failure, -2 canonical-but-unsupported network, -3 `data_dir` was bootstrapped
 * from a caller-supplied checkpoint (see myotis_create_with_checkpoint) and
 * cannot be resumed from the embedded anchor. `data_dir` is where the engine
 * persists sync snapshots and caches. */
int64_t myotis_create(const char *network, const char *data_dir);

/* Like myotis_create, but the light client bootstraps from the CALLER's beacon
 * block root (32-byte hex, 0x optional) and header slot instead of the
 * embedded checkpoint — the recovery path for an install parked in
 * STALE_ANCHOR after the host obtained a fresher checkpoint by its own means.
 * The engine does NOT authenticate the root; it pins the bootstrap to it and
 * verifies forward from it exactly as from the embedded checkpoint (BLS on
 * every update, snapshot probation, weak-subjectivity gate on the supplied
 * slot's age). `checkpoint_slot` is the checkpoint block header's slot, not the
 * epoch boundary; >= 1 and not in the future (the Node binding additionally
 * bounds it to a JS safe integer). The first call on a
 * directory records the anchor in `sync-anchor[-net].json`; later calls with
 * the SAME root+slot resume that generation (normal snapshot resume rules),
 * anything else is refused: -3 for a different anchor or a directory holding
 * embedded-anchor state, -1 invalid input / runtime failure / empty data_dir /
 * a data_dir another live handle of this process already uses, -2 unsupported
 * network. Requires ABI >= 26. */
int64_t myotis_create_with_checkpoint(const char *network, const char *data_dir,
                                      const char *checkpoint_root, uint64_t checkpoint_slot);

/* Start the sync loop. False for an unknown/already-running handle. */
bool myotis_start(int64_t handle);

/* Toggle Tor verified-read routing (docs/privacy-and-tor.md). Returns true iff
 * this build supports Tor (built with `--features tor`); a Tor-less build
 * returns false and no-ops. Process-global, not per-handle. */
bool myotis_set_tor_enabled(bool on);

/* Tor status bitmask: bit0 compiled-in, bit1 enabled, bit2 bootstrapped.
 * 0 = this build has no Tor support. */
int32_t myotis_tor_status(void);

/* Status JSON object (camelCase keys), or "{}" for an unknown handle. */
char *myotis_status_json(int64_t handle);

/* Signal pending readers, drain registered work, remove + shut down.
 * Synchronous; no-op for an unknown id. No hard wall-clock termination bound.
 * Serialize start/pause/resume/stop on each handle. */
void myotis_stop(int64_t handle);

/* Idle-sleep: Running->Paused (tear down networking, keep warm state).
 * True only on an actual transition. */
bool myotis_pause(int64_t handle);

/* Live-set the eth/69 served-block window (clamped [1,4096]; stashed for
 * spin_up when the handle isn't running). False only for an unknown handle. */
bool myotis_set_served_block_window(int64_t handle, int32_t blocks);

/* Paused->Running warm restart. False when the rebuild failed (still PAUSED,
 * retryable) or the handle isn't paused. */
bool myotis_resume(int64_t handle);

/* Override the weak-subjectivity anchor-age bound (sync-committee periods);
 * 0 restores the network default. Applied live — a handle parked in the
 * STALE_ANCHOR beaconState re-evaluates within a second. False only for an
 * unknown handle. */
bool myotis_set_ws_bound_periods(int64_t handle, int64_t periods);

/* One-shot consent to sync forward from an anchor older than the
 * weak-subjectivity bound — releases a STALE_ANCHOR park for the rest of this
 * run; never persisted. False only for an unknown handle. */
bool myotis_accept_stale_anchor(int64_t handle);

/* Verified reads — JSON results; {"error": "..."} on transport/not-running/
 * bad-input failures; verification failures carry a `failReason` inside the
 * normal result shape instead. */
char *myotis_request_account_json(int64_t handle, const char *address);
char *myotis_get_storage_proof_json(int64_t handle, const char *address,
                                    int64_t slot, const char *holder_or_null);
char *myotis_get_code_json(int64_t handle, const char *address);
char *myotis_get_storage_at_json(int64_t handle, const char *address,
                                 const char *position);
/* eth_call: {"status":"ok","resultHex"} | {"status":"revert","dataHex"} |
 * {"status":"unavailable","reason"} | {"error"} | {"error","code":-32602}.
 * Every status also carries "blockNumber" (the block the call ran against)
 * and "verified" (true = an ok/revert that ran against the beacon-FINALIZED
 * block; always false on unavailable), ABI >= 30.
 * `from` empty = anonymous; `value` is wei as a decimal string.
 * The engine checks `block` itself (ABI >= 27): latest/pending/safe or
 * empty/NULL run against the VERIFIED HEAD's state; "finalized" (ABI >= 30)
 * runs against the beacon-finalized block — older and never reorged, but a
 * state peers may already have pruned, so it can fail retryably while latest
 * serves (before ABI 30 it ran against the head); safe and pending still mean
 * the head (#366). A block number (0x-hex, or bare decimal digits) runs only
 * within [head-64, head+16], and still against head state. Anything else is
 * refused, never answered from the head:
 *   - behind that window, earliest, a block hash, or a malformed selector:
 *     {"error","code":-32602}, PERMANENT (JSON-RPC invalid params) — do
 *     not retry. A malformed from/to/data/value is refused the same way;
 *   - ahead of the window, or no verified head yet: a plain {"error"},
 *     retryable.
 * An EMPTY `to` selects contract creation (the calldata is init code and the
 * constructor's return data is the result), so a NULL `to` is REFUSED
 * (ABI >= 29) rather than read as that: pass "" to create. */
char *myotis_eth_call_json(int64_t handle, const char *from, const char *to,
                           const char *data, const char *value,
                           const char *block);

/* eth_call with a STATE OVERRIDE object as JSON (empty => none). The answer is
   a simulation over verified state — the caller's hypothesis, not a chain fact.
   An EMPTY `to` selects contract creation: the calldata is init code and the
   constructor's return data is the result, and a NULL `to` is refused.
   `block` is checked, and a malformed argument (overrides included) refused,
   exactly as for myotis_eth_call_json. */
char *myotis_eth_call_overrides_json(int64_t handle, const char *from,
                                     const char *to, const char *data,
                                     const char *value, const char *block,
                                     const char *state_overrides);
/* {"status":"ok","gas":N} | {"status":"revert","dataHex"} (the estimated tx
 * reverted — a verified answer; serve JSON-RPC code 3 with the raw payload) |
 * {"status":"unavailable","reason"} | {"error"}. */
char *myotis_estimate_gas_json(int64_t handle, const char *from,
                               const char *to, const char *data,
                               const char *value);
/* {"status":"ok","addressHex","blockNumber"} | {"status":"noRecord",...} |
 * {"status":"offchain",...} | {"error"}. */
char *myotis_resolve_ens_json(int64_t handle, const char *name);
/* Generic ENS record dispatch; method + args travel in params_json. */
char *myotis_ens_record_json(int64_t handle, const char *params_json);
/* Block JSON, the literal "null", or {"error"}. full_transactions selects
 * decoded tx objects over hashes. */
char *myotis_get_block_by_number_json(int64_t handle, const char *block_tag,
                                      bool full_transactions);
/* Pending-tag nonce overlay: max(mined_nonce, own broadcast nonce + 1) while
 * unmined+unexpired, identity otherwise; negative on malformed input (serve
 * the plain mined nonce). */
int64_t myotis_pending_nonce_overlay(int64_t handle, const char *address_hex,
                                     int64_t mined_nonce);
/* Receipt JSON, the literal "null" (verified not-seen), or {"error"}. */
char *myotis_get_transaction_receipt_json(int64_t handle,
                                          const char *tx_hash_hex);
/* Tx JSON, the literal "null" (verified not-seen), or {"error"}. */
char *myotis_get_transaction_by_hash_json(int64_t handle,
                                          const char *tx_hash_hex);
/* Block JSON, the literal "null" (never-verified hash), or {"error"}.
 * full_transactions selects decoded tx objects over hashes. */
char *myotis_get_block_by_hash_json(int64_t handle,
                                    const char *block_hash_hex,
                                    bool full_transactions);
/* Receipts array JSON, the literal "null" (unknown/future block or
 * never-verified hash), or {"error"}. selector = tag | 0x-number | 0x-hash. */
char *myotis_get_block_receipts_json(int64_t handle, const char *selector);
/* {"gasPriceWei","maxPriorityFeePerGasWei"} or {"error"}. */
char *myotis_fee_estimate_json(int64_t handle);
/* eth_feeHistory: {"oldestBlock","baseFeePerGas","gasUsedRatio"[,"reward"]}
 * or {"error"}. percentiles_json is a JSON number array, or NULL/"" to omit
 * the reward matrix. */
char *myotis_fee_history_json(int64_t handle, int64_t block_count,
                              const char *newest_block_tag,
                              const char *percentiles_json);
/* {"txHash":"0x..."} or {"error"}. */
char *myotis_send_raw_transaction_json(int64_t handle, const char *raw_tx_hex);

/* Release any char* returned by the functions above. NULL is a no-op. */
void myotis_string_free(char *s);

/* v21: the opt-in eth_getLogs watch-list index (docs/eth-getlogs-design.md).
 * get_logs answers only inside indexed coverage; anything else is an
 * {"error": ...} JSON — never an empty array for unindexed ranges. */
char *myotis_get_logs_json(int64_t handle, const char *filter_json);
bool myotis_set_log_index_config(int64_t handle, const char *config_json);
char *myotis_log_index_status_json(int64_t handle);

/* v28: the read-fetch shadow-cache counters (docs/read-stats.md): how much of
 * the verified account / storage / bytecode fetch traffic a cache would have
 * served, by keying, with the wall-clock it would have saved. Counts only —
 * nothing is served from it. {"error": ...} when the handle has no EL reader. */
char *myotis_read_stats_json(int64_t handle);

/* v24: import portable log-index snapshots. paths_json is a JSON array of
 * absolute file paths, each a self-describing snapshot of this handle's
 * chain; all-or-nothing merge, importing is the opt-in (catch-up starts
 * immediately). {"ok":true,"status":...} or {"error":...}. */
char *myotis_import_log_index_files(int64_t handle, const char *paths_json);
/* v24: export the current index as a portable snapshot at path
 * (finality-clamped, self-describing). {"ok":true} or {"error":...}. */
char *myotis_export_log_index(int64_t handle, const char *path);

/* v31: host-supplied EL seed pins (#465). enodes_json is a JSON array of
 * "enode://<128-hex pubkey>@ip:port" strings (numeric address, no DNS).
 * REPLACES the handle's host list (an empty array clears it); the network's
 * own pins are unaffected. Applied or refused AS A WHOLE: false for NULL,
 * invalid JSON, a non-array, any malformed entry, a duplicate address, more
 * than 64 entries, or an unknown handle — nothing is applied on refusal.
 * Kept per handle and applied on every start/resume, and live on a running
 * handle: the pins are dialed like the network's pins (directly, never seeded
 * into the peer cache; re-dialed while the pool is below its target and,
 * above it, once proven to serve snap data).
 * v31 also adds "snapServingPeers" to myotis_status_json: the pooled peers
 * that can answer a read at the anchored head NOW — gate reads on it rather
 * than on "snapPeers", which a pool of still-syncing peers satisfies for
 * hours while every read fails. */
bool myotis_set_boot_enodes(int64_t handle, const char *enodes_json);

#ifdef __cplusplus
}
#endif

#endif /* MYOTIS_ENGINE_H */
