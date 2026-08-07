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
 *  - All verified reads are BLOCKING (up to ~90 s) — call off the UI thread.
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
#define MYOTIS_ABI_VERSION 22

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
 * failure, -2 canonical-but-unsupported network. `data_dir` is where the
 * engine persists sync snapshots and caches. */
int64_t myotis_create(const char *network, const char *data_dir);

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

/* Remove + shut down; no-op for an unknown id. */
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
 * {"status":"unavailable","reason"} | {"error"}. `from` empty = anonymous;
 * `value` is wei as a decimal string. */
char *myotis_eth_call_json(int64_t handle, const char *from, const char *to,
                           const char *data, const char *value,
                           const char *block);
/* {"status":"ok","gas":N} | {"status":"unavailable","reason"} | {"error"}. */
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

#ifdef __cplusplus
}
#endif

#endif /* MYOTIS_ENGINE_H */
