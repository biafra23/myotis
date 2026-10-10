//! The seam between the JSON-RPC router and the myotis engine.
//!
//! [`Engine`] mirrors the engine's verified-read surface one method per
//! `myotis_engine::ffi` export, strings in and the engine's JSON strings out,
//! so the router can be tested against recorded engine shapes without a running
//! light client. [`FfiEngine`] is the real thing: one engine handle.
//!
//! The readiness hold the JVM host (`RustChainHandle.awaitWake`) puts in front
//! of every read is NOT here: the router takes it once per request (and once
//! per batch, as one budget), so a read that touches the engine several times
//! cannot wait several times over.

use myotis_engine::ffi;

/// Everything the router asks of the engine. Nothing here holds for
/// readiness; the reads themselves may still block in the engine.
pub trait Engine: Send + Sync {
    fn chain_id(&self) -> u64;
    /// The handle's status JSON — non-blocking.
    fn status_json(&self) -> String;
    /// The log index's status JSON (`GET /logindex`) — non-blocking.
    fn log_index_status_json(&self) -> String;
    /// The verified optimistic head block number from the status snapshot —
    /// non-blocking; `None` when the engine has none to give.
    fn head_block_number(&self) -> Option<u64>;
    fn request_account(&self, address: &str, block: &str) -> String;
    fn pending_nonce_overlay(&self, address: &str, mined: i64) -> i64;
    fn get_code(&self, address: &str, block: &str) -> String;
    fn get_storage_at(&self, address: &str, position: &str, block: &str) -> String;
    fn eth_call(&self, from: &str, to: &str, data: &str, value: &str, block: &str) -> String;
    #[allow(clippy::too_many_arguments)]
    fn eth_call_overrides(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: &str,
        overrides: &str,
    ) -> String;
    fn eth_call_tx(&self, tx: &str, block: &str, overrides: &str) -> String;
    fn estimate_gas_tx(&self, tx: &str, block: &str, overrides: &str) -> String;
    /// `eth_createAccessList` for the transaction object (ABI 40): the engine's
    /// access-list JSON, the list and gas next to the run's own failure.
    fn create_access_list(&self, tx: &str, block: &str, overrides: &str) -> String;
    fn block_by_number(&self, tag: &str, full: bool) -> String;
    fn block_by_hash(&self, hash: &str, full: bool) -> String;
    fn fee_estimate(&self) -> String;
    fn fee_history(&self, count: i64, newest: &str, percentiles: &str) -> String;
    fn send_raw_transaction(&self, raw: &str) -> String;
    fn transaction_receipt(&self, hash: &str) -> String;
    fn transaction_by_hash(&self, hash: &str) -> String;
    fn block_receipts(&self, selector: &str) -> String;
    fn get_logs(&self, filter: &str) -> String;
}

/// A started engine handle.
pub struct FfiEngine {
    pub handle: i64,
    pub chain_id: u64,
}

/// What [`ready_for_reads`] needs from the status JSON.
#[derive(Debug, Default, PartialEq)]
pub struct Readiness {
    pub running: bool,
    pub beacon_state: String,
    pub el_reader_available: bool,
    pub optimistic_block: u64,
    pub snap_serving_peers: u64,
    pub peer_count: u64,
}

impl Readiness {
    pub fn parse(status: &str) -> Self {
        let v: serde_json::Value = serde_json::from_str(status).unwrap_or_default();
        let u = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        Readiness {
            running: v.get("running").and_then(|x| x.as_bool()).unwrap_or(false),
            beacon_state: v
                .get("beaconState")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            el_reader_available: v
                .get("elReaderAvailable")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            optimistic_block: u("optimisticBlockNumber"),
            snap_serving_peers: u("snapServingPeers"),
            peer_count: u("peerCount"),
        }
    }

    /// The JVM host's `readyForReads`: SYNCED, an anchored head, and a pooled
    /// peer that can serve at it (`snapServingPeers`, not `snapPeers` — a pool of
    /// still-syncing peers keeps the latter positive for hours, #465). A RUNNING
    /// handle with no EL reader, or parked on STALE_ANCHOR, is "attempt now":
    /// waiting cannot change either, and the engine's own refusal is the answer.
    pub fn ready_for_reads(&self) -> bool {
        if self.running && !self.el_reader_available {
            return true;
        }
        if self.running && self.beacon_state == "STALE_ANCHOR" {
            return true;
        }
        self.running
            && self.beacon_state == "SYNCED"
            && self.optimistic_block > 0
            && self.snap_serving_peers > 0
    }
}

impl Engine for FfiEngine {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
    fn status_json(&self) -> String {
        ffi::status_json(self.handle)
    }
    fn log_index_status_json(&self) -> String {
        ffi::log_index_status_json(self.handle)
    }
    fn head_block_number(&self) -> Option<u64> {
        Some(Readiness::parse(&ffi::status_json(self.handle)).optimistic_block).filter(|&h| h > 0)
    }
    fn request_account(&self, address: &str, block: &str) -> String {
        ffi::request_account_json(self.handle, address.into(), block.into())
    }
    fn pending_nonce_overlay(&self, address: &str, mined: i64) -> i64 {
        ffi::pending_nonce_overlay(self.handle, address.into(), mined)
    }
    fn get_code(&self, address: &str, block: &str) -> String {
        ffi::get_code_json(self.handle, address.into(), block.into())
    }
    fn get_storage_at(&self, address: &str, position: &str, block: &str) -> String {
        ffi::get_storage_at_json(self.handle, address.into(), position.into(), block.into())
    }
    fn eth_call(&self, from: &str, to: &str, data: &str, value: &str, block: &str) -> String {
        ffi::eth_call_json(
            self.handle,
            from.into(),
            to.into(),
            data.into(),
            value.into(),
            block.into(),
        )
    }
    fn eth_call_overrides(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: &str,
        overrides: &str,
    ) -> String {
        ffi::eth_call_overrides_json(
            self.handle,
            from.into(),
            to.into(),
            data.into(),
            value.into(),
            block.into(),
            overrides.into(),
        )
    }
    fn eth_call_tx(&self, tx: &str, block: &str, overrides: &str) -> String {
        ffi::eth_call_tx_json(self.handle, tx.into(), block.into(), overrides.into())
    }
    fn estimate_gas_tx(&self, tx: &str, block: &str, overrides: &str) -> String {
        ffi::estimate_gas_tx_json(self.handle, tx.into(), block.into(), overrides.into())
    }
    fn create_access_list(&self, tx: &str, block: &str, overrides: &str) -> String {
        ffi::create_access_list_json(self.handle, tx.into(), block.into(), overrides.into())
    }
    fn block_by_number(&self, tag: &str, full: bool) -> String {
        ffi::get_block_by_number_json(self.handle, tag.into(), full)
    }
    fn block_by_hash(&self, hash: &str, full: bool) -> String {
        ffi::get_block_by_hash_json(self.handle, hash.into(), full)
    }
    fn fee_estimate(&self) -> String {
        ffi::fee_estimate_json(self.handle)
    }
    fn fee_history(&self, count: i64, newest: &str, percentiles: &str) -> String {
        ffi::fee_history_json(self.handle, count, newest.into(), percentiles.into())
    }
    fn send_raw_transaction(&self, raw: &str) -> String {
        ffi::send_raw_transaction_json(self.handle, raw.into())
    }
    fn transaction_receipt(&self, hash: &str) -> String {
        ffi::get_transaction_receipt_json(self.handle, hash.into())
    }
    fn transaction_by_hash(&self, hash: &str) -> String {
        ffi::get_transaction_by_hash_json(self.handle, hash.into())
    }
    fn block_receipts(&self, selector: &str) -> String {
        ffi::get_block_receipts_json(self.handle, selector.into())
    }
    fn get_logs(&self, filter: &str) -> String {
        ffi::get_logs_json(self.handle, filter.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine's own pinned not-started status (host.rs status golden).
    const NOT_STARTED: &str = r#"{"running":false,"paused":false,"network":"mainnet","beaconState":"STARTING","bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,"currentPeriod":0,"targetPeriod":0,"peerCount":0,"servedPeersLastMinute":0,"discv5TableSize":0,"syncStartPeriod":-1,"lcHunting":false,"wsBoundPeriods":0,"finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000","elReaderAvailable":false,"snapPeers":0,"snapServingPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,"backedOffPeers":0,"blacklistedPeers":0,"optimisticBlockNumber":0,"finalizedBlockNumber":0,"executionBlockNumber":0,"elHunting":false,"peerHeaderRequests":0,"peerHeaderRequestsServed":0,"peerBodyRequests":0,"peerBodyRequestsServed":0,"upgradeAdvisory":null}"#;

    #[test]
    fn readiness_follows_the_jvm_predicate() {
        assert!(!Readiness::parse(NOT_STARTED).ready_for_reads());
        assert!(!Readiness::parse("{}").ready_for_reads());
        assert!(!Readiness::parse("garbage").ready_for_reads());
        let synced = r#"{"running":true,"beaconState":"SYNCED","elReaderAvailable":true,
            "optimisticBlockNumber":42,"snapServingPeers":1}"#;
        assert!(Readiness::parse(synced).ready_for_reads());
        // Pooled-but-not-serving peers are not ready (#465).
        let no_serving = synced.replace("\"snapServingPeers\":1", "\"snapServingPeers\":0");
        assert!(!Readiness::parse(&no_serving).ready_for_reads());
        // No EL reader / STALE_ANCHOR: attempt now, the engine says why.
        assert!(
            Readiness::parse(r#"{"running":true,"elReaderAvailable":false}"#).ready_for_reads()
        );
        assert!(Readiness::parse(
            r#"{"running":true,"elReaderAvailable":true,"beaconState":"STALE_ANCHOR"}"#
        )
        .ready_for_reads());
    }
}
