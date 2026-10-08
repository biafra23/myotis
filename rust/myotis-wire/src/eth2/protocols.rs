//! Eth2 req/resp protocol identifiers — exactly the set (and versions) the Java
//! `BeaconP2PService` speaks, plus the per-protocol wire attributes the codec
//! needs (context bytes, expected request size).

#[allow(unused_imports)]
use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};
pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const BOOTSTRAP: &str = "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy";
pub const UPDATES_BY_RANGE: &str =
    "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy";
pub const FINALITY_UPDATE: &str =
    "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy";
pub const OPTIMISTIC_UPDATE: &str =
    "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy";
/// `BeaconBlocksByRoot v2` — answered INBOUND ONLY, and always with zero
/// chunks: a light client holds no blocks, and an empty response is the
/// spec's "none of these". It exists because Nimbus's sync overseer
/// (`updatePeerStatus` → `doRootSyncStep`, v26.9) asks every new peer for
/// the head block that peer advertised in Status whenever the block is not in
/// Nimbus's own sync DAG — a light client's head is its last verified header,
/// always older than that DAG — and ends the peer loop (disconnect) when the
/// request cannot be negotiated at all. An empty answer passes its
/// `checkResponse`, costs no score, and the connection survives.
pub const BLOCKS_BY_ROOT: &str = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
pub const PING: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
/// Fulu `GetMetaData v3`: v2 plus `custody_group_count`. Post-Fulu peers ask
/// for THIS version; Nimbus's sync overseer asks for nothing else and drops a
/// peer that cannot answer it (`doPeerUpdateMetadata` → "Peer loop stopped"),
/// so a host without v3 is disconnected before its first light-client request.
pub const METADATA_V3: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";
pub const GOODBYE: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";

/// Whether the protocol's responses carry 4 context bytes (fork digest) between
/// the result byte and the length varint. True for fork-dependent SSZ types
/// (`light_client_*`), false for the fixed ones (status/ping/metadata/goodbye)
/// — mirrors the Java `registerBinding` flags.
pub fn has_context_bytes(protocol: &str) -> bool {
    matches!(
        protocol,
        BOOTSTRAP | UPDATES_BY_RANGE | FINALITY_UPDATE | OPTIMISTIC_UPDATE | BLOCKS_BY_ROOT
    )
}

/// Expected SSZ size of the request body for the responder role. 0 means the
/// body is not parsed: the request has none (metadata / finality_update /
/// optimistic_update), or the answer does not depend on it (blocks_by_root,
/// whose root list is never read because the answer is always empty) — same
/// table the Java `registerBinding` calls pin.
pub fn expected_request_size(protocol: &str) -> usize {
    match protocol {
        STATUS_V2 => 92,
        STATUS_V1 => 84,
        PING | GOODBYE => 8,
        BOOTSTRAP => 32,
        UPDATES_BY_RANGE => 16,
        _ => 0, // metadata, finality_update, optimistic_update, blocks_by_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_requests_have_no_body() {
        assert_eq!(expected_request_size(METADATA_V2), 0);
        assert_eq!(expected_request_size(METADATA_V3), 0);
    }

    #[test]
    fn blocks_by_root_is_fork_dependent_and_its_body_is_not_parsed() {
        assert!(has_context_bytes(BLOCKS_BY_ROOT));
        assert_eq!(expected_request_size(BLOCKS_BY_ROOT), 0);
    }

    #[test]
    fn context_bytes_table_matches_java_bindings() {
        assert!(!has_context_bytes(STATUS_V2));
        assert!(!has_context_bytes(STATUS_V1));
        assert!(!has_context_bytes(PING));
        assert!(!has_context_bytes(METADATA_V2));
        assert!(!has_context_bytes(METADATA_V3));
        assert!(!has_context_bytes(GOODBYE));
        assert!(has_context_bytes(BOOTSTRAP));
        assert!(has_context_bytes(UPDATES_BY_RANGE));
        assert!(has_context_bytes(FINALITY_UPDATE));
        assert!(has_context_bytes(OPTIMISTIC_UPDATE));
    }
}
