//! Eth2 req/resp protocol identifiers — exactly the set (and versions) the Java
//! `BeaconP2PService` speaks, plus the per-protocol wire attributes the codec
//! needs (context bytes, expected request size).

pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const BOOTSTRAP: &str = "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy";
pub const UPDATES_BY_RANGE: &str =
    "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy";
pub const FINALITY_UPDATE: &str =
    "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy";
pub const OPTIMISTIC_UPDATE: &str =
    "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy";
pub const PING: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
pub const GOODBYE: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";

/// Whether the protocol's responses carry 4 context bytes (fork digest) between
/// the result byte and the length varint. True for fork-dependent SSZ types
/// (`light_client_*`), false for the fixed ones (status/ping/metadata/goodbye)
/// — mirrors the Java `registerBinding` flags.
pub fn has_context_bytes(protocol: &str) -> bool {
    matches!(
        protocol,
        BOOTSTRAP | UPDATES_BY_RANGE | FINALITY_UPDATE | OPTIMISTIC_UPDATE
    )
}

/// Expected SSZ size of the request body for the responder role. 0 means the
/// request has no body (metadata / finality_update / optimistic_update) — same
/// table the Java `registerBinding` calls pin.
pub fn expected_request_size(protocol: &str) -> usize {
    match protocol {
        STATUS_V2 => 92,
        STATUS_V1 => 84,
        PING | GOODBYE => 8,
        BOOTSTRAP => 32,
        UPDATES_BY_RANGE => 16,
        _ => 0, // metadata, finality_update, optimistic_update
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_bytes_table_matches_java_bindings() {
        assert!(!has_context_bytes(STATUS_V2));
        assert!(!has_context_bytes(STATUS_V1));
        assert!(!has_context_bytes(PING));
        assert!(!has_context_bytes(METADATA_V2));
        assert!(!has_context_bytes(GOODBYE));
        assert!(has_context_bytes(BOOTSTRAP));
        assert!(has_context_bytes(UPDATES_BY_RANGE));
        assert!(has_context_bytes(FINALITY_UPDATE));
        assert!(has_context_bytes(OPTIMISTIC_UPDATE));
    }
}
