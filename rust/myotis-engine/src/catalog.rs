//! The embedded network catalog — the Rust twin of the Java engine's
//! `NetworkConfig`-derived `NetworkInfo` list. Field names serialize in the exact
//! camelCase shape `io.myotis.api.NetworkInfo` uses; the committed golden sample
//! (`rust/testdata/networks_catalog.json`) is asserted byte-for-byte here AND parsed
//! by the Java side's `NetworksJsonGoldenTest`, so the two catalogs cannot drift
//! apart silently.

use serde::Serialize;

/// Mirrors `io.myotis.api.NetworkInfo` (see its javadoc for field semantics).
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    pub name: &'static str,
    pub display_name: &'static str,
    pub chain_id: u64,
    pub has_ens: bool,
    pub default_el_port: u16,
    pub default_discv5_port: u16,
    pub default_rpc_port: u16,
    pub cl_genesis_time: u64,
    pub seconds_per_slot: u32,
}

/// Display order matches the Java engine (`NetworkConfig.allNetworks()`):
/// mainnet, gnosis, sepolia.
pub const NETWORKS: [NetworkInfo; 3] = [
    NetworkInfo {
        name: "mainnet",
        display_name: "Ethereum Mainnet",
        chain_id: 1,
        has_ens: true,
        default_el_port: 30303,
        default_discv5_port: 9000,
        default_rpc_port: 8545,
        cl_genesis_time: 1_606_824_023, // 2020-12-01 12:00:23 UTC
        seconds_per_slot: 12,
    },
    NetworkInfo {
        name: "gnosis",
        display_name: "Gnosis Chain",
        chain_id: 100,
        has_ens: false,
        default_el_port: 30304,
        default_discv5_port: 9001,
        default_rpc_port: 8546,
        cl_genesis_time: 1_638_993_340, // 2021-12-08 19:55:40 UTC
        seconds_per_slot: 5,
    },
    NetworkInfo {
        name: "sepolia",
        display_name: "Sepolia",
        chain_id: 11_155_111,
        has_ens: true,
        default_el_port: 30305,
        default_discv5_port: 9002,
        default_rpc_port: 8547,
        cl_genesis_time: 1_655_733_600, // 2022-06-20 14:00:00 UTC
        seconds_per_slot: 12,
    },
];

/// The catalog as the JSON array `RustEngineNative.nativeAvailableNetworksJson()`
/// returns. Pretty-printed so the committed golden file stays reviewable.
pub fn networks_json() -> String {
    serde_json::to_string_pretty(&NETWORKS).expect("static catalog always serializes")
}

/// Resolve a name or alias (case-insensitive; `xdai`/`gbc` → `gnosis`) to the
/// canonical name, mirroring the Java engine's `canonicalNetworkName`. `None` for
/// unknown networks (the Java wrapper turns that into an `EngineException`).
/// Deliberately NO trim(): the Java reference (`NetworkConfig.byName`) doesn't trim,
/// and the two engines must reject exactly the same inputs.
pub fn canonical_network_name(name_or_alias: &str) -> Option<&'static str> {
    match name_or_alias.to_ascii_lowercase().as_str() {
        "mainnet" => Some("mainnet"),
        "gnosis" | "gbc" | "xdai" => Some("gnosis"),
        "sepolia" => Some("sepolia"),
        // holesky retired: the EF shut it down in Oct 2025.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed sample is the cross-language contract: this test pins the Rust
    /// serialization to it, and the Java `NetworksJsonGoldenTest` parses the same
    /// file and compares against `JavaMyotisEngine.availableNetworks()`.
    #[test]
    fn catalog_matches_committed_golden_sample() {
        let golden = include_str!("../../testdata/networks_catalog.json");
        assert_eq!(networks_json().trim(), golden.trim());
    }

    #[test]
    fn aliases_resolve_like_the_java_engine() {
        assert_eq!(canonical_network_name("mainnet"), Some("mainnet"));
        assert_eq!(canonical_network_name("MAINNET"), Some("mainnet"));
        assert_eq!(canonical_network_name("xdai"), Some("gnosis"));
        assert_eq!(canonical_network_name("GBC"), Some("gnosis"));
        assert_eq!(canonical_network_name("gnosis"), Some("gnosis"));
        assert_eq!(canonical_network_name("sepolia"), Some("sepolia"));
        assert_eq!(canonical_network_name("holesky"), None);
        assert_eq!(canonical_network_name(""), None);
        // No trim — whitespace-wrapped input is rejected exactly like the Java engine.
        assert_eq!(canonical_network_name(" mainnet "), None);
    }
}
