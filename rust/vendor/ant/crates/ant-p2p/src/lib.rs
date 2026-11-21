//! libp2p host (TCP + DNS, Noise, Yamux, Identify, Ping) and Swarm `/swarm/handshake/14.0.0/handshake`.

mod behaviour;
mod bounded_close;
mod dial;
pub mod dnsaddr;
mod handshake;
mod liveness;
pub mod lurker;
pub mod lurker_registry;
pub mod messaging;
mod peerstore;
pub mod pseudosettle;
pub mod pullsync;
pub mod push_dedup;
pub mod push_pseudosettle;
pub mod pushsync_swap;
pub mod routing;
mod sinks;
pub mod swap;
mod underlay;

pub use behaviour::{
    feed_lookup_ack, manifest_page_ack, run, LateChainInit, RunConfig, RunError, SwapConfig,
    UploadRuntime, DEFAULT_TARGET_PEERS,
};
pub use handshake::{
    handshake_outbound, handshake_outbound_with_role, HandshakeError, HandshakeInfo,
    PROTOCOL_HANDSHAKE, PROTOCOL_HANDSHAKE_V14, PROTOCOL_HANDSHAKE_V15,
};
pub use pushsync_swap::{
    NoopPushsyncSettlement, PeerEthMap, PushsyncSwap, PushsyncSwapConfig, RetrievalSwapPolicy,
    DELIVERY_GRACE,
};
pub use routing::{proximity, RoutingTable, NUM_BINS, OVERLAY_LEN};

use libp2p::multiaddr::Multiaddr;

/// Default mainnet bootnodes, matching upstream `bee` >= 2.7
/// (`/dnsaddr/mainnet.ethswarm.org` is the only published entry).
#[must_use]
pub fn default_mainnet_bootnodes() -> Vec<Multiaddr> {
    ["/dnsaddr/mainnet.ethswarm.org"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}
