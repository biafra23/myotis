//! Myotis consensus-layer networking — ALL the I/O around the sans-I/O
//! [`myotis_consensus`] verification core.
//!
//! - [`codec`] — eth2 req/resp wire framing (varint + snappy frames), the Rust
//!   twin of the Java `ReqRespCodec` + the multi-chunk scanner, pinned against
//!   Java-generated golden vectors.
//! - [`protocols`] — the protocol IDs the Java `BeaconP2PService` speaks.
//! - [`status`] — `Status`/`MetaData` SSZ + fork-digest math (incl. EIP-7892 BPO).
//! - [`reqresp`] — libp2p (TCP + noise + yamux + identify, secp256k1 identity)
//!   dialer/responder for the eth2 req/resp protocols.
//! - [`discovery`] — sigp discv5 seeded from the chain's bootstrap ENRs,
//!   filtering by the `eth2` ENR fork digest.
//! - [`sync`] — the light-client sync loop ([`sync::SyncHandle`]): bootstrap →
//!   catch-up → finality polling, driving `myotis_consensus`.
//!
//! Dependency direction is one-way by design: `myotis-net` → `myotis-consensus`.
//! The consensus crate stays free of tokio/sockets/fs/clock (enforced by the
//! wasm32 canary in the root Gradle build); every clock read happens here and
//! crosses into the consensus crate as a plain slot number.
//!
//! Library hygiene: tracing only (no println), no global mutable state — every
//! [`sync::SyncHandle`] owns its own libp2p host, discv5 service, and store.

// Re-exported so downstream crates (rust/roost) can build a `HostConfig`
// without pinning their own libp2p version — the types in that config are
// libp2p's, so version skew would be a confusing type error. Narrowed to the
// items a downstream actually needs — building a `HostConfig` (`identity`,
// `Multiaddr`) and handling what `start_host_with` returns (`PeerId`), plus
// `multiaddr` for constructing an address from its protocols. Deliberately not
// `pub use libp2p;`, which would put the whole crate in this one's public
// surface.
pub use libp2p::{identity, multiaddr, Multiaddr, PeerId};

pub mod clcache;
pub mod codec;
pub mod discovery;
pub mod el;
pub mod protocols;
pub mod reqresp;
pub mod status;
pub mod sync;

pub use sync::{ChainConfig, SyncHandle, SyncState, SyncStatus};
