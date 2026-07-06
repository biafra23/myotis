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

pub mod clcache;
pub mod codec;
pub mod discovery;
pub mod protocols;
pub mod reqresp;
pub mod status;
pub mod sync;

pub use sync::{ChainConfig, SyncHandle, SyncState, SyncStatus};
