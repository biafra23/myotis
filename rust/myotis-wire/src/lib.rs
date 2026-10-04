//! Myotis execution-layer wire protocols, without an async runtime.
//!
//! The protocol logic `myotis-net` drives over tokio, split out (myotis#505)
//! so a host with its own event loop can drive the same code: UEFI firmware,
//! wasm32 in a browser, a blocking client. Sans-I/O like `myotis-core` --
//! no sockets, clock or entropy; every random value is a parameter -- and
//! `no_std` + `alloc` when built with `default-features = false`.
//!
//! - [`discv4`] -- the discovery packet codec (ping/pong/findnode/neighbors)
//! - [`rlpx`]   -- ECIES handshake, frame codec, p2p Hello
//! - [`eth`]    -- eth/66-69 messages (Status, headers, bodies, receipts)
//! - [`snap`]   -- snap/1 messages and proof verification of the responses
//! - [`eth2`]   -- consensus req/resp framing (ssz_snappy), Status, fork digests
//!
//! `myotis-net` re-exports each module at its previous path, so nothing that
//! depended on those paths changes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod discv4;
pub mod eth;
#[cfg(feature = "eth2")]
pub mod eth2;
pub mod rlpx;
pub mod snap;
pub mod snappy;
