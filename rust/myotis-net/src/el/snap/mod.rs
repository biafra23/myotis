//! The snap/1 sub-protocol (EL-A6) — SNAP-served state, verified on fetch.
//!
//! - [`messages`] — pure encode/decode with the dynamic base offset
//!   (0x21 eth/67-68, 0x22 eth/69), the slim-account and double-wrapped-slot
//!   rules, and empty responders. Twin of `networking.snap.messages`.
//! - [`fetch`] — verify-on-fetch against a trusted state root (the MPT proof
//!   is the trust anchor; the peer's slim body is never trusted). Twin of the
//!   `SnapBackedStateOracle` verification.
//!
//! The async single-shot request methods are on
//! [`crate::el::eth::session::EthSession`] (snap shares the eth peer's RLPx
//! connection, multiplexed by message code). Peer rotation, the stale-head
//! floor, and inbound snap responders are EL-A7 (see [`fetch`]).

pub mod fetch;
pub mod messages;
