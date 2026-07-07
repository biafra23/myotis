//! The eth/66-69 sub-protocol (EL-A5) on top of the RLPx framed channel.
//!
//! - [`messages`] — pure encode/decode for Status, GetBlockHeaders/Bodies/
//!   Receipts and their responses (canonical header hashing, eth/69 bloomless
//!   receipt re-canonicalization). Twin of `networking.eth.messages`.
//! - [`session`] — the async Hello/Status handshake with the network
//!   compatibility gate and request/response correlation. Twin of the
//!   `EthHandler` state machine.

pub mod messages;
pub mod session;
