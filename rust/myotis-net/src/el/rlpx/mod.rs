//! RLPx — the TCP transport under the `eth`/`snap` sub-protocols (EL-A4),
//! twin of the Java `networking.rlpx` package (docs/reimplementation/02 §5).
//!
//! - [`ecies`] — ECIES for the auth/ack messages (`EciesCodec`).
//! - [`handshake`] — EIP-8 auth/ack + session-secret derivation (`AuthHandshake`).
//! - [`frame`] — the AES-256-CTR framed channel with keccak MAC chains (`FrameCodec`).
//! - [`transport`] — the tokio dialer driving `HANDSHAKE → FRAMED` and the
//!   p2p base messages (Hello/Disconnect/Ping/Pong).
//!
//! Initiator-only, matching the reference. The codecs are pure (entropy is a
//! parameter) and pinned by `rust/testdata/el/rlpx/`; only [`transport`] uses
//! sockets and OS entropy.

pub mod ecies;
pub mod frame;
pub mod handshake;
pub mod transport;
