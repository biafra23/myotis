//! The eth2 (consensus-layer) req/resp wire, moved here from `myotis-net`
//! (myotis#505): ssz_snappy request/response framing, `Status`/`MetaData`, the
//! fork-digest math, and the protocol ids. The libp2p transport stays in
//! `myotis-net`; a host with its own Noise/yamux uses these directly.

pub mod codec;
pub mod protocols;
pub mod status;
