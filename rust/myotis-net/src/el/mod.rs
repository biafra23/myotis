//! Execution-layer networking (the EL phase, docs/reimplementation/07).
//!
//! Twins of the Java `com.jaeckel.ethp2p.networking` module, arriving PR by
//! PR: discv4 (EL-A3), RLPx (EL-A4), eth/66-69 (EL-A5), snap/1 (EL-A6).
//! Pure wire codecs live beside the tokio I/O that drives them, the same
//! split `codec.rs`/`reqresp.rs` uses on the CL side; the codecs are pinned
//! against Java-generated conformance corpora under `rust/testdata/el/`.

pub mod anchor;
pub mod discv4;
pub mod eth;
pub mod peer;
pub mod rlpx;
pub mod snap;
pub mod verify;
