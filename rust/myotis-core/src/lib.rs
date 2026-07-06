//! Myotis execution-layer primitives (EL-A1 of the EL phase —
//! docs/reimplementation/07-el-implementation-plan.md).
//!
//! Sans-I/O by rule: no sockets, filesystem, clock, or entropy. Everything here
//! is a pure function over caller-supplied bytes, mirroring the Java `:core`
//! module (`com.jaeckel.ethp2p.core`) and pinned against it by the shared
//! conformance corpus in `rust/testdata/el/core/`.
//!
//! Twins on the Java side:
//! - [`rlp`]      ⇄ Tuweni `RLP` usage in `core`/`networking`
//! - [`keccak`]   ⇄ Tuweni `Hash.keccak256`
//! - [`nodekey`]  ⇄ `core.crypto.NodeKey`
//! - [`header`]   ⇄ `core.types.BlockHeader`
//! - [`enr`]      ⇄ `core.enr.Enr`
//! - [`forkid`]   ⇄ the pinned EIP-2124 constants in `networking.NetworkConfig`
//!
//! Error convention (workspace-wide): `Result<_, CoreError>` with Java-shaped
//! messages; decoding untrusted bytes never panics (the workspace builds with
//! `panic = "abort"`, so a panic crossing JNI kills the host process).

pub mod enr;
pub mod forkid;
pub mod header;
pub mod keccak;
pub mod nodekey;
pub mod rlp;

/// Single error type for this crate, mirroring `SszError(String)` in
/// `myotis-consensus`: a message, no hierarchy (FFI-flat by design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError(pub String);

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CoreError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, CoreError> {
    Err(CoreError(msg.into()))
}
