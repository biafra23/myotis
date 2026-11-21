//! The addr1 address index on Swarm, as Myotis reads it (sans-I/O).
//!
//! The format is eth2swarm's `docs/address-index.md` at commit `a1b3923`
//! (<https://github.com/biafra23/eth2swarm>, branch `feature/address-index`), the revision the
//! data-source carve-out names (`.claude/agent/data-sources.md`, Swarm reads of the address
//! index). This crate holds what a reader needs and nothing that touches the network:
//!
//! - [`records`]: the identifiers and the binary records (`HeadRecord`, `SliceRecord`,
//!   `BucketRecord`, address records, spill and bucket pages), decoded strictly: anything an
//!   importer following the format would not produce is an error, so independent importers
//!   compare byte for byte.
//! - [`cover`]: which slices a head makes a client read, for an index from genesis or from a
//!   later unit, whole or incrementally.
//! - [`swarm`]: the checks of what Swarm delivered: a SOC's address and owner signature, a
//!   content-addressed chunk's address, a file's root reference.
//! - [`lookup`]: one address in one slice: its bucket, its records, its entries.
//!
//! Golden vectors: the known-answer encodings of eth2swarm's `layout.rs` and the file
//! references Bee 2.8.3 returned, in the tests.

pub mod client;
pub mod cover;
pub mod lookup;
pub mod records;
pub mod swarm;

/// What a reader rejected, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// `ensure!(cond, "format", args…)`: an [`Error`] unless `cond` holds.
macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err($crate::Error(format!($($fmt)+)));
        }
    };
}
pub(crate) use ensure;

/// An [`Error`] from a format string.
macro_rules! fail {
    ($($fmt:tt)+) => {
        $crate::Error(format!($($fmt)+))
    };
}
pub(crate) use fail;

/// Lowercase hex of `bytes`, for messages.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
