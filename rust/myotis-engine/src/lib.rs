//! The Rust implementation of the `io.myotis.api` engine contract, exposed to the
//! JVM via hand-JNI (compound records cross as JSON — see the phase-1 plan and
//! docs/reimplementation/05).
//!
//! PR 1 of the series only establishes the crate + build plumbing; the JNI surface
//! (`RustEngineNative` on the Java side) lands with the selector in PR 2. The ABI
//! version below is the stale-.so guard: the Java wrapper refuses to use a library
//! whose `nativeInit()` doesn't return the version it was compiled against.

/// Bumped whenever the JNI surface changes shape. Checked by the Java wrapper's
/// availability probe before any other native call.
pub const ABI_VERSION: i32 = 1;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;
