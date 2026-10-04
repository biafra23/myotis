//! Bootstrapping from a caller-supplied checkpoint instead of the engine's
//! embedded one.
//!
//! The embedded checkpoint ages with the build; once it is past the
//! weak-subjectivity bound the node parks in STALE_ANCHOR. Besides consenting
//! to the stale anchor, the operator can pin a root they already trust with
//! `--checkpoint-root` / `--checkpoint-slot`, which go to the engine's
//! create-with-checkpoint path (the one the Node addon exposes as
//! `createWithCheckpoint`, #441). The daemon never fetches a root itself: the
//! only data sources are devp2p and libp2p, so where the root comes from is the
//! operator's decision, made outside this process.
//!
//! Trust: the pinned root is trusted as the ANCHOR only. The engine does not
//! authenticate it; it fetches a LightClientBootstrap for it from libp2p peers,
//! checks the bootstrap against the root, and from there verifies every later
//! header forward with sync-committee signatures exactly as it does from the
//! embedded checkpoint. A wrong root can pick the starting point, nothing after
//! it.

use std::ffi::CString;
use std::path::Path;

/// A checkpoint: the beacon block root (hash_tree_root of the header) and that
/// header's slot.
#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub root: String,
    pub slot: u64,
}

/// Validate an explicit `--checkpoint-root` / `--checkpoint-slot` pin.
pub fn explicit(root: &str, slot: u64) -> Result<Checkpoint, String> {
    let r = root.strip_prefix("0x").unwrap_or(root);
    if r.len() != 64 || !r.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("--checkpoint-root '{root}' is not 32 bytes of hex"));
    }
    if slot == 0 {
        return Err("--checkpoint-slot must be >= 1".into());
    }
    Ok(Checkpoint {
        root: format!("0x{}", r.to_ascii_lowercase()),
        slot,
    })
}

/// The anchor a data dir was bound to by an earlier create-with-checkpoint
/// (`sync-anchor[-net].json`, written by the engine). `Ok(None)` when the dir
/// has no marker; `Err` when one exists but cannot be read (the engine would
/// refuse it too).
pub fn bound_anchor(data_dir: &Path, network: &str) -> Result<Option<Checkpoint>, String> {
    let suffix = if network == "mainnet" {
        String::new()
    } else {
        format!("-{network}")
    };
    let path = data_dir.join(format!("sync-anchor{suffix}.json"));
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    match (v["checkpointRoot"].as_str(), v["checkpointSlot"].as_u64()) {
        (Some(r), Some(slot)) => explicit(r, slot).map(Some),
        _ => Err(format!("{}: not an anchor marker", path.display())),
    }
}

/// `myotis_create_with_checkpoint` (the engine's C ABI; `ffi` has no wrapper).
/// Same sentinels as `create`: -1 invalid input, -2 unsupported network, -3 the
/// data dir is bound to a different anchor.
pub fn create_handle(network: &str, data_dir: &str, cp: &Checkpoint) -> i64 {
    let (Ok(n), Ok(d), Ok(r)) = (
        CString::new(network),
        CString::new(data_dir),
        CString::new(cp.root.as_str()),
    ) else {
        return -1;
    };
    // SAFETY: three valid NUL-terminated C strings that outlive the call; the
    // engine copies them before returning.
    unsafe {
        myotis_engine::capi::myotis_create_with_checkpoint(
            n.as_ptr(),
            d.as_ptr(),
            r.as_ptr(),
            cp.slot,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_bad_pins() {
        assert!(explicit("0x1234", 5).is_err());
        assert!(explicit(&format!("0x{}", "zz".repeat(32)), 5).is_err());
        assert!(explicit(&"ab".repeat(32), 0).is_err());
        assert!(explicit(&"ab".repeat(32), 1).is_ok());
    }
}
