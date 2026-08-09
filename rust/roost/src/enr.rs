//! The ENR roost would publish — built and inspectable, not published.
//!
//! Publishing is deliberately not wired up here. A record in the DHT is
//! outward-facing and hard to retract: wallets cache it, and a wrong one is
//! worse than none, because they discover it, dial, fail, and spend their three
//! strikes to eviction (`clcache.rs`, `FAILURE_THRESHOLD = 3`) on a node that is
//! actually healthy. So the record is made buildable and printable first, and
//! the switch that puts it on the network is a separate, deliberate step.
//!
//! # The sequence number is the mechanism, not bookkeeping
//!
//! The DHT keeps the highest-sequence record it has seen for a node id. A record
//! that does not out-rank the cached one is **ignored** — so a sequence number
//! that resets on restart makes every later update silently ineffective, and the
//! update that matters most is the one carrying a changed IP. Persisting it
//! monotonically is what makes "re-publish on address change" work at all, which
//! is why it lives next to the key rather than in memory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// A persisted, monotonically increasing ENR sequence number.
#[derive(Debug)]
pub struct EnrSeq {
    path: PathBuf,
    current: u64,
}

impl EnrSeq {
    /// Load the sequence number, starting at 1 if there is none.
    ///
    /// A corrupt or unreadable file is a hard error rather than a reset to 1:
    /// silently restarting the sequence is exactly the failure this exists to
    /// prevent, and it would be invisible until an update failed to take.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let current = match std::fs::read_to_string(&path) {
            Ok(raw) => raw
                .trim()
                .parse::<u64>()
                .with_context(|| format!("parsing the ENR sequence number in {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, current })
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    /// Advance and persist, returning the new value.
    ///
    /// Written before it is used, not after: a crash between publishing and
    /// persisting would otherwise re-issue a number the network has already
    /// seen, and the DHT would ignore the re-issued record.
    pub fn bump(&mut self) -> Result<u64> {
        let next = self
            .current
            .checked_add(1)
            .context("ENR sequence number overflowed u64")?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Write-then-rename so a crash mid-write cannot leave a truncated number
        // that would parse as something smaller.
        let tmp = self.path.with_extension("seq.tmp");
        std::fs::write(&tmp, next.to_string())
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        self.current = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("roost-enr-seq-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn starts_at_one_and_survives_a_restart() {
        let path = tmp("restart");
        let mut seq = EnrSeq::load(&path).unwrap();
        assert_eq!(seq.current(), 1);
        assert_eq!(seq.bump().unwrap(), 2);
        assert_eq!(seq.bump().unwrap(), 3);

        // The restart is the case that matters: a reset here would make every
        // later update invisible to the DHT.
        let reloaded = EnrSeq::load(&path).unwrap();
        assert_eq!(reloaded.current(), 3);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_corrupt_file_fails_rather_than_silently_restarting_the_sequence() {
        let path = tmp("corrupt");
        std::fs::write(&path, "not a number").unwrap();
        assert!(
            EnrSeq::load(&path).is_err(),
            "resetting to 1 would make updates silently ineffective"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn is_monotonic_across_many_bumps() {
        let path = tmp("monotonic");
        let mut seq = EnrSeq::load(&path).unwrap();
        let mut last = seq.current();
        for _ in 0..50 {
            let next = seq.bump().unwrap();
            assert!(next > last, "sequence must strictly increase");
            last = next;
            assert_eq!(EnrSeq::load(&path).unwrap().current(), next, "persisted each time");
        }
        std::fs::remove_file(&path).ok();
    }
}
