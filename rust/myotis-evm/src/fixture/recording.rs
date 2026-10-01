//! [`RecordingOracle`]: keep every verified answer an executor asked for.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use revm::primitives::U256;

use crate::oracle::{OracleAccount, OracleError, SnapStateOracle};

/// The state one or more runs read: what a replay needs, keyed like the
/// oracle's own answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedWorld {
    /// The state root every account and storage read was made against.
    pub state_root: [u8; 32],
    /// Each account read — `None` where the proof showed it absent.
    pub accounts: BTreeMap<[u8; 20], Option<OracleAccount>>,
    /// Each storage read, by account, then by raw 32-byte slot.
    pub storage: BTreeMap<[u8; 20], BTreeMap<[u8; 32], U256>>,
    /// Each bytecode read, by its code hash.
    pub code: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Default)]
struct Recording {
    /// Bound by the first account or storage read.
    state_root: Option<[u8; 32]>,
    world: RecordedWorld,
}

impl Recording {
    /// The world for a read against `state_root`, or the read's failure when
    /// the recording is already bound to another root.
    fn bind(&mut self, state_root: &[u8; 32], address: [u8; 20], slot: Option<U256>) -> Result<&mut RecordedWorld, OracleError> {
        let bound = *self.state_root.get_or_insert(*state_root);
        if &bound != state_root {
            return Err(OracleError::StateUnavailable {
                state_root: *state_root,
                address,
                slot: slot.map(|s| s.to_be_bytes::<32>()),
            });
        }
        self.world.state_root = bound;
        Ok(&mut self.world)
    }
}

/// A [`SnapStateOracle`] that answers from `inner` and keeps every answer.
///
/// It adds nothing to what `inner` verified. It does NOT forward
/// [`SnapStateOracle::prefetch_batch`]: a prefetch writes straight into the
/// executor's caches, so its reads would never pass through here. Every read
/// takes the per-item path instead, which is slower and complete. For the same
/// reason, build the executor over EMPTY caches: a cached value is not
/// re-read.
///
/// One recording spans one state root; a read against another root fails
/// (an error, not a panic, for recorders built with `panic = "abort"`), since
/// the result would be a world no block ever had.
pub struct RecordingOracle {
    inner: Arc<dyn SnapStateOracle>,
    recording: Mutex<Recording>,
}

impl RecordingOracle {
    pub fn new(inner: Arc<dyn SnapStateOracle>) -> RecordingOracle {
        RecordingOracle { inner, recording: Mutex::new(Recording::default()) }
    }

    /// Everything read so far.
    pub fn recorded(&self) -> RecordedWorld {
        self.lock().world.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Recording> {
        // A poisoned lock only means another recording thread panicked; the
        // maps are still consistent (every insert is a single call).
        self.recording.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SnapStateOracle for RecordingOracle {
    fn check_request(&self) -> Result<(), OracleError> {
        self.inner.check_request()
    }

    fn fetch_account(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<OracleAccount>, OracleError> {
        let account = self.inner.fetch_account(state_root, address)?;
        self.lock().bind(state_root, address, None)?.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn fetch_storage(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
        slot: U256,
    ) -> Result<U256, OracleError> {
        let value = self.inner.fetch_storage(state_root, address, slot)?;
        self.lock()
            .bind(state_root, address, Some(slot))?
            .storage
            .entry(address)
            .or_default()
            .insert(slot.to_be_bytes::<32>(), value);
        Ok(value)
    }

    fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        // Content-addressed, so not tied to the root.
        let code = self.inner.fetch_bytecode(code_hash)?;
        self.lock().world.code.insert(*code_hash, code.clone());
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::FixtureSnapStateOracle;
    use myotis_core::trie::EMPTY_TRIE_ROOT;

    const ROOT: [u8; 32] = [0x44; 32];

    #[test]
    fn keeps_every_answer_including_proven_absence() {
        let mut inner = FixtureSnapStateOracle::new();
        let code_hash = inner.with_bytecode(vec![0x60, 0x00]);
        let present = OracleAccount { nonce: 1, balance: U256::from(7u64), code_hash, storage_root: EMPTY_TRIE_ROOT };
        let inner = inner.with_account(ROOT, [1; 20], present.clone()).with_storage(ROOT, [1; 20], [9; 32], U256::from(5u64));
        let oracle = RecordingOracle::new(Arc::new(inner));

        assert_eq!(oracle.fetch_account(&ROOT, [1; 20]).unwrap(), Some(present.clone()));
        assert_eq!(oracle.fetch_account(&ROOT, [2; 20]).unwrap(), None);
        assert_eq!(oracle.fetch_storage(&ROOT, [1; 20], U256::from_be_bytes([9; 32])).unwrap(), U256::from(5u64));
        assert_eq!(oracle.fetch_storage(&ROOT, [1; 20], U256::from(3u64)).unwrap(), U256::ZERO);
        assert_eq!(oracle.fetch_bytecode(&code_hash).unwrap(), vec![0x60, 0x00]);

        let world = oracle.recorded();
        assert_eq!(world.state_root, ROOT);
        assert_eq!(world.accounts.get(&[1; 20]), Some(&Some(present)));
        assert_eq!(world.accounts.get(&[2; 20]), Some(&None), "a proven absence is part of the world");
        let slots = &world.storage[&[1; 20]];
        assert_eq!(slots[&[9; 32]], U256::from(5u64));
        assert_eq!(slots[&U256::from(3u64).to_be_bytes::<32>()], U256::ZERO, "a zero slot is recorded too");
        assert_eq!(world.code[&code_hash], vec![0x60, 0x00]);
    }

    #[test]
    fn refuses_to_mix_state_roots() {
        let oracle = RecordingOracle::new(Arc::new(FixtureSnapStateOracle::new()));
        oracle.fetch_account(&ROOT, [1; 20]).unwrap();
        assert!(matches!(oracle.fetch_account(&[0x45; 32], [1; 20]), Err(OracleError::StateUnavailable { .. })));
        assert_eq!(oracle.recorded().state_root, ROOT);
    }
}
