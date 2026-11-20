//! Swarm ACT (access control) storage structures.
//!
//! Bee's access control (`pkg/accesscontrol`) persists three artifacts
//! on Swarm, all of which this module reads and writes byte-compatibly:
//!
//! - **ACT key-value store** (`kvs/kvs.go`): a *simple* manifest — a
//!   JSON document `{"entries":{"<hex lookup key>":{"reference":"<hex
//!   sealed access key>"}}}` (bee `pkg/manifest/simple`, keys sorted by
//!   Go's `json.Marshal`) — stored through the plain pipeline at
//!   redundancy `NONE`. Each row maps a grantee's lookup key to their
//!   XOR-sealed copy of the 32-byte access key.
//! - **History** (`history.go`): a mantaray manifest (zero obfuscation
//!   key) whose keys are `strconv.FormatInt(math.MaxInt64 - unixTime)`
//!   — the *latest* epoch gets the lexicographically *smallest* key —
//!   and whose entries reference ACT kvs roots. Grantee updates add
//!   `{"encryptedglref": <hex>}` metadata. `Lookup(t)` walks value
//!   nodes in ascending key order (newest first) and picks the first
//!   epoch whose timestamp is `<= t`, falling back to the *oldest*
//!   epoch when `t` predates them all.
//! - **Grantee list** (`grantee.go`): the concatenation of 65-byte
//!   uncompressed SEC1 public keys, stored through the *encrypted*
//!   pipeline (64-byte reference), which is then wrapped once more for
//!   the publisher.
//!
//! Reads go through a [`ChunkFetcher`]; writes return [`SplitChunk`]s
//! for the caller to pushsync — mirroring how the manifest writer and
//! splitter integrate with the gateway upload path.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::joiner::{join, join_encrypted, JoinError, ENCRYPTED_REF_SIZE};
use crate::manifest_writer::{
    build_entries_manifest, ManifestWriteError, ManifestWriteResult, RawManifestEntry,
};
use crate::mantaray::{load_node_ref, ManifestError};
use crate::{ChunkAddr, ChunkFetcher};

/// History metadata key carrying the publisher-encrypted grantee-list
/// reference (bee `controller.go::UpdateHandler`).
pub const HISTORY_GRANTEE_LIST_KEY: &str = "encryptedglref";

/// Upper bound for joined ACT artifacts (kvs manifests, histories,
/// grantee lists). These are small (tens of rows); 4 MiB is generous
/// headroom while bounding a malicious reference.
const ACT_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ActError {
    /// The requested entry does not exist (bee `accesscontrol.ErrNotFound`).
    #[error("access control: not found")]
    NotFound,
    /// `Lookup` was called with a non-positive timestamp
    /// (bee `accesscontrol.ErrInvalidTimestamp`).
    #[error("invalid timestamp")]
    InvalidTimestamp,
    /// A history epoch with this key already exists. Bee's mantaray
    /// `Add` of an existing key on a lazily-loaded trie leaves the leaf
    /// with `forks == nil`, so `Store` fails with `ErrInvalidInput`
    /// ("input invalid") — the documented same-second-update failure
    /// (`controller.go` comment on `UpdateHandler`).
    #[error("input invalid")]
    DuplicateEpoch,
    #[error("fetch/join failed: {0}")]
    Join(#[from] JoinError),
    #[error("manifest read failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("manifest write failed: {0}")]
    Write(#[from] ManifestWriteError),
    #[error("malformed ACT key-value store: {0}")]
    MalformedKvs(String),
}

// --- ACT key-value store (bee pkg/accesscontrol/kvs over a simple manifest) ---

#[derive(Clone, Serialize, Deserialize)]
struct SimpleEntry {
    reference: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    metadata: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct SimpleManifest {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, SimpleEntry>,
}

/// In-memory ACT key-value store: hex lookup key → sealed access key.
///
/// Serialization matches bee's simple manifest JSON exactly: object
/// keys sorted (Go's `json.Marshal` map ordering), `metadata` omitted
/// when empty, no whitespace.
#[derive(Default)]
pub struct ActKvs {
    entries: BTreeMap<String, SimpleEntry>,
    /// Number of `put`s since load/creation — bee's `putCnt`, whose
    /// zero value makes `Save` fail with `ErrNothingToSave`.
    puts: usize,
}

impl ActKvs {
    /// Empty store (bee `kvs.New`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load an existing store by joining its 32-byte reference
    /// (bee `kvs.NewReference`).
    pub async fn load(fetcher: &dyn ChunkFetcher, reference: ChunkAddr) -> Result<Self, ActError> {
        let bytes = load_plain(fetcher, reference).await?;
        let manifest: SimpleManifest = serde_json::from_slice(&bytes)
            .map_err(|e| ActError::MalformedKvs(format!("parse simple manifest: {e}")))?;
        Ok(Self {
            entries: manifest.entries,
            puts: 0,
        })
    }

    /// Fetch the value stored under `key` (bee `kvs.Get`, which reads
    /// the entry's "reference" hex back into bytes).
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let entry = self.entries.get(&hex::encode(key))?;
        hex::decode(&entry.reference).ok()
    }

    /// Store `value` under `key` (bee `kvs.Put`).
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.entries.insert(
            hex::encode(key),
            SimpleEntry {
                reference: hex::encode(value),
                metadata: BTreeMap::new(),
            },
        );
        self.puts += 1;
    }

    /// Whether `save` would fail bee-style with `ErrNothingToSave`
    /// (`kvs.Save` on a store that saw no `Put` since load).
    #[must_use]
    pub fn nothing_to_save(&self) -> bool {
        self.puts == 0
    }

    /// Serialize to the exact JSON bytes bee's simple manifest
    /// marshals; the caller stores them through the plain splitter.
    #[must_use]
    pub fn to_manifest_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&SimpleManifest {
            entries: self.entries.clone(),
        })
        .expect("kvs manifest serializes")
    }
}

// --- history (bee pkg/accesscontrol/history.go) ---

/// One history epoch: a reversed-timestamp key, the ACT kvs root it
/// references, and its fork metadata.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Manifest key: `(i64::MAX - unix_seconds)` in decimal.
    pub key: String,
    /// 32-byte ACT kvs root reference.
    pub reference: ChunkAddr,
    pub metadata: BTreeMap<String, String>,
}

impl HistoryEntry {
    /// The epoch's original unix timestamp, when the key parses.
    #[must_use]
    pub fn timestamp(&self) -> Option<i64> {
        self.key.parse::<i64>().ok().map(|rev| i64::MAX - rev)
    }
}

/// Bee's history key for a unix timestamp:
/// `strconv.FormatInt(math.MaxInt64 - unixTime, 10)`.
#[must_use]
pub fn history_key(unix_time: i64) -> String {
    (i64::MAX - unix_time).to_string()
}

/// Load every value entry of a history manifest, in bee's `WalkNode`
/// order: ascending fork-byte order at every level, i.e. ascending
/// lexicographic key order — the *newest* epoch first (keys are
/// reversed timestamps).
pub async fn history_entries(
    fetcher: &dyn ChunkFetcher,
    root: ChunkAddr,
) -> Result<Vec<HistoryEntry>, ActError> {
    let node = load_node_ref(fetcher, &root).await?;
    let mut out = Vec::new();
    walk_history(fetcher, &node, String::new(), &mut out).await?;
    Ok(out)
}

fn walk_history<'a>(
    fetcher: &'a dyn ChunkFetcher,
    node: &'a crate::mantaray::Node,
    path: String,
    out: &'a mut Vec<HistoryEntry>,
) -> futures::future::BoxFuture<'a, Result<(), ActError>> {
    Box::pin(async move {
        let mut fork_keys: Vec<u8> = node.forks.keys().copied().collect();
        fork_keys.sort_unstable();
        for k in fork_keys {
            let fork = &node.forks[&k];
            let fork_path = format!("{path}{}", String::from_utf8_lossy(&fork.prefix));
            let child = load_node_ref(fetcher, &fork.child_ref).await?;
            // Bee's walker records nodes with `IsValueType() &&
            // len(Entry()) > 0`; ant's parser keeps a value node's
            // entry bytes verbatim (all-zero = no entry).
            if child.entry.iter().any(|&b| b != 0) {
                let reference: ChunkAddr = child.entry.as_slice().try_into().map_err(|_| {
                    ActError::Manifest(ManifestError::InvalidRefLength(child.entry.len() as u8))
                })?;
                out.push(HistoryEntry {
                    key: fork_path.clone(),
                    reference,
                    metadata: fork
                        .metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                });
            }
            walk_history(fetcher, &child, fork_path, out).await?;
        }
        Ok(())
    })
}

/// Bee's `History.Lookup`: pick the epoch for `timestamp` from entries
/// in walk order (newest first). The first epoch whose timestamp is
/// `<= timestamp` wins; a timestamp older than every epoch falls back
/// to the *oldest* epoch; an empty history is `NotFound`; a
/// non-positive timestamp is `InvalidTimestamp`.
pub fn history_lookup(entries: &[HistoryEntry], timestamp: i64) -> Result<&HistoryEntry, ActError> {
    if timestamp <= 0 {
        return Err(ActError::InvalidTimestamp);
    }
    let searched_reversed = i64::MAX - timestamp;
    let mut after: Option<&HistoryEntry> = None;
    for entry in entries {
        after = Some(entry);
        // bee `isBeforeMatch`: unparseable keys abort the walk; a key
        // of exactly "0" never matches.
        let target: i64 = entry
            .key
            .parse()
            .map_err(|_| ActError::MalformedKvs(format!("bad history key {}", entry.key)))?;
        if target != 0 && searched_reversed <= target {
            return Ok(entry);
        }
    }
    after.ok_or(ActError::NotFound)
}

/// Append a new epoch and rebuild the history manifest. Bee's mantaray
/// `Add` of an already-present key on a freshly loaded trie makes the
/// subsequent `Store` fail (`ErrInvalidInput`) — the same-second update
/// limitation — so a duplicate key is [`ActError::DuplicateEpoch`].
///
/// The rebuild produces the same canonical prefix-compressed trie bee's
/// incremental adds maintain, hence the same root reference (pinned by
/// the deterministic `act.json` history vectors).
pub fn history_with_epoch(
    entries: &[HistoryEntry],
    key: String,
    reference: ChunkAddr,
    metadata: BTreeMap<String, String>,
) -> Result<ManifestWriteResult, ActError> {
    if entries.iter().any(|e| e.key == key) {
        return Err(ActError::DuplicateEpoch);
    }
    let mut raw: Vec<RawManifestEntry> = entries
        .iter()
        .map(|e| RawManifestEntry {
            path: e.key.clone(),
            reference: e.reference,
            metadata: e.metadata.clone(),
        })
        .collect();
    raw.push(RawManifestEntry {
        path: key,
        reference,
        metadata,
    });
    Ok(build_entries_manifest(&raw)?)
}

// --- grantee list (bee pkg/accesscontrol/grantee.go) ---

/// Serialize grantee public keys as concatenated 65-byte uncompressed
/// SEC1 points (bee `grantee.go::serialize`).
#[must_use]
pub fn serialize_grantees(grantees: &[k256::PublicKey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(grantees.len() * 65);
    for g in grantees {
        out.extend_from_slice(&ant_crypto::act::uncompress_public_key(g));
    }
    out
}

/// Deserialize a grantee list. Bee returns an *empty list* — not an
/// error — for malformed input (`grantee.go::deserialize` bails to
/// `[]` when any key fails to parse); mirror that.
#[must_use]
pub fn deserialize_grantees(data: &[u8]) -> Vec<k256::PublicKey> {
    if data.is_empty() || !data.len().is_multiple_of(65) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len() / 65);
    for chunk in data.chunks(65) {
        match ant_crypto::act::parse_public_key(chunk) {
            Ok(pk) => out.push(pk),
            Err(_) => return Vec::new(),
        }
    }
    out
}

// --- shared loaders ---

/// Join a plain 32-byte reference into its full byte payload (the
/// loadsave `Load` path bee uses for kvs manifests and histories).
pub async fn load_plain(
    fetcher: &dyn ChunkFetcher,
    reference: ChunkAddr,
) -> Result<Vec<u8>, ActError> {
    let root_chunk = fetcher.fetch(reference).await.map_err(|e| {
        ActError::Join(JoinError::FetchChunk {
            addr: hex::encode(reference),
            source: e,
        })
    })?;
    Ok(join(fetcher, &root_chunk, ACT_MAX_BYTES).await?)
}

/// Join an encrypted 64-byte reference (the grantee-list load path).
pub async fn load_encrypted(
    fetcher: &dyn ChunkFetcher,
    reference: [u8; ENCRYPTED_REF_SIZE],
) -> Result<Vec<u8>, ActError> {
    Ok(join_encrypted(fetcher, reference, ACT_MAX_BYTES).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvs_serializes_like_go_simple_manifest() {
        let mut kvs = ActKvs::new();
        kvs.put(&[0xbb; 4], &[0x02; 3]);
        kvs.put(&[0xaa; 4], &[0x01; 3]);
        assert_eq!(
            String::from_utf8(kvs.to_manifest_bytes()).unwrap(),
            r#"{"entries":{"aaaaaaaa":{"reference":"010101"},"bbbbbbbb":{"reference":"020202"}}}"#
        );
        assert_eq!(kvs.get(&[0xaa; 4]).unwrap(), vec![0x01; 3]);
        assert!(kvs.get(&[0xcc; 4]).is_none());
        assert!(!kvs.nothing_to_save());
        assert!(ActKvs::new().nothing_to_save());
    }

    #[test]
    fn history_key_reverses_timestamp() {
        assert_eq!(history_key(1_700_000_000), "9223372035154775807");
    }

    fn entry(ts: i64) -> HistoryEntry {
        HistoryEntry {
            key: history_key(ts),
            reference: [ts as u8; 32],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn history_lookup_matches_bee_walk_semantics() {
        // Walk order = ascending key = descending timestamp.
        let mut entries = vec![entry(100), entry(50), entry(10)];
        entries.sort_by(|a, b| a.key.cmp(&b.key));

        // Exact and in-between hits pick the closest epoch <= t.
        assert_eq!(
            history_lookup(&entries, 100).unwrap().timestamp(),
            Some(100)
        );
        assert_eq!(history_lookup(&entries, 70).unwrap().timestamp(), Some(50));
        assert_eq!(history_lookup(&entries, 10).unwrap().timestamp(), Some(10));
        // Future timestamps get the newest epoch.
        assert_eq!(
            history_lookup(&entries, 1 << 40).unwrap().timestamp(),
            Some(100)
        );
        // Before-all falls back to the OLDEST epoch (bee's afterNode).
        assert_eq!(history_lookup(&entries, 5).unwrap().timestamp(), Some(10));
        // Non-positive timestamps are invalid.
        assert!(matches!(
            history_lookup(&entries, 0),
            Err(ActError::InvalidTimestamp)
        ));
        // Empty history is NotFound.
        assert!(matches!(history_lookup(&[], 5), Err(ActError::NotFound)));
    }

    #[test]
    fn duplicate_epoch_is_rejected() {
        let entries = vec![entry(100)];
        let err =
            history_with_epoch(&entries, history_key(100), [1u8; 32], BTreeMap::new()).unwrap_err();
        assert!(matches!(err, ActError::DuplicateEpoch));
    }

    #[test]
    fn grantee_list_round_trips_and_tolerates_garbage() {
        let a = ant_crypto::act::public_key_of(&[0x11; 32]).unwrap();
        let b = ant_crypto::act::public_key_of(&[0x22; 32]).unwrap();
        let data = serialize_grantees(&[a, b]);
        assert_eq!(data.len(), 130);
        assert_eq!(deserialize_grantees(&data), vec![a, b]);
        assert_eq!(
            deserialize_grantees(&[0u8; 65]),
            [] as [k256::elliptic_curve::PublicKey<k256::Secp256k1>; 0]
        );
        assert_eq!(
            deserialize_grantees(&data[..64]),
            [] as [k256::elliptic_curve::PublicKey<k256::Secp256k1>; 0]
        );
        assert_eq!(
            deserialize_grantees(&[]),
            [] as [k256::elliptic_curve::PublicKey<k256::Secp256k1>; 0]
        );
    }
}
