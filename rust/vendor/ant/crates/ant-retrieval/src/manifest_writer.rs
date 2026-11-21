//! Mantaray v0.2 manifest writer.
//!
//! The inverse of [`crate::mantaray`]. Builds the chunks that bee's
//! `mantaray.NodeMarshalBinary` would emit, given a list of files
//! already split into chunk trees by [`crate::splitter::split_bytes`].
//!
//! Wire shape (de-obfuscated; we always emit the all-zero obfuscation
//! key, which matches what `swarm-cli upload` produces for unencrypted
//! manifests):
//!
//! ```text
//! [0..32]   obfuscation key (zeros)
//! [32..63]  31-byte version hash for "mantaray:0.2"
//! [63]      ref-bytes-size (0x20 if the node has any forks or its own
//!           entry; 0x00 only for empty placeholder leaves)
//! [64..96]  entry (32 bytes: data ref, or zeros for nodes that only
//!           anchor metadata-bearing forks). Omitted when ref-size is 0.
//! [+0..+32] 256-bit forks bitmap; bit `b` set ⇒ a fork starts on byte b
//! [forks…]  ascending bit order; for each set bit:
//!             - 1 byte  type      (2=value, 4=edge, 8=path-separator,
//!                                  16=with-metadata; bitwise-or)
//!             - 1 byte  prefix-len (1..30)
//!             - 30 bytes prefix    (only the first prefix-len matter)
//!             - 32 bytes child reference
//!             - if (type & 16): 2 BE bytes meta length, then JSON
//!               metadata padded with '\n' so that
//!               (meta_len + 2) is a multiple of 32
//! ```
//!
//! The fork-as-a-whole alignment is important: a parser that wants to
//! seek forward fork-by-fork relies on each fork occupying a whole
//! number of 32-byte blocks.
//!
//! Manifests are emitted as a proper recursive trie: every node fits in
//! one CAC chunk, and large collections naturally deepen the tree
//! instead of overflowing a single root chunk. A flat 12-file collection
//! lands in a single root chunk; a 200-file site distributes across
//! ~20–40 chunks (root + per-prefix sub-tries). Path segments longer
//! than [`MAX_FILENAME_BYTES`] are split into chained 30-byte forks
//! transparently — bee's reader walks the chain identically to a
//! single-fork prefix.

use std::collections::BTreeMap;

use ant_crypto::{cac_new, CHUNK_SIZE};
use thiserror::Error;

use crate::enc_split::{split_bytes_encrypted, ENC_REF_SIZE};

/// Store one serialized manifest node, appending its chunks to the
/// output; returns the node's reference (32 bytes plain / 64 encrypted).
type NodeSaver<'a> =
    &'a mut dyn FnMut(&[u8], &mut Vec<SplitChunk>) -> Result<Vec<u8>, ManifestWriteError>;
use crate::splitter::SplitChunk;
use crate::{ChunkAddr, MANTARAY_CONTENT_TYPE_KEY, MANTARAY_INDEX_DOC_KEY};

/// 31 leading bytes of `keccak256("mantaray:0.2")`. Bee writes only the
/// first 31 bytes on the wire (`versionHashSize = 31`).
const VERSION_HASH_31: [u8; 31] = [
    0x57, 0x68, 0xb3, 0xb6, 0xa7, 0xdb, 0x56, 0xd2, 0x1d, 0x1a, 0xbf, 0xf4, 0x0d, 0x41, 0xce, 0xbf,
    0xc8, 0x34, 0x48, 0xfe, 0xd8, 0xd7, 0xe9, 0xb0, 0x6e, 0xc0, 0xd3, 0xb0, 0x73, 0xf2, 0x8f,
];

const NODE_TYPE_VALUE: u8 = 2;
const NODE_TYPE_EDGE: u8 = 4;
const NODE_TYPE_PATH_SEPARATOR: u8 = 8;
const NODE_TYPE_WITH_METADATA: u8 = 16;

/// Bee's hard cap on per-fork prefix length: 30 bytes (the on-wire
/// prefix slot is a fixed 30-byte zero-padded field). Path segments
/// longer than this are emitted as chained 30-byte forks with
/// synthetic single-fork intermediate nodes — bee's reader walks the
/// chain identically to a flat prefix.
pub const MAX_FILENAME_BYTES: usize = 30;

/// One file to add to a collection manifest.
#[derive(Debug, Clone)]
pub struct ManifestFile {
    /// Path inside the manifest (no leading slash). May contain slashes
    /// to nest into subdirectories. Each path segment must be ≤
    /// [`MAX_FILENAME_BYTES`] bytes.
    pub path: String,
    /// MIME type written into the file fork's metadata. `None` falls
    /// back to `application/octet-stream`, matching bee's default.
    pub content_type: Option<String>,
    /// Reference to the file's data root: the 32-byte root chunk
    /// address (usually [`crate::splitter::SplitResult::root`]) for
    /// plain manifests, or the 64-byte `address ‖ key` encrypted
    /// reference ([`crate::enc_split::EncryptedSplitResult::root_ref`])
    /// for encrypted ones. Width must match the builder used.
    pub data_ref: Vec<u8>,
}

/// Result of building a manifest: the manifest root reference, plus
/// every chunk that has to be pushed to Swarm to make the manifest
/// retrievable. The root chunk is always the *last* entry.
#[derive(Debug, Clone)]
pub struct ManifestWriteResult {
    pub root: ChunkAddr,
    pub chunks: Vec<SplitChunk>,
}

#[derive(Debug, Error)]
pub enum ManifestWriteError {
    /// A path segment exceeds the 30-byte fork-prefix limit. Today bee
    /// uses chained forks for long names; we don't yet emit those.
    #[error("path segment too long: {segment} bytes (cap {cap})")]
    SegmentTooLong { segment: usize, cap: usize },
    /// Empty path was passed in a multi-file collection. The single-file
    /// helper assigns its own filename, so this only ever fires for the
    /// collection variant.
    #[error("empty path is not allowed in a manifest")]
    EmptyPath,
    /// The serialised root manifest exceeds [`CHUNK_SIZE`]. Today this
    /// happens only for collections with very many or very long names;
    /// the proper fix is to split the manifest itself across an
    /// intermediate join chunk, which is future work. (Encrypted
    /// manifests don't hit this: their nodes go through the splitter
    /// and may span multiple chunks.)
    #[error("manifest root payload {size} bytes exceeds chunk capacity {cap}; multi-chunk manifests not yet supported")]
    ManifestTooBig { size: usize, cap: usize },
    /// A file's `data_ref` width doesn't match the builder (32 for
    /// plain manifests, 64 for encrypted ones).
    #[error("data reference is {have} bytes; this builder needs {want}")]
    RefWidth { have: usize, want: usize },
}

/// Build a single-file manifest with a `website-index-document` pointing
/// at `filename`, so both `bzz://<root>/<filename>` and the bare
/// `bzz://<root>/` resolve to the same data. Mirrors what
/// `swarm-cli upload <file>` produces.
///
/// `data_ref` is the file's root chunk address, typically the `root`
/// field of a [`crate::splitter::SplitResult`]. The file's *data* chunks
/// are **not** included in the returned `chunks`; the caller is
/// responsible for pushing those (the splitter already returns them).
pub fn build_single_file_manifest(
    filename: &str,
    content_type: Option<&str>,
    data_ref: ChunkAddr,
) -> Result<ManifestWriteResult, ManifestWriteError> {
    build_collection_manifest(
        &[ManifestFile {
            path: filename.to_string(),
            content_type: content_type.map(str::to_string),
            data_ref: data_ref.to_vec(),
        }],
        Some(filename),
        IndexAnchor::EmptyNode,
    )
}

/// [`build_single_file_manifest`] for an **encrypted** upload
/// (`swarm-encrypt: true` on `POST /bzz`): the file's data reference is
/// the 64-byte `address ‖ key`, every manifest node is itself stored
/// encrypted (via [`crate::enc_split`], at redundancy `level` like bee's
/// `loadsave` with an encrypting pipeline factory), fork/entry
/// references are 64 bytes wide and each node gets a fresh random
/// obfuscation key (bee generates one whenever the manifest is built
/// with `encrypted = true`).
pub fn build_single_file_manifest_encrypted(
    filename: &str,
    content_type: Option<&str>,
    data_ref: &[u8; ENC_REF_SIZE],
    level: u8,
) -> Result<EncryptedManifestWriteResult, ManifestWriteError> {
    build_collection_manifest_encrypted(
        &[ManifestFile {
            path: filename.to_string(),
            content_type: content_type.map(str::to_string),
            data_ref: data_ref.to_vec(),
        }],
        Some(filename),
        IndexAnchor::EmptyNode,
        level,
    )
}

/// Shape of the synthetic `/` index-document anchor's child node. Bee
/// emits different bytes from its two upload code paths, and manifest
/// references only match bee's if ant mirrors the distinction:
/// single-file uploads (`bzz.go` file handler) produce a refsize-0
/// empty node; tar/multipart dir uploads (`dirs.go`) store
/// `swarm.ZeroAddress`, i.e. a 32-byte zero entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexAnchor {
    EmptyNode,
    ZeroEntry,
}

/// Build a manifest covering many files. `files` is a list of distinct
/// paths and their pre-split data references. If any path equals
/// `index_document` (typically `"index.html"`), the root carries a
/// `website-index-document` metadata pointer so `bzz://<root>/` serves
/// that file.
///
/// The writer constructs a real radix trie: every node serializes to
/// exactly one CAC chunk, and large collections naturally deepen the
/// tree instead of overflowing the root. Path segments longer than
/// [`MAX_FILENAME_BYTES`] are emitted as chained 30-byte forks with
/// synthetic single-fork intermediate nodes — bee's reader walks the
/// chain identically. Returns
/// [`ManifestWriteError::ManifestTooBig`] only in the pathological
/// case where one trie level has so many forks (with metadata) that a
/// single node exceeds [`CHUNK_SIZE`]; in practice this requires
/// 50+ siblings sharing a prefix at the same trie depth.
pub fn build_collection_manifest(
    files: &[ManifestFile],
    index_document: Option<&str>,
    anchor: IndexAnchor,
) -> Result<ManifestWriteResult, ManifestWriteError> {
    let root = build_collection_trie(files, index_document, anchor, 32)?;
    // Serialize bottom-up. Plain nodes must each fit one CAC chunk.
    let mut chunks: Vec<SplitChunk> = Vec::new();
    let mut saver =
        |payload: &[u8], out: &mut Vec<SplitChunk>| -> Result<Vec<u8>, ManifestWriteError> {
            if payload.len() > CHUNK_SIZE {
                return Err(ManifestWriteError::ManifestTooBig {
                    size: payload.len(),
                    cap: CHUNK_SIZE,
                });
            }
            let (addr, wire) = cac_payload(payload);
            out.push(SplitChunk {
                address: addr,
                wire,
            });
            Ok(addr.to_vec())
        };
    let root_ref = serialize_node(&root, &mut chunks, &mut saver)?;
    let root_addr: ChunkAddr = root_ref
        .as_slice()
        .try_into()
        .expect("plain saver returns 32-byte refs");
    Ok(ManifestWriteResult {
        root: root_addr,
        chunks,
    })
}

/// Result of building an **encrypted** manifest: the 64-byte root
/// reference, the root node chunk's stored (encrypted) wire bytes for
/// dispersed replicas, and every chunk to push.
#[derive(Debug, Clone)]
pub struct EncryptedManifestWriteResult {
    pub root_ref: [u8; ENC_REF_SIZE],
    pub root_wire: Vec<u8>,
    pub chunks: Vec<SplitChunk>,
    /// `(address, stored wire)` of every node's pipeline root — each
    /// manifest node is saved through its own mini-pipeline (bee
    /// loadsave), so each counts as a root for dispersed replicas at
    /// redundancy level > 0. The manifest root itself is the last
    /// entry.
    pub node_roots: Vec<(ChunkAddr, Vec<u8>)>,
}

impl EncryptedManifestWriteResult {
    /// The manifest root chunk's 32-byte stored address.
    #[must_use]
    pub fn root_address(&self) -> ChunkAddr {
        self.root_ref[..32].try_into().expect("64-byte root ref")
    }
}

/// [`build_collection_manifest`] for an encrypted upload: 64-byte
/// `data_ref`s, 64-byte fork/entry slots, random per-node obfuscation
/// keys, and every node stored through the encrypted splitter at
/// redundancy `level` (mirroring bee's `loadsave` with an encrypting
/// pipeline factory). Encrypted manifests are inherently nondeterministic
/// (random chunk keys *and* random obfuscation keys), exactly like
/// bee's.
pub fn build_collection_manifest_encrypted(
    files: &[ManifestFile],
    index_document: Option<&str>,
    anchor: IndexAnchor,
    level: u8,
) -> Result<EncryptedManifestWriteResult, ManifestWriteError> {
    let root = build_collection_trie(files, index_document, anchor, ENC_REF_SIZE)?;
    let mut chunks: Vec<SplitChunk> = Vec::new();
    let mut node_roots: Vec<(ChunkAddr, Vec<u8>)> = Vec::new();
    let mut saver =
        |payload: &[u8], out: &mut Vec<SplitChunk>| -> Result<Vec<u8>, ManifestWriteError> {
            let split = split_bytes_encrypted(payload, level);
            node_roots.push((split.root_address(), split.root_wire));
            out.extend(split.chunks);
            Ok(split.root_ref.to_vec())
        };
    let root_ref_vec = serialize_node(&root, &mut chunks, &mut saver)?;
    let root_ref: [u8; ENC_REF_SIZE] = root_ref_vec
        .as_slice()
        .try_into()
        .expect("encrypted saver returns 64-byte refs");
    // Nodes serialize bottom-up, so the root's pipeline is the last.
    let root_wire = node_roots
        .last()
        .map(|(_, wire)| wire.clone())
        .expect("at least the root node was saved");
    Ok(EncryptedManifestWriteResult {
        root_ref,
        root_wire,
        chunks,
        node_roots,
    })
}

/// Shared trie construction for the plain and encrypted builders.
/// `ref_size` (32 or 64) sets the width of the zero-entry anchor and is
/// validated against every file's `data_ref`.
fn build_collection_trie(
    files: &[ManifestFile],
    index_document: Option<&str>,
    anchor: IndexAnchor,
    ref_size: usize,
) -> Result<TrieNode, ManifestWriteError> {
    if files.is_empty() {
        return Err(ManifestWriteError::EmptyPath);
    }
    for f in files {
        if f.path.is_empty() {
            return Err(ManifestWriteError::EmptyPath);
        }
        // Duplicate paths are allowed: bee's mantaray `Add` simply
        // overwrites the entry at the existing node, so within one
        // upload the LAST write wins (a tar may legally repeat a
        // member name). `trie_insert` mirrors that by overwriting
        // `own_data_ref`/`own_metadata` when the path already exists.
        if f.data_ref.len() != ref_size {
            return Err(ManifestWriteError::RefWidth {
                have: f.data_ref.len(),
                want: ref_size,
            });
        }
    }

    // Build the in-memory trie.
    let mut root = TrieNode::default();
    for f in files {
        let ct = f
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        trie_insert(
            &mut root,
            f.path.as_bytes(),
            f.data_ref.clone(),
            file_metadata(&ct, &f.path),
        )?;
    }

    // Index-document anchor on the synthetic '/' fork at the root.
    if let Some(idx) = index_document {
        // bee's bzzUploadHandler always sets the '/' fork's metadata
        // to website-index-document, regardless of whether the named
        // file exists in the manifest. If it doesn't, bee returns 404
        // when bzz://<root>/ is hit; we mirror that exactly.
        //
        // The anchor's child node differs between bee's two upload
        // paths and both must hash to bee's exact bytes: the
        // single-file handler emits a refsize-0 empty node, while the
        // dir handler stores swarm.ZeroAddress — a ref-width zero entry
        // (dirs.go `manifest.NewEntry(swarm.ZeroAddress, metadata)`).
        let idx_node = match anchor {
            IndexAnchor::EmptyNode => TrieNode {
                value: Some(EmptyValue),
                ..Default::default()
            },
            IndexAnchor::ZeroEntry => TrieNode {
                own_data_ref: Some(vec![0u8; ref_size]),
                ..Default::default()
            },
        };
        let fork = TrieFork {
            prefix: b"/".to_vec(),
            child: Box::new(idx_node),
            metadata_override: Some(index_doc_metadata(idx)),
            // A lone "/" prefix does NOT get the path-separator flag
            // under bee's index>0 rule; setting it flips one bit in
            // the fork type byte and changes the manifest reference.
            path_separator: bee_path_separator(b"/"),
        };
        root.forks.insert(b'/', fork);
    }
    Ok(root)
}

/// Build a **feed manifest**: a mantaray manifest whose single `/` fork
/// carries the `swarm-feed-{owner,topic,type}` metadata bee's feed
/// dereferencer reads (see [`crate::feed::feed_from_metadata`] and
/// [`crate::mantaray::resolve_feed_root`]). This is what bee's
/// `POST /feeds/{owner}/{topic}` (`createFeedManifest` in bee-js)
/// returns: a stable reference that transparently resolves to whichever
/// feed update is current.
///
/// Only the `Sequence` feed type is emitted (the only type bee writes
/// through `/feeds`). The `/` fork's child is a zero-address value leaf,
/// mirroring bee's `feedManifestEntry`. Returns the manifest root plus
/// the (single) chunk to push.
pub fn build_feed_manifest(
    owner: &[u8; 20],
    topic: &[u8; 32],
) -> Result<ManifestWriteResult, ManifestWriteError> {
    let mut meta = BTreeMap::new();
    meta.insert(crate::feed::FEED_OWNER_KEY.to_string(), hex::encode(owner));
    meta.insert(crate::feed::FEED_TOPIC_KEY.to_string(), hex::encode(topic));
    meta.insert(
        crate::feed::FEED_TYPE_KEY.to_string(),
        "Sequence".to_string(),
    );

    let mut root = TrieNode::default();
    // Bee's feedManifestEntry carries a zero (32-byte) address as the
    // entry — refBytesSize 0x20 with an all-zero entry — unlike the
    // website-index-document anchor, whose child is the refsize-0
    // empty node. The distinction changes the child node bytes and
    // therefore the feed-manifest reference (must match bee's).
    let leaf = TrieNode {
        own_data_ref: Some(vec![0u8; 32]),
        ..Default::default()
    };
    root.forks.insert(
        b'/',
        TrieFork {
            prefix: b"/".to_vec(),
            child: Box::new(leaf),
            metadata_override: Some(meta),
            // Same index>0 rule as the index-document fork: bee does
            // not flag a lone "/" prefix, and the feed-manifest
            // reference must match bee's byte-for-byte.
            path_separator: bee_path_separator(b"/"),
        },
    );

    let mut chunks: Vec<SplitChunk> = Vec::new();
    let mut saver =
        |payload: &[u8], out: &mut Vec<SplitChunk>| -> Result<Vec<u8>, ManifestWriteError> {
            if payload.len() > CHUNK_SIZE {
                return Err(ManifestWriteError::ManifestTooBig {
                    size: payload.len(),
                    cap: CHUNK_SIZE,
                });
            }
            let (addr, wire) = cac_payload(payload);
            out.push(SplitChunk {
                address: addr,
                wire,
            });
            Ok(addr.to_vec())
        };
    let root_ref = serialize_node(&root, &mut chunks, &mut saver)?;
    let root_addr: ChunkAddr = root_ref
        .as_slice()
        .try_into()
        .expect("plain saver returns 32-byte refs");
    Ok(ManifestWriteResult {
        root: root_addr,
        chunks,
    })
}

/// One raw manifest entry for [`build_entries_manifest`]: an arbitrary
/// path with an arbitrary metadata map, no file-upload conventions
/// (no `Content-Type`/`Filename` defaults, no index-document anchor).
#[derive(Debug, Clone)]
pub struct RawManifestEntry {
    /// Manifest key (bee mantaray path), e.g. an ACT history's
    /// reversed-timestamp decimal string.
    pub path: String,
    /// 32-byte entry reference stored on the value node.
    pub reference: ChunkAddr,
    /// Fork metadata, verbatim (empty map → no with-metadata flag).
    pub metadata: BTreeMap<String, String>,
}

/// Build a plain (unencrypted, zero-obfuscation-key) mantaray manifest
/// from raw `path → (reference, metadata)` entries — the shape bee's
/// `manifest.NewMantarayManifest(ls, false)` + `Add(path, NewEntry(ref,
/// metadata))` + `Store()` produces. This is what bee's access-control
/// history is: a manifest keyed by reversed-timestamp strings whose
/// entries point at ACT key-value stores, with optional
/// `encryptedglref` metadata (`pkg/accesscontrol/history.go`).
///
/// The trie construction is canonical (prefix-compressed radix), which
/// matches what bee's incremental `mantaray.Node.Add` maintains, so a
/// rebuild from the full entry list marshals to the same bytes — and
/// the same root reference — as bee's load-and-extend flow. Pinned by
/// the deterministic history vectors in `act.json`.
pub fn build_entries_manifest(
    entries: &[RawManifestEntry],
) -> Result<ManifestWriteResult, ManifestWriteError> {
    if entries.is_empty() {
        return Err(ManifestWriteError::EmptyPath);
    }
    let mut root = TrieNode::default();
    for e in entries {
        if e.path.is_empty() {
            return Err(ManifestWriteError::EmptyPath);
        }
        trie_insert(
            &mut root,
            e.path.as_bytes(),
            e.reference.to_vec(),
            e.metadata.clone(),
        )?;
    }

    let mut chunks: Vec<SplitChunk> = Vec::new();
    let mut saver =
        |payload: &[u8], out: &mut Vec<SplitChunk>| -> Result<Vec<u8>, ManifestWriteError> {
            if payload.len() > CHUNK_SIZE {
                return Err(ManifestWriteError::ManifestTooBig {
                    size: payload.len(),
                    cap: CHUNK_SIZE,
                });
            }
            let (addr, wire) = cac_payload(payload);
            out.push(SplitChunk {
                address: addr,
                wire,
            });
            Ok(addr.to_vec())
        };
    let root_ref = serialize_node(&root, &mut chunks, &mut saver)?;
    let root_addr: ChunkAddr = root_ref
        .as_slice()
        .try_into()
        .expect("plain saver returns 32-byte refs");
    Ok(ManifestWriteResult {
        root: root_addr,
        chunks,
    })
}

// --- trie data model + insertion ---

/// Marker for the "/" placeholder leaf used to anchor the
/// website-index-document metadata. Carries no data of its own.
#[derive(Clone)]
struct EmptyValue;

#[derive(Default)]
struct TrieNode {
    /// File path that ends exactly at this node, if any (32 or 64
    /// bytes, per the builder). The data ref will be written to the
    /// node's `entry` slot at serialization time; the matching metadata
    /// lives on the parent fork.
    own_data_ref: Option<Vec<u8>>,
    own_metadata: BTreeMap<String, String>,
    /// Marker present iff this node represents the empty-stub fork
    /// for the website-index-document anchor. Distinct from
    /// `own_data_ref` because the empty stub carries refsize=0x00,
    /// not 0x20+entry — but it is still a bee *value* node
    /// (`makeValue` on a zero-length entry), so the parent fork's
    /// type byte carries the value bit.
    value: Option<EmptyValue>,
    /// Outgoing forks keyed by the byte that distinguishes them.
    forks: BTreeMap<u8, TrieFork>,
}

struct TrieFork {
    /// Bytes consumed by following this fork (prefix length 1..=30).
    prefix: Vec<u8>,
    child: Box<TrieNode>,
    /// Override the fork's metadata block at serialization. Only used
    /// for the synthetic '/' index-document fork; everywhere else the
    /// metadata is read from `child.own_metadata`.
    metadata_override: Option<BTreeMap<String, String>>,
    path_separator: bool,
}

/// Bee's mantaray path-separator rule
/// (`pkg/manifest/mantaray/node.go::updateIsWithPathSeparator`): the
/// fork-type flag is set only when `/` occurs at index **> 0** of the
/// path being inserted at that trie level — a *leading* separator does
/// not count. Getting this bit wrong changes the node bytes and
/// therefore the content-addressed manifest reference, so ant and bee
/// would compute different `/bzz` references for identical uploads.
fn bee_path_separator(path: &[u8]) -> bool {
    path.iter().position(|&b| b == b'/').is_some_and(|i| i > 0)
}

/// Insert `path → data_ref` into `node`. Splits or extends forks as
/// needed and chains 30-byte forks for paths whose remaining suffix
/// exceeds the per-fork prefix cap.
fn trie_insert(
    node: &mut TrieNode,
    path: &[u8],
    data_ref: Vec<u8>,
    metadata: BTreeMap<String, String>,
) -> Result<(), ManifestWriteError> {
    if path.is_empty() {
        node.own_data_ref = Some(data_ref);
        node.own_metadata = metadata;
        return Ok(());
    }
    let first = path[0];
    // Take the existing fork (if any) by removing it; we may rebuild
    // it before re-inserting. Borrow-checker friendly.
    if let Some(mut fork) = node.forks.remove(&first) {
        let lcp = longest_common_prefix([fork.prefix.as_slice(), path].iter().copied());
        if lcp.len() == fork.prefix.len() {
            // Whole existing prefix matches; descend with the
            // remaining tail. Bee recomputes the child's separator
            // flag from the *full* path being inserted at this level
            // on every descend (node.go:254), so mirror that.
            fork.path_separator = bee_path_separator(path);
            trie_insert(&mut fork.child, &path[lcp.len()..], data_ref, metadata)?;
            node.forks.insert(first, fork);
        } else {
            // Split: create an intermediate node holding the old
            // child under the suffix it kept, plus the new branch.
            let old_suffix: Vec<u8> = fork.prefix[lcp.len()..].to_vec();
            let mut intermediate = TrieNode::default();
            // Move the old subtree under a fork keyed on
            // old_suffix[0]. Its metadata still hangs off the
            // existing fork's metadata_override (if any) — but
            // because fork.metadata_override is only set for the
            // index-doc placeholder which we never split, this is
            // None and we keep it None on the intermediate fork too.
            // Bee recomputes the moved-down old child's flag from the
            // prefix tail it keeps (node.go:245 `f.updateIsWithPathSeparator(rest)`).
            let old_path_sep = bee_path_separator(&old_suffix);
            intermediate.forks.insert(
                old_suffix[0],
                TrieFork {
                    prefix: old_suffix,
                    child: std::mem::take(&mut fork.child),
                    metadata_override: fork.metadata_override.take(),
                    path_separator: old_path_sep,
                },
            );
            // Insert the new tail into the intermediate.
            trie_insert(&mut intermediate, &path[lcp.len()..], data_ref, metadata)?;
            // Replace the original fork with one truncated to LCP.
            // Bee sets the intermediate's flag from the full incoming
            // path at this level, not from the LCP (node.go:254).
            let lcp_path_sep = bee_path_separator(path);
            node.forks.insert(
                first,
                TrieFork {
                    prefix: lcp,
                    child: Box::new(intermediate),
                    metadata_override: None,
                    path_separator: lcp_path_sep,
                },
            );
        }
        Ok(())
    } else {
        // No fork starts with this byte yet; create one. If `path` is
        // longer than the per-fork cap, chain through synthetic
        // intermediates so each fork carries at most 30 bytes.
        let (head, tail) = path.split_at(path.len().min(MAX_FILENAME_BYTES));
        if tail.is_empty() {
            let leaf = TrieNode {
                own_data_ref: Some(data_ref),
                own_metadata: metadata,
                ..Default::default()
            };
            node.forks.insert(
                first,
                TrieFork {
                    prefix: head.to_vec(),
                    child: Box::new(leaf),
                    metadata_override: None,
                    path_separator: bee_path_separator(head),
                },
            );
        } else {
            // Build a child intermediate that holds the tail, then
            // recurse into it with the same data_ref/metadata.
            let mut intermediate = TrieNode::default();
            trie_insert(&mut intermediate, tail, data_ref, metadata)?;
            node.forks.insert(
                first,
                TrieFork {
                    prefix: head.to_vec(),
                    child: Box::new(intermediate),
                    metadata_override: None,
                    path_separator: bee_path_separator(head),
                },
            );
        }
        Ok(())
    }
}

// --- serialization ---

/// Recursively serialize `node` and all descendants. Each serialized
/// node is handed to `saver`, which stores it (plain CAC chunk, or the
/// encrypted splitter) and returns its reference — the reference width
/// (32/64) flows into the parent's fork slots and refsize byte.
/// Chunks are appended to `out` in post-order (children before parents)
/// so callers that push chunks sequentially can rely on dependents
/// already being on the network when each chunk is pushed. The caller
/// still needs to push the *entire* slice — bee's pushsync doesn't
/// backtrack.
fn serialize_node(
    node: &TrieNode,
    out: &mut Vec<SplitChunk>,
    saver: NodeSaver<'_>,
) -> Result<Vec<u8>, ManifestWriteError> {
    // Resolve each fork's child reference first.
    let mut child_refs: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for (&k, fork) in &node.forks {
        let child_ref = serialize_node(&fork.child, out, saver)?;
        child_refs.insert(k, child_ref);
    }

    let payload = serialize_node_payload(node, &child_refs)?;
    saver(&payload, out)
}

/// Serialize one node into its on-wire bytes. Plain nodes carry the
/// all-zero obfuscation key (XOR identity); when any reference in the
/// node is 64 bytes wide (encrypted manifest) a fresh random
/// obfuscation key is generated and the body past byte 32 is `XORed`
/// with it, exactly like bee's `MarshalBinary` for a node whose
/// obfuscation key was left unset by `NewMantarayManifest(_, true)`.
fn serialize_node_payload(
    node: &TrieNode,
    child_refs: &BTreeMap<u8, Vec<u8>>,
) -> Result<Vec<u8>, ManifestWriteError> {
    // Reference width for this node: its own entry or any child ref.
    // (Within one manifest all refs share a width by construction.)
    let ref_size = node
        .own_data_ref
        .as_ref()
        .map(Vec::len)
        .or_else(|| child_refs.values().next().map(Vec::len))
        .unwrap_or(0);
    let encrypted = ref_size == ENC_REF_SIZE;

    let mut p = Vec::with_capacity(128);
    p.extend_from_slice(&[0u8; 32]); // obf key (filled below if encrypted)
    p.extend_from_slice(&VERSION_HASH_31);

    // refsize: the reference width if the node has any forks or its own
    // data_ref; 0x00 only for the empty index-doc placeholder leaf.
    let needs_ref = node.own_data_ref.is_some() || !node.forks.is_empty();
    if needs_ref {
        p.push(ref_size as u8);
        match node.own_data_ref {
            Some(ref a) => p.extend_from_slice(a),
            None => p.extend(std::iter::repeat_n(0u8, ref_size)),
        }
    } else {
        p.push(0x00);
    }

    // Forks bitmap.
    let mut bitmap = [0u8; 32];
    for byte in node.forks.keys() {
        bitmap[(*byte as usize) / 8] |= 1 << (*byte % 8);
    }
    p.extend_from_slice(&bitmap);

    // Forks in ascending order (BTreeMap preserves this).
    for (k, fork) in &node.forks {
        // Resolve the metadata: explicit override (only set on the
        // index-doc placeholder) wins; otherwise read from the child
        // node's own_metadata if it carries a file value. A purely
        // structural intermediate has empty metadata.
        let meta = if let Some(m) = &fork.metadata_override {
            m.clone()
        } else if fork.child.own_data_ref.is_some() {
            fork.child.own_metadata.clone()
        } else {
            BTreeMap::new()
        };
        let child_ref = child_refs
            .get(k)
            .expect("child_refs populated for every fork above");
        // The fork's type byte is bee's *child node* type
        // (`marshal.go` writes `f.nodeType`): value iff an entry ends
        // at the child (including the zero-length entry of the "/"
        // anchor, bee's `makeValue` on an empty entry), edge iff the
        // child has forks of its own, plus the metadata and
        // path-separator flags. A split intermediate is edge-only —
        // writing a value bit there (or omitting the edge bit)
        // changes the node bytes and forks the manifest reference.
        let mut node_type = 0u8;
        if fork.child.own_data_ref.is_some() || fork.child.value.is_some() {
            node_type |= NODE_TYPE_VALUE;
        }
        if !fork.child.forks.is_empty() {
            node_type |= NODE_TYPE_EDGE;
        }
        if !meta.is_empty() {
            node_type |= NODE_TYPE_WITH_METADATA;
        }
        if fork.path_separator {
            node_type |= NODE_TYPE_PATH_SEPARATOR;
        }
        let bytes = serialize_fork_to_bytes(&fork.prefix, child_ref, &meta, node_type)?;
        p.extend_from_slice(&bytes);
    }

    if encrypted {
        // Bee: `NewMantarayManifest(ls, encrypted=true)` leaves the
        // obfuscation key empty, so `MarshalBinary` draws a random one
        // per node and XORs everything past the key with it.
        let mut obf = [0u8; 32];
        getrandom::fill(&mut obf).expect("OS RNG");
        p[..32].copy_from_slice(&obf);
        for chunk in p[32..].chunks_mut(32) {
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= obf[i];
            }
        }
    }
    Ok(p)
}

fn serialize_fork_to_bytes(
    prefix: &[u8],
    child_ref: &[u8],
    metadata: &BTreeMap<String, String>,
    node_type: u8,
) -> Result<Vec<u8>, ManifestWriteError> {
    if prefix.is_empty() || prefix.len() > MAX_FILENAME_BYTES {
        return Err(ManifestWriteError::SegmentTooLong {
            segment: prefix.len(),
            cap: MAX_FILENAME_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(64);
    bytes.push(node_type);
    bytes.push(prefix.len() as u8);
    bytes.extend_from_slice(prefix);
    bytes.extend(std::iter::repeat_n(0u8, MAX_FILENAME_BYTES - prefix.len()));
    bytes.extend_from_slice(child_ref);
    if !metadata.is_empty() {
        let meta_json = encode_metadata(metadata);
        // Bee's padding (marshal.go `fork.bytes`): bring (json + the
        // 2-byte length prefix) up to a multiple of 32 — with the
        // quirk that when the total already IS a multiple of 32 and
        // exceeds 32, Go computes `32 - x%32` with `x%32 == 0` and
        // appends a FULL EXTRA 32 newlines; only an exact total of 32
        // gets no padding. Bug-compatible on purpose: the manifest
        // reference depends on these bytes (caught by the manifest
        // differential fuzz on any metadata whose JSON is 32k-2 long).
        let with_size = meta_json.len() + 2;
        let pad = match with_size.cmp(&32) {
            std::cmp::Ordering::Less => 32 - with_size,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 32 - with_size % 32,
        };
        let mut padded = meta_json.into_bytes();
        padded.extend(std::iter::repeat_n(b'\n', pad));
        let meta_len = padded.len() as u16;
        bytes.extend_from_slice(&meta_len.to_be_bytes());
        bytes.extend_from_slice(&padded);
    }
    Ok(bytes)
}

// --- internal helpers ---

/// Stable JSON encoding for mantaray fork metadata: flat string→string
/// object, `BTreeMap` order (Go's `json.Marshal` sorts map keys), no
/// whitespace. Escaping mirrors Go's `encoding/json` exactly — bee
/// marshals with the default HTML-escaping encoder, so the characters
/// `<`, `>` and `&` are emitted as six-byte `\u00XX` escape sequences
/// (and U+2028/U+2029 as `\u2028`/`\u2029`); diverging here changes
/// the node bytes and therefore the manifest reference for any
/// filename containing those characters.
fn encode_metadata(meta: &BTreeMap<String, String>) -> String {
    let mut out = String::from("{");
    let mut first = true;
    for (k, v) in meta {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        push_json_escaped(&mut out, k);
        out.push_str("\":\"");
        push_json_escaped(&mut out, v);
        out.push('"');
    }
    out.push('}');
    out
}

fn push_json_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Go's default encoder HTML-escapes these three even in
            // regular strings (encoding/json `htmlSafeSet`).
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            // Go escapes the JS line separators (U+2028/U+2029) too.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                write!(out, "\\u{:04x}", c as u32).expect("writing to String");
            }
            c => out.push(c),
        }
    }
}

fn index_doc_metadata(filename: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(MANTARAY_INDEX_DOC_KEY.to_string(), filename.to_string());
    m
}

fn file_metadata(content_type: &str, filename: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        MANTARAY_CONTENT_TYPE_KEY.to_string(),
        content_type.to_string(),
    );
    // Bee stores the path BASENAME as Filename (dirs.go uses
    // fileHeader.FileInfo().Name()); writing the full path changes the
    // metadata bytes and therefore the manifest reference.
    let base = filename.rsplit('/').next().unwrap_or(filename);
    m.insert("Filename".to_string(), base.to_string());
    m
}

/// CAC-wrap a manifest node payload (always one chunk; payload size is
/// already validated against [`CHUNK_SIZE`] in [`serialize_node_payload`]).
fn cac_payload(payload: &[u8]) -> (ChunkAddr, Vec<u8>) {
    cac_new(payload).expect("manifest node payload pre-validated against CHUNK_SIZE")
}

fn longest_common_prefix<'a, I>(it: I) -> Vec<u8>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut iter = it.into_iter();
    let first = match iter.next() {
        Some(s) => s.to_vec(),
        None => return Vec::new(),
    };
    let mut max_len = first.len();
    for s in iter {
        let mut common = 0;
        for (a, b) in first.iter().zip(s.iter()) {
            if a == b {
                common += 1;
            } else {
                break;
            }
        }
        max_len = max_len.min(common);
        if max_len == 0 {
            return Vec::new();
        }
    }
    first[..max_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mantaray::{list_manifest, lookup_path, ManifestError};
    use crate::ChunkFetcher;
    use async_trait::async_trait;
    use std::collections::{BTreeSet, HashMap};
    use std::error::Error;

    /// Golden references produced by bee itself (via the beemock
    /// conformance oracle) for identical inputs. If these drift, ant's
    /// manifests are no longer byte-compatible with bee's and the same
    /// upload yields a different /bzz reference on each client. The
    /// historical bug here was the path-separator fork flag: bee only
    /// sets it for '/' at index > 0, so the synthetic "/" fork must
    /// stay unflagged (caught by the differential conformance runner).
    #[test]
    fn single_file_manifest_reference_matches_bee() {
        let split = crate::splitter::split_bytes(b"hello differential world\n");
        assert_eq!(
            hex::encode(split.root),
            "ba0692eb77950120fead8d5d50b8fa49799228029b8f1ee9cb039a7d0397425d",
        );
        let m = build_single_file_manifest("hello.txt", Some("text/plain"), split.root).unwrap();
        assert_eq!(
            hex::encode(m.root),
            "143b41f878de114a9240a1d3278ac20a7a0e7786106d19a492a250a318a5f68a",
        );
    }

    #[test]
    fn collection_manifest_reference_matches_bee() {
        let index_split = crate::splitter::split_bytes(b"<h1>index</h1>");
        let data_split = crate::splitter::split_bytes(b"nested data");
        let m = build_collection_manifest(
            &[
                ManifestFile {
                    path: "index.html".to_string(),
                    content_type: Some("text/html; charset=utf-8".to_string()),
                    data_ref: index_split.root.to_vec(),
                },
                ManifestFile {
                    path: "sub/data.txt".to_string(),
                    content_type: Some("text/plain; charset=utf-8".to_string()),
                    data_ref: data_split.root.to_vec(),
                },
            ],
            Some("index.html"),
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        assert_eq!(
            hex::encode(m.root),
            "4f37b1abda26f952cbf72b387449d5887314d99c19b3d8cf78e4001b939e4c77",
        );
    }

    #[test]
    fn feed_manifest_reference_matches_bee() {
        let owner: [u8; 20] = hex::decode("ff6316419def87e4ea768e09a04dd56ebb40cb4e")
            .unwrap()
            .try_into()
            .unwrap();
        let topic: [u8; 32] =
            hex::decode("e36165b0d71a05b2330be5a2519c2573d2c9b35c75e94fab874c46a8210641d0")
                .unwrap()
                .try_into()
                .unwrap();
        let m = build_feed_manifest(&owner, &topic).unwrap();
        assert_eq!(
            hex::encode(m.root),
            "b04fab6986a2ee96857a3ecfef12b90fb51233b05f1f627a7f82d901081904a2",
        );
    }

    struct MapFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
    }

    impl MapFetcher {
        fn new() -> Self {
            Self {
                chunks: HashMap::new(),
            }
        }
        fn ingest(&mut self, c: &SplitChunk) {
            self.chunks.insert(c.address, c.wire.clone());
        }
    }

    #[async_trait]
    impl ChunkFetcher for MapFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!("missing {}", hex::encode(addr)).into()
                })
        }
    }

    /// End-to-end **encrypted**: encrypt-split a file, build an
    /// encrypted manifest around its 64-byte ref, walk it with the
    /// reader (which must decrypt every node), and decrypt-join the
    /// resolved data ref back to the plaintext — the exact shape of
    /// `POST /bzz` + `GET /bzz/{128-hex}/{path}` with `swarm-encrypt`.
    #[tokio::test]
    async fn encrypted_manifest_round_trips_through_reader() {
        use crate::enc_split::split_bytes_encrypted;
        use crate::joiner::join_encrypted;

        let payload = b"secret website payload".repeat(300); // multi-chunk
        for level in [0u8, 1u8] {
            let split = split_bytes_encrypted(&payload, level);
            let manifest = build_single_file_manifest_encrypted(
                "hello.txt",
                Some("text/plain"),
                &split.root_ref,
                level,
            )
            .unwrap();

            let mut fetcher = MapFetcher::new();
            for c in split.chunks.iter().chain(&manifest.chunks) {
                fetcher.ingest(c);
            }
            assert_eq!(manifest.root_address().as_slice(), &manifest.root_ref[..32]);

            for path in ["hello.txt", ""] {
                let lookup = lookup_path(&fetcher, &manifest.root_ref, path)
                    .await
                    .unwrap_or_else(|e| panic!("level {level} path {path:?}: {e}"));
                assert_eq!(lookup.data_ref, split.root_ref.to_vec());
                assert_eq!(lookup.content_type.as_deref(), Some("text/plain"));
                let enc_ref: [u8; 64] = lookup.data_ref.as_slice().try_into().unwrap();
                let back = join_encrypted(&fetcher, enc_ref, 1 << 30).await.unwrap();
                assert_eq!(back, payload, "level {level} path {path:?}");
            }
        }
    }

    /// Encrypted collection: multiple paths, index document, listing.
    #[tokio::test]
    async fn encrypted_collection_manifest_walks() {
        use crate::enc_split::split_bytes_encrypted;

        let a = split_bytes_encrypted(b"file a", 0);
        let b = split_bytes_encrypted(&b"file b".repeat(1000), 0);
        let manifest = build_collection_manifest_encrypted(
            &[
                ManifestFile {
                    path: "index.html".into(),
                    content_type: Some("text/html".into()),
                    data_ref: a.root_ref.to_vec(),
                },
                ManifestFile {
                    path: "assets/site.css".into(),
                    content_type: Some("text/css".into()),
                    data_ref: b.root_ref.to_vec(),
                },
            ],
            Some("index.html"),
            IndexAnchor::ZeroEntry,
            0,
        )
        .unwrap();

        let mut fetcher = MapFetcher::new();
        for c in a.chunks.iter().chain(&b.chunks).chain(&manifest.chunks) {
            fetcher.ingest(c);
        }

        let css = lookup_path(&fetcher, &manifest.root_ref, "assets/site.css")
            .await
            .unwrap();
        assert_eq!(css.data_ref, b.root_ref.to_vec());
        let idx = lookup_path(&fetcher, &manifest.root_ref, "").await.unwrap();
        assert_eq!(idx.data_ref, a.root_ref.to_vec());

        let listing = list_manifest(&fetcher, &manifest.root_ref).await.unwrap();
        let css_entry = listing
            .iter()
            .find(|e| e.reference == Some(b.root_ref.to_vec()))
            .unwrap_or_else(|| {
                panic!(
                    "listing has the css file; got paths {:?}",
                    listing.iter().map(|e| &e.path).collect::<Vec<_>>()
                )
            });
        assert_eq!(css_entry.reference, Some(b.root_ref.to_vec()));
        assert_eq!(css_entry.size, Some(b"file b".repeat(1000).len() as u64));
    }

    /// End-to-end: split + manifest a small text file, walk the
    /// manifest with the existing reader, expect to recover the file's
    /// data ref + content-type. This is the same shape the gateway
    /// will exercise for `POST /bzz?name=hello.txt`.
    #[tokio::test]
    async fn single_file_round_trip() {
        let body = b"uploaded via ant\n".to_vec();
        let split = crate::splitter::split_bytes(&body);
        let manifest =
            build_single_file_manifest("hello.txt", Some("text/plain; charset=utf-8"), split.root)
                .unwrap();

        let mut fetcher = MapFetcher::new();
        for c in &split.chunks {
            fetcher.ingest(c);
        }
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }

        // /bzz/<root>/hello.txt → should resolve to the file body's data ref.
        let lookup = lookup_path(&fetcher, &manifest.root, "hello.txt")
            .await
            .unwrap();
        assert_eq!(lookup.data_ref, split.root);
        assert_eq!(
            lookup.content_type.as_deref(),
            Some("text/plain; charset=utf-8"),
        );
        assert_eq!(
            lookup.metadata.get("Filename").map(String::as_str),
            Some("hello.txt"),
        );

        // Index-document fallback: bare /bzz/<root>/ resolves to the same.
        let idx = lookup_path(&fetcher, &manifest.root, "").await.unwrap();
        assert_eq!(idx.data_ref, split.root);
    }

    /// Multi-file collection with an index-document. Verify each path
    /// resolves to its own data ref and the bare path returns the index.
    #[tokio::test]
    async fn collection_round_trip() {
        let mut fetcher = MapFetcher::new();
        let mut files: Vec<ManifestFile> = Vec::new();
        let bodies = [
            ("index.html", "text/html", &b"<html>hi</html>"[..]),
            ("style.css", "text/css", &b"body{}"[..]),
            ("script.js", "application/javascript", &b"alert(1)"[..]),
        ];
        let mut data_refs: HashMap<&str, [u8; 32]> = HashMap::new();
        for (name, ct, body) in &bodies {
            let split = crate::splitter::split_bytes(body);
            for c in &split.chunks {
                fetcher.ingest(c);
            }
            data_refs.insert(name, split.root);
            files.push(ManifestFile {
                path: name.to_string(),
                content_type: Some(ct.to_string()),
                data_ref: split.root.to_vec(),
            });
        }
        let manifest =
            build_collection_manifest(&files, Some("index.html"), IndexAnchor::ZeroEntry)
                .expect("build manifest");
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }

        for (name, ct, _body) in &bodies {
            let r = lookup_path(&fetcher, &manifest.root, name).await.unwrap();
            assert_eq!(&r.data_ref, data_refs.get(name).unwrap(), "name {name}");
            assert_eq!(r.content_type.as_deref(), Some(*ct));
        }
        // Index-document fallback returns the index file's data.
        let r = lookup_path(&fetcher, &manifest.root, "").await.unwrap();
        assert_eq!(r.data_ref, *data_refs.get("index.html").unwrap());

        // Listing should surface every path (note: list_manifest returns
        // metadata-only entries too — index-document fork shows up).
        let listing = list_manifest(&fetcher, &manifest.root).await.unwrap();
        let paths: BTreeSet<&str> = listing.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains("index.html"));
        assert!(paths.contains("style.css"));
        assert!(paths.contains("script.js"));
    }

    /// Filename with a slash gets the path-separator type bit set on its
    /// fork — bee's listing format uses this to render `dir/` listings.
    /// We just check the round-trip still resolves cleanly.
    #[tokio::test]
    async fn nested_path_round_trip() {
        let body = b"sub-page".to_vec();
        let split = crate::splitter::split_bytes(&body);
        let manifest = build_collection_manifest(
            &[ManifestFile {
                path: "blog/post".to_string(),
                content_type: Some("text/html".to_string()),
                data_ref: split.root.to_vec(),
            }],
            None,
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        let mut fetcher = MapFetcher::new();
        for c in &split.chunks {
            fetcher.ingest(c);
        }
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }
        let r = lookup_path(&fetcher, &manifest.root, "blog/post")
            .await
            .unwrap();
        assert_eq!(r.data_ref, split.root);
    }

    /// Path segments longer than the 30-byte fork prefix cap are
    /// chained transparently. End-to-end: write a 90-character
    /// filename, then walk it back via the reader.
    #[tokio::test]
    async fn long_filename_chains_and_round_trips() {
        let long = "x".repeat(90);
        let body = b"long-name body".to_vec();
        let split = crate::splitter::split_bytes(&body);
        let manifest = build_single_file_manifest(&long, Some("text/plain"), split.root).unwrap();
        let mut fetcher = MapFetcher::new();
        for c in &split.chunks {
            fetcher.ingest(c);
        }
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }
        let r = lookup_path(&fetcher, &manifest.root, &long).await.unwrap();
        assert_eq!(r.data_ref, split.root);
        assert_eq!(r.content_type.as_deref(), Some("text/plain"));
    }

    /// Every chunk emitted by the trie writer must be a valid CAC so
    /// bee gateways accept it on push. Quick structural check across a
    /// few-file collection (root + per-fork sub-tries).
    #[test]
    fn every_emitted_chunk_is_valid_cac() {
        let files: Vec<ManifestFile> = ["a.txt", "b.txt", "ab.txt"]
            .iter()
            .map(|p| ManifestFile {
                path: (*p).to_string(),
                content_type: Some("text/plain".to_string()),
                data_ref: vec![0u8; 32],
            })
            .collect();
        let manifest = build_collection_manifest(&files, None, IndexAnchor::ZeroEntry).unwrap();
        for c in &manifest.chunks {
            assert!(
                ant_crypto::cac_valid(&c.address, &c.wire),
                "chunk {} not a valid CAC",
                hex::encode(c.address),
            );
        }
        // Root must be the last chunk emitted (post-order).
        assert_eq!(manifest.chunks.last().unwrap().address, manifest.root);
    }

    /// Many shared-prefix files trigger an actual multi-chunk
    /// manifest: the trie deepens and the writer emits ≥ 2 manifest
    /// chunks. Verifies every file resolves and that the writer no
    /// longer errors with `ManifestTooBig` on collections that the
    /// old flat encoder couldn't fit.
    #[tokio::test]
    async fn deep_collection_emits_multiple_chunks_and_round_trips() {
        // 64 files, all sharing the prefix "blog/posts/" then a
        // 5-char unique suffix. Long enough metadata (Filename) that
        // packing them all into one fork-bitmap would overflow a
        // single 4 KiB chunk under the old writer.
        let mut files: Vec<ManifestFile> = Vec::new();
        let mut data_refs: HashMap<String, [u8; 32]> = HashMap::new();
        let mut fetcher = MapFetcher::new();
        for i in 0..64u8 {
            let path = format!("blog/posts/post-{i:02x}");
            let body = format!("body-{i}").into_bytes();
            let split = crate::splitter::split_bytes(&body);
            for c in &split.chunks {
                fetcher.ingest(c);
            }
            data_refs.insert(path.clone(), split.root);
            files.push(ManifestFile {
                path,
                content_type: Some("text/plain".to_string()),
                data_ref: split.root.to_vec(),
            });
        }
        let manifest = build_collection_manifest(&files, None, IndexAnchor::ZeroEntry).unwrap();
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }
        // The trie should have deepened — expect at least 2 manifest
        // chunks (root + at least one sub-trie node).
        assert!(
            manifest.chunks.len() >= 2,
            "deep collection should emit multiple manifest chunks; got {}",
            manifest.chunks.len(),
        );

        // Every file path resolves to its own data ref.
        for (path, want_ref) in &data_refs {
            let r = lookup_path(&fetcher, &manifest.root, path).await.unwrap();
            assert_eq!(&r.data_ref, want_ref, "path {path}");
        }
    }

    /// Insertion order must not change the manifest root. The trie
    /// builder sorts forks by byte at every node (`BTreeMap`), so two
    /// permutations of the same file set hash to the same root.
    #[test]
    fn insertion_order_does_not_change_root() {
        let make_file = |name: &str, ref_byte: u8| ManifestFile {
            path: name.to_string(),
            content_type: Some("text/plain".to_string()),
            data_ref: [ref_byte; 32].to_vec(),
        };
        let forward = vec![
            make_file("apple", 1),
            make_file("apricot", 2),
            make_file("banana", 3),
            make_file("blueberry", 4),
            make_file("cherry", 5),
        ];
        let reversed: Vec<ManifestFile> = forward.iter().rev().cloned().collect();

        let m1 = build_collection_manifest(&forward, None, IndexAnchor::ZeroEntry).unwrap();
        let m2 = build_collection_manifest(&reversed, None, IndexAnchor::ZeroEntry).unwrap();
        assert_eq!(m1.root, m2.root);
    }

    /// Adding a file whose path is a prefix of another already in the
    /// manifest puts the prefix file's value at the parent node and
    /// the longer path under a new fork. Walks both back correctly.
    #[tokio::test]
    async fn prefix_overlap_round_trip() {
        let mut fetcher = MapFetcher::new();
        let body_a = b"abc".to_vec();
        let body_b = b"abc/d".to_vec();
        let split_a = crate::splitter::split_bytes(&body_a);
        let split_b = crate::splitter::split_bytes(&body_b);
        for c in &split_a.chunks {
            fetcher.ingest(c);
        }
        for c in &split_b.chunks {
            fetcher.ingest(c);
        }

        let manifest = build_collection_manifest(
            &[
                ManifestFile {
                    path: "abc".to_string(),
                    content_type: Some("text/plain".to_string()),
                    data_ref: split_a.root.to_vec(),
                },
                ManifestFile {
                    path: "abc/d".to_string(),
                    content_type: Some("text/html".to_string()),
                    data_ref: split_b.root.to_vec(),
                },
            ],
            None,
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }

        let ra = lookup_path(&fetcher, &manifest.root, "abc").await.unwrap();
        assert_eq!(ra.data_ref, split_a.root);
        assert_eq!(ra.content_type.as_deref(), Some("text/plain"));
        let rb = lookup_path(&fetcher, &manifest.root, "abc/d")
            .await
            .unwrap();
        assert_eq!(rb.data_ref, split_b.root);
        assert_eq!(rb.content_type.as_deref(), Some("text/html"));
    }

    /// Duplicate paths in the input list follow bee's mantaray `Add`
    /// semantics: the entry at the node is overwritten, so the LAST
    /// write wins and the manifest equals one built from only the
    /// final occurrence (caught by the manifest differential fuzz —
    /// bee accepts tars with repeated member names).
    #[tokio::test]
    async fn duplicate_paths_last_write_wins() {
        let mk = |b: u8| ManifestFile {
            path: "dup.txt".to_string(),
            content_type: Some("text/plain".to_string()),
            data_ref: vec![b; 32],
        };
        let dup = build_collection_manifest(&[mk(1), mk(2)], None, IndexAnchor::ZeroEntry).unwrap();
        let only_last = build_collection_manifest(&[mk(2)], None, IndexAnchor::ZeroEntry).unwrap();
        assert_eq!(dup.root, only_last.root);

        let mut fetcher = MapFetcher::new();
        for c in &dup.chunks {
            fetcher.ingest(c);
        }
        let r = lookup_path(&fetcher, &dup.root, "dup.txt").await.unwrap();
        assert_eq!(r.data_ref, vec![2u8; 32]);
    }

    /// A feed manifest built by [`build_feed_manifest`] must be
    /// recognised as a feed by the reader: `resolve_feed_root` detects
    /// the `/` fork's `swarm-feed-*` metadata and *attempts* to
    /// dereference (failing only because no update chunks are staged).
    /// A non-feed manifest would instead return the root unchanged. We
    /// assert the "detected" branch by requiring an error rather than
    /// `Ok(root)`.
    #[tokio::test]
    async fn feed_manifest_is_detected_by_reader() {
        use crate::mantaray::resolve_feed_root;

        let owner = [0x11u8; 20];
        let topic = [0x22u8; 32];
        let manifest = build_feed_manifest(&owner, &topic).expect("build feed manifest");
        // The trie is the root node plus its `/`-fork value leaf, so it
        // serializes to two chunks; the root is emitted last (bottom-up).
        assert_eq!(manifest.chunks.len(), 2, "feed manifest is root + leaf");
        assert_eq!(manifest.chunks.last().unwrap().address, manifest.root);

        let mut fetcher = MapFetcher::new();
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }

        // Detected as a feed → tries to resolve → no updates staged →
        // Err. A plain content manifest would return Ok(root) instead.
        let resolved = resolve_feed_root(&fetcher, &manifest.root).await;
        assert!(
            resolved.is_err(),
            "feed manifest should be detected and attempt dereference, got {resolved:?}",
        );
    }

    /// Build a manifest whose `/` fork carries both
    /// `website-index-document` and `website-error-document`, then push
    /// every chunk into `fetcher`. The writer's public API only emits the
    /// index document, so we assemble the trie by hand here to exercise
    /// the reader's error-document fallback.
    fn build_manifest_with_error_doc(
        fetcher: &mut MapFetcher,
        files: &[ManifestFile],
        index: &str,
        error: &str,
    ) -> ChunkAddr {
        let mut root = TrieNode::default();
        for f in files {
            let ct = f
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            trie_insert(
                &mut root,
                f.path.as_bytes(),
                f.data_ref.clone(),
                file_metadata(&ct, &f.path),
            )
            .unwrap();
        }
        let mut meta = BTreeMap::new();
        meta.insert(MANTARAY_INDEX_DOC_KEY.to_string(), index.to_string());
        meta.insert(crate::MANTARAY_ERROR_DOC_KEY.to_string(), error.to_string());
        root.forks.insert(
            b'/',
            TrieFork {
                prefix: b"/".to_vec(),
                child: Box::new(TrieNode {
                    value: Some(EmptyValue),
                    ..Default::default()
                }),
                metadata_override: Some(meta),
                path_separator: true,
            },
        );
        let mut chunks = Vec::new();
        let mut saver =
            |payload: &[u8], out: &mut Vec<SplitChunk>| -> Result<Vec<u8>, ManifestWriteError> {
                let (addr, wire) = cac_payload(payload);
                out.push(SplitChunk {
                    address: addr,
                    wire,
                });
                Ok(addr.to_vec())
            };
        let root_ref = serialize_node(&root, &mut chunks, &mut saver).unwrap();
        for c in &chunks {
            fetcher.ingest(c);
        }
        root_ref.as_slice().try_into().unwrap()
    }

    /// Bee-compat `website-error-document` fallback: an otherwise-404 path
    /// serves the declared error document, while explicit and index-doc
    /// paths are unaffected.
    #[tokio::test]
    async fn error_document_fallback() {
        let mut fetcher = MapFetcher::new();
        let mut files = Vec::new();
        let mut data_refs: HashMap<&str, [u8; 32]> = HashMap::new();
        for name in ["index.html", "error.html"] {
            let body = format!("<html>{name}</html>");
            let split = crate::splitter::split_bytes(body.as_bytes());
            for c in &split.chunks {
                fetcher.ingest(c);
            }
            data_refs.insert(name, split.root);
            files.push(ManifestFile {
                path: name.to_string(),
                content_type: Some("text/html".to_string()),
                data_ref: split.root.to_vec(),
            });
        }
        let root = build_manifest_with_error_doc(&mut fetcher, &files, "index.html", "error.html");

        // A genuine miss falls back to the error document.
        let miss = lookup_path(&fetcher, &root, "does/not/exist")
            .await
            .unwrap();
        assert_eq!(miss.data_ref, data_refs["error.html"]);

        // Explicit existing paths and the bare root are unaffected.
        let explicit = lookup_path(&fetcher, &root, "index.html").await.unwrap();
        assert_eq!(explicit.data_ref, data_refs["index.html"]);
        let bare = lookup_path(&fetcher, &root, "").await.unwrap();
        assert_eq!(bare.data_ref, data_refs["index.html"]);
    }

    /// Without a `website-error-document`, a miss still 404s (the
    /// fallback must be opt-in via the metadata key).
    #[tokio::test]
    async fn no_error_document_still_not_found() {
        let mut fetcher = MapFetcher::new();
        let body = b"<html>hi</html>".to_vec();
        let split = crate::splitter::split_bytes(&body);
        for c in &split.chunks {
            fetcher.ingest(c);
        }
        let manifest = build_collection_manifest(
            &[ManifestFile {
                path: "index.html".to_string(),
                content_type: Some("text/html".to_string()),
                data_ref: split.root.to_vec(),
            }],
            Some("index.html"),
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        for c in &manifest.chunks {
            fetcher.ingest(c);
        }
        let err = lookup_path(&fetcher, &manifest.root, "does/not/exist")
            .await
            .unwrap_err();
        assert!(matches!(err, ManifestError::NotFound { .. }), "got {err:?}");
    }

    /// JSON encoder produces strict, deterministic output for the keys
    /// bee actually uses. Important because byte-equal output keeps
    /// bee-shaped fixtures stable.
    #[test]
    fn metadata_encoding_is_stable() {
        let mut m = BTreeMap::new();
        m.insert("Content-Type".to_string(), "text/plain".to_string());
        m.insert("Filename".to_string(), "hello.txt".to_string());
        let s = encode_metadata(&m);
        assert_eq!(s, r#"{"Content-Type":"text/plain","Filename":"hello.txt"}"#);
    }

    /// Go's `json.Marshal` (bee's encoder) HTML-escapes `<`, `>`, `&`;
    /// ant must emit identical bytes or the manifest reference forks
    /// on filenames containing them.
    #[test]
    fn metadata_encoding_matches_go_html_escaping() {
        let mut m = BTreeMap::new();
        m.insert("Filename".to_string(), "a&b<c>d.txt".to_string());
        let s = encode_metadata(&m);
        assert_eq!(s, r#"{"Filename":"a\u0026b\u003cc\u003ed.txt"}"#);
    }
}
