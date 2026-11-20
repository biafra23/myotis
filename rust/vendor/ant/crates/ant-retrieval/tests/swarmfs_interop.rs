//! Cross-implementation vectors for file splitting, SOC/feed addressing
//! and Mantaray manifests, from a generator that is neither bee nor ant
//! (issue #62; BMT chunk vectors live in `ant-crypto`'s
//! `swarmfs_bmt_interop.rs`).
//!
//! Every `swarmfs_*.jsonl` here was produced by `scripts/swarmfs_vectors.py`
//! with swarmfs (<https://github.com/petfold/swarmfs>, Python, pinned
//! commit in each line's `generator`). bee <-> ant vectors
//! (`trojan_interop.rs`, `bzz_fixture.rs`) prove the two agree with each
//! other; these prove ant agrees with an implementation written
//! independently from the format, which is what catches ant and bee
//! drifting from the spec together. A divergence here is silent in
//! production — a wrong address, not an error — so every check compares
//! bytes, in both directions where ant has a writer:
//!
//! - files: both of ant's splitters reproduce swarmfs's root reference;
//! - SOC: ant derives the same feed id, SOC address and owner, accepts
//!   every swarmfs-signed chunk, and its own SOC builder emits the same
//!   bytes (signature included: both sign with RFC 6979 nonces);
//! - Mantaray: ant's reader resolves every swarmfs-built manifest
//!   (including an obfuscated one) and ant's writer reproduces swarmfs's
//!   chunks and root for every unobfuscated one.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error as StdError;

use ant_crypto::gsoc::{build_gsoc_chunk, identifier_from_string, soc_address};
use ant_crypto::{
    ethereum_address_from_public_key, soc_valid, CHUNK_SIZE, SOC_HEADER_SIZE, SPAN_SIZE,
};
use ant_retrieval::mantaray::list_manifest_paths;
use ant_retrieval::{
    build_entries_manifest, lookup_path, sequence_update_address, sequence_update_id, split_bytes,
    ChunkFetcher, Feed, FeedType, RawManifestEntry, SplitChunk, StreamingSplitter,
};
use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}
fn h20(s: &str) -> [u8; 20] {
    h(s).try_into().unwrap()
}

fn lines(raw: &str) -> impl Iterator<Item = Value> + '_ {
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
}

/// The generator's `pattern(n)`: with `k = i / 4096` (the chunk index),
/// byte `i` is `((i * 7 + k) % 251) ^ ((k / 251) & 0xff)`. The XOR term
/// keeps every chunk distinct past the 251-chunk period of the first.
fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            let k = i / 4096;
            (((i * 7 + k) % 251) ^ ((k / 251) & 0xff)) as u8
        })
        .collect()
}

/// File vectors where ant's plain splitters are known to disagree with
/// swarmfs *and* bee, each with its tracking issue. Each one is checked
/// to still disagree, so the entry has to go when the fix lands — all
/// of an issue's entries together: the 64 MiB one only runs under
/// `--ignored`, so a fix trips the 512 KiB one in a plain run first.
const KNOWN_SPLIT_DIVERGENCES: &[(&str, &str)] = &[];

/// File vectors above this size (the three-level tree, 64 MiB) take
/// tens of seconds in a debug build, so they run in the ignored test.
const LARGE_FILE: u64 = 8 << 20;

#[test]
fn split_roots_match_swarmfs() {
    let n = check_split_roots(|size| size <= LARGE_FILE);
    assert!(
        n >= 11,
        "expected the full swarmfs file vector set, got {n}"
    );
}

#[test]
#[ignore = "splits 64 MiB; run with --ignored"]
fn split_roots_match_swarmfs_three_levels() {
    let n = check_split_roots(|size| size > LARGE_FILE);
    assert!(n >= 1, "expected the large swarmfs file vectors, got {n}");
}

fn check_split_roots(wanted: impl Fn(u64) -> bool) -> usize {
    let mut n = 0;
    for v in lines(include_str!("swarmfs_files.jsonl")) {
        let case = v["case"].as_str().unwrap();
        if !wanted(v["size"].as_u64().unwrap()) {
            continue;
        }
        assert_eq!(v["content"], "pattern", "unknown content kind on {case}");
        let size = usize::try_from(v["size"].as_u64().unwrap()).unwrap();
        let data = pattern(size);
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            v["content_sha256"].as_str().unwrap(),
            "test-side pattern() disagrees with the generator on {case} \
             (fix the content, this is not a splitter divergence)",
        );

        // `split_bytes` (gateway, ACT) and `StreamingSplitter` (node
        // uploads, `antctl pin`) are separate implementations of the
        // same tree; both must give swarmfs's root.
        let plain = split_bytes(&data);
        let mut streaming = StreamingSplitter::new();
        let mut streamed: Vec<SplitChunk> = Vec::new();
        for leaf in data.chunks(CHUNK_SIZE) {
            streamed.extend(streaming.push_leaf(leaf));
        }
        let (stream_root, stream_total, tail) = streaming.finish();
        streamed.extend(tail);

        for (splitter, root, total, chunks) in [
            ("split_bytes", plain.root, plain.total_bytes, &plain.chunks),
            ("StreamingSplitter", stream_root, stream_total, &streamed),
        ] {
            if let Some((_, issue)) = KNOWN_SPLIT_DIVERGENCES.iter().find(|(c, _)| *c == case) {
                assert_ne!(
                    hex::encode(root),
                    v["root_hex"].as_str().unwrap(),
                    "{splitter}: {case} now matches swarmfs: if {issue} is \
                     fixed, drop every entry for it from KNOWN_SPLIT_DIVERGENCES",
                );
                continue;
            }
            assert_eq!(
                hex::encode(root),
                v["root_hex"].as_str().unwrap(),
                "{splitter}: root reference mismatch on {case}",
            );
            assert_eq!(total, size as u64, "{splitter}: span mismatch on {case}");
            let want_chunks = usize::try_from(v["chunk_count"].as_u64().unwrap()).unwrap();
            let distinct: HashSet<_> = chunks.iter().map(|c| c.address).collect();
            assert_eq!(
                distinct.len(),
                want_chunks,
                "{splitter}: chunk count mismatch on {case}"
            );
        }
        n += 1;
    }
    n
}

#[test]
fn soc_and_feed_addressing_match_swarmfs() {
    let mut n = 0;
    for v in lines(include_str!("swarmfs_soc.jsonl")) {
        let case = v["case"].as_str().unwrap();
        let secret = h32(v["signer_priv_hex"].as_str().unwrap());
        let owner = h20(v["owner_hex"].as_str().unwrap());
        let topic = h32(v["topic_hex"].as_str().unwrap());
        let index: u64 = v["index"].as_str().unwrap().parse().unwrap();
        let identifier = h32(v["identifier_hex"].as_str().unwrap());
        let address = h32(v["soc_address_hex"].as_str().unwrap());
        let soc = h(v["soc_data_hex"].as_str().unwrap());

        // owner = last 20 bytes of keccak256(pubkey)
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        assert_eq!(
            ethereum_address_from_public_key(sk.verifying_key()),
            owner,
            "owner mismatch on {case}",
        );
        // topic = keccak256(utf8) unless the string was a raw 64-hex topic
        if !v["topic_is_raw"].as_bool().unwrap() {
            assert_eq!(
                identifier_from_string(v["topic_string"].as_str().unwrap()),
                topic,
                "topic mismatch on {case}",
            );
        }
        // feed id = keccak256(topic ‖ index_be8); address = keccak256(id ‖ owner)
        assert_eq!(
            sequence_update_id(&topic, index),
            identifier,
            "feed id mismatch on {case}"
        );
        assert_eq!(
            soc_address(&identifier, &owner),
            address,
            "SOC address mismatch on {case}"
        );
        let feed = Feed {
            owner,
            topic,
            kind: FeedType::Sequence,
        };
        assert_eq!(
            sequence_update_address(&feed, index),
            address,
            "feed update address mismatch on {case}",
        );

        // inbound: ant accepts the swarmfs-signed chunk at its address...
        assert!(soc_valid(&address, &soc), "soc_valid rejected {case}");
        // ...and rejects it with one payload byte flipped, or at another address
        let mut tampered = soc.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            !soc_valid(&address, &tampered),
            "tampered payload accepted on {case}"
        );
        let mut other = address;
        other[0] ^= 1;
        assert!(!soc_valid(&other, &soc), "wrong address accepted on {case}");

        // outbound: ant's SOC builder signs the same wrapped chunk into the
        // exact same bytes
        let wrapped = &soc[SOC_HEADER_SIZE..];
        let (span, payload) = wrapped.split_at(SPAN_SIZE);
        assert_eq!(
            u64::from_le_bytes(span.try_into().unwrap()),
            payload.len() as u64
        );
        let built = build_gsoc_chunk(&secret, &identifier, payload).unwrap();
        assert_eq!(
            built.address, address,
            "built SOC address mismatch on {case}"
        );
        assert_eq!(
            hex::encode(built.signature),
            v["signature_hex"].as_str().unwrap(),
            "signature mismatch on {case}",
        );
        assert_eq!(
            hex::encode(&built.wire),
            hex::encode(&soc),
            "SOC bytes mismatch on {case}"
        );
        n += 1;
    }
    assert!(n >= 54, "expected the full swarmfs SOC vector set, got {n}");
}

struct MapFetcher(HashMap<[u8; 32], Vec<u8>>);

#[async_trait]
impl ChunkFetcher for MapFetcher {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        self.0
            .get(&addr)
            .cloned()
            .ok_or_else(|| -> Box<dyn StdError + Send + Sync> {
                format!("vector missing chunk {}", hex::encode(addr)).into()
            })
    }
}

fn metadata_of(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

#[tokio::test]
async fn mantaray_manifests_match_swarmfs() {
    let mut n = 0;
    let mut encoded = 0;
    for v in lines(include_str!("swarmfs_mantaray.jsonl")) {
        let case = v["case"].as_str().unwrap();
        let root = h32(v["root_hex"].as_str().unwrap());
        let chunks: HashMap<[u8; 32], Vec<u8>> = v["chunks"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(a, d)| (h32(a), h(d.as_str().unwrap())))
            .collect();
        for (addr, data) in &chunks {
            assert!(
                ant_crypto::cac_valid(addr, data),
                "bad vector chunk on {case}"
            );
        }
        let entries: Vec<(String, Vec<u8>, BTreeMap<String, String>)> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["path"].as_str().unwrap().to_owned(),
                    h(e["ref_hex"].as_str().unwrap()),
                    metadata_of(&e["metadata"]),
                )
            })
            .collect();
        let fetcher = MapFetcher(chunks.clone());

        // read: every entry resolves to its reference and metadata
        for (path, reference, metadata) in &entries {
            let got = lookup_path(&fetcher, &root, path)
                .await
                .unwrap_or_else(|e| panic!("lookup {path:?} failed on {case}: {e}"));
            assert_eq!(
                &got.data_ref, reference,
                "ref mismatch for {path:?} on {case}"
            );
            let got_meta: BTreeMap<_, _> = got.metadata.into_iter().collect();
            assert_eq!(
                &got_meta, metadata,
                "metadata mismatch for {path:?} on {case}"
            );
        }
        // ...no proper prefix of one that isn't an entry itself does
        for missing in v["missing_paths_hex"].as_array().unwrap() {
            let Ok(path) = String::from_utf8(h(missing.as_str().unwrap())) else {
                continue; // splits a codepoint: not addressable as a &str path
            };
            if let Ok(got) = lookup_path(&fetcher, &root, &path).await {
                panic!(
                    "{path:?} is not an entry but resolved to {} on {case}",
                    hex::encode(got.data_ref)
                );
            }
        }
        // ...and the listing is exactly the entry set, each entry once:
        // compared as sorted lists, not maps, so a path listed twice fails
        let mut listed: Vec<(String, Vec<u8>)> = list_manifest_paths(&fetcher, &root)
            .await
            .unwrap_or_else(|e| panic!("list failed on {case}: {e}"))
            .into_iter()
            .filter_map(|e| e.reference.map(|r| (e.path, r)))
            .collect();
        listed.sort();
        let mut want: Vec<(String, Vec<u8>)> = entries
            .iter()
            .map(|(p, r, _)| (p.clone(), r.clone()))
            .collect();
        want.sort();
        assert_eq!(listed, want, "listing mismatch on {case}");

        // write: ant's manifest writer only emits the zero obfuscation key;
        // for those, it must produce swarmfs's exact chunks and root
        if v["obfuscation_key_hex"].as_str().unwrap() == "00".repeat(32) {
            let raw: Vec<RawManifestEntry> = entries
                .iter()
                .map(|(path, reference, metadata)| RawManifestEntry {
                    path: path.clone(),
                    reference: reference.as_slice().try_into().unwrap(),
                    metadata: metadata.clone(),
                })
                .collect();
            let built = build_entries_manifest(&raw)
                .unwrap_or_else(|e| panic!("ant manifest build failed on {case}: {e}"));
            let built_chunks: HashMap<[u8; 32], Vec<u8>> = built
                .chunks
                .into_iter()
                .map(|c| (c.address, c.wire))
                .collect();
            let mut want_addrs: Vec<_> = chunks.keys().map(hex::encode).collect();
            let mut got_addrs: Vec<_> = built_chunks.keys().map(hex::encode).collect();
            want_addrs.sort();
            got_addrs.sort();
            assert_eq!(
                got_addrs, want_addrs,
                "manifest chunk set mismatch on {case}"
            );
            assert_eq!(
                hex::encode(built.root),
                hex::encode(root),
                "root mismatch on {case}"
            );
            encoded += 1;
        }
        n += 1;
    }
    assert!(
        n >= 10,
        "expected the full swarmfs Mantaray vector set, got {n}"
    );
    assert!(
        encoded >= 9,
        "expected every unobfuscated case encoded, got {encoded}"
    );
}
