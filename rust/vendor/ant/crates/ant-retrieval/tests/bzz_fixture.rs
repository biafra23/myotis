//! Offline replay of a real `antctl get bzz://...` against a frozen
//! fixture of the chunks the daemon retrieved on the first successful
//! mainnet run.
//!
//! The fixture in `tests/fixtures/bzz-ab7720-13-4358-2645/` was captured
//! by running
//!
//! ```sh
//! RECORD_DIR=$(pwd)/crates/ant-retrieval/tests/fixtures/bzz-ab7720-13-4358-2645 \
//!     ./scripts/verify-bzz-get.sh
//! ```
//!
//! against Swarm mainnet. Each `<hex_addr>.bin` is the wire bytes of one
//! chunk (`8-byte LE span || payload`). Replaying these through the
//! mantaray walker + joiner exercises every code path that turns a
//! `bzz://<root>/<path>` into raw file bytes — without depending on the
//! live network. If the test fails after a refactor of either the
//! mantaray decoder or the joiner, that's the regression we want to
//! catch.

use ant_retrieval::{
    join_with_options, lookup_path, ChunkFetcher, JoinOptions, DEFAULT_MAX_FILE_BYTES,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::path::Path;

/// Manifest reference at the head of `bzz://AB7720…/13/4358/2645.png`.
const ROOT_REF: &str = "ab77201f6541a9ceafb98a46c643273cfa397a87798273dd17feb2aa366ce2e6";

/// Manifest path inside the BZZ URL — three numeric segments plus a
/// `.png` leaf. Verifies that mantaray's fork-by-fork walker handles
/// multi-segment paths the same way bee does.
const MANIFEST_PATH: &str = "13/4358/2645.png";

/// SHA-256 of the file body the live daemon produced on capture day.
/// If a future refactor of the joiner / span handling changes a single
/// byte of the assembled output, this assertion fires.
const EXPECTED_FILE_SHA256: &str =
    "2fedb435506d7f61f6c1014d94a7422f53e4a1a6bdd1ff8231c1215033e5ea3d";

/// Expected file size — captured tile is a 256×256 paletted PNG. Used
/// alongside the sha256 so a length-only regression surfaces a more
/// useful failure than just "hash mismatch".
const EXPECTED_FILE_BYTES: usize = 18_604;

/// HashMap-backed `ChunkFetcher` that loads every `<hex>.bin` file in
/// a directory. Mirrors the per-module `MapFetcher` used by the
/// joiner / mantaray unit tests, but lives here so the integration
/// test doesn't depend on test-private helpers from `src/`.
struct DirFetcher {
    chunks: HashMap<[u8; 32], Vec<u8>>,
}

impl DirFetcher {
    fn from_dir(dir: &Path) -> std::io::Result<Self> {
        let mut chunks = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let mut addr = [0u8; 32];
            if hex::decode_to_slice(stem, &mut addr).is_err() {
                continue;
            }
            chunks.insert(addr, std::fs::read(&path)?);
        }
        Ok(Self { chunks })
    }
}

#[async_trait]
impl ChunkFetcher for DirFetcher {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        self.chunks
            .get(&addr)
            .cloned()
            .ok_or_else(|| -> Box<dyn StdError + Send + Sync> {
                format!("fixture missing chunk {}", hex::encode(addr)).into()
            })
    }
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("bzz-ab7720-13-4358-2645")
}

fn decode_root() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(ROOT_REF, &mut out).expect("root ref hex");
    out
}

/// Full read-path replay: walk the manifest, fetch the data root,
/// join the file body, hash it. Locks both `lookup_path` and
/// `join_with_options` against a real-world manifest that exercises
/// the redundancy-mask path the live daemon takes for this URL.
#[tokio::test]
async fn replays_mainnet_bzz_fixture() {
    let fetcher = DirFetcher::from_dir(&fixture_dir()).expect("load fixture chunks");
    let root = decode_root();

    let lookup = lookup_path(&fetcher, &root, MANIFEST_PATH)
        .await
        .expect("manifest lookup");

    assert_eq!(
        lookup.content_type.as_deref(),
        Some("image/png"),
        "expected the manifest to advertise the tile as image/png",
    );

    // The data ref is the fixture's only chunk that *isn't* on the
    // mantaray walk path; carrying its hex into the test gives the
    // assertion a fingerprint independent of the joiner's output.
    assert_eq!(
        hex::encode(&lookup.data_ref),
        "285e4c1564cce481fcb21039208795b86ef42042cc0bb45b9d7f16d638d3c296",
        "data ref drifted; either the manifest changed on chain or \
         the lookup walker took a different fork",
    );

    let root_chunk = fetcher
        .fetch(
            lookup
                .data_ref
                .as_slice()
                .try_into()
                .expect("32-byte data ref"),
        )
        .await
        .expect("fetch data root from fixture");

    // The live root chunk's span carries a redundancy level byte; the
    // joiner decodes it on every path. `allow_degraded_redundancy` is a
    // legacy no-op (antctl only sends `true` when a user passes the
    // deprecated `--allow-degraded-redundancy` flag; it defaults to
    // `false`), so the join must succeed with it set too.
    let opts = JoinOptions {
        allow_degraded_redundancy: true,
    };
    let body = join_with_options(&fetcher, &root_chunk, DEFAULT_MAX_FILE_BYTES, opts)
        .await
        .expect("join file body");

    assert_eq!(
        body.len(),
        EXPECTED_FILE_BYTES,
        "joined byte count drifted from the captured PNG",
    );
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hasher.finalize();
    assert_eq!(
        hex::encode(digest),
        EXPECTED_FILE_SHA256,
        "joined byte stream sha256 drifted; the joiner produced a \
         different file from the same chunks",
    );

    let png_magic: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    assert!(
        body.starts_with(png_magic),
        "joined body is missing the PNG magic header",
    );
}
