//! Gloas light-client decoding and proof selection against the consensus-specs
//! v1.7.0-beta.2 vectors in `rust/testdata/lc/gloas-spec` (see its README).
//! Java twin: `GloasSpecVectorTest`.
//!
//! - `ssz_static` (mainnet preset): the production Gloas decoders read each
//!   container, and the container root recomputed from the decoded fields
//!   equals the spec's — so every field sits where the decoder reads it.
//! - `light_client_sync` / `gloas_fork` (minimal preset, sliced by hand): the
//!   production gindices and `verify_execution_branch_at` accept genuine Gloas
//!   proofs, and the depth-derived pre-Gloas gindices do not. Genuine Fulu
//!   headers upgraded to the Gloas shape (`upgrade_lc_header_to_gloas`) — what a
//!   Gloas update carries as its finalized header in the first epochs after the
//!   fork — prove at 812 with zero padding.

use myotis_consensus::fork::{ForkSchedule, LcFork};
use myotis_consensus::spec;
use myotis_consensus::ssz::{self, Root};
use myotis_consensus::store::verify_execution_branch_at;
use myotis_consensus::types::{
    HeaderExecution, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientUpdate, SyncAggregate,
};

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/lc/gloas-spec")
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn hex32(s: &str) -> Root {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn roots() -> Vec<(String, Root)> {
    String::from_utf8(read("mainnet/ssz_static/roots.txt"))
        .unwrap()
        .lines()
        .map(|l| {
            let (name, root) = l.split_once(' ').unwrap();
            (name.to_string(), hex32(root))
        })
        .collect()
}

// ---- container roots, recomputed from decoded fields (test-side only) ----

fn header_root(h: &LightClientHeader) -> Root {
    ssz::container_root(&[
        h.beacon.hash_tree_root(),
        h.execution_block_hash(),
        ssz::merkleize(&h.execution_branch),
    ])
}

fn aggregate_root(a: &SyncAggregate) -> Root {
    let bits: Vec<Root> = a
        .sync_committee_bits
        .chunks(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    ssz::container_root(&[
        ssz::merkleize(&bits),
        ssz::byte_vector_root(&a.sync_committee_signature),
    ])
}

#[test]
fn ssz_static_containers_decode_to_the_spec_roots() {
    let mut checked = 0;
    for (name, want) in roots() {
        let bytes = read(&format!("mainnet/ssz_static/{name}.ssz"));
        let got = match name.split('/').next().unwrap() {
            "LightClientHeader" => {
                let h = LightClientHeader::decode_for(LcFork::Gloas, &bytes).unwrap();
                assert_eq!(h.shape(), LcFork::Gloas);
                header_root(&h)
            }
            "LightClientBootstrap" => {
                let b = LightClientBootstrap::decode_for(LcFork::Gloas, &bytes).unwrap();
                ssz::container_root(&[
                    header_root(&b.header),
                    b.current_sync_committee.hash_tree_root(),
                    ssz::merkleize(&b.current_sync_committee_branch),
                ])
            }
            "LightClientUpdate" => {
                let u = LightClientUpdate::decode_for(LcFork::Gloas, &bytes).unwrap();
                ssz::container_root(&[
                    header_root(&u.attested_header),
                    u.next_sync_committee.hash_tree_root(),
                    ssz::merkleize(&u.next_sync_committee_branch),
                    header_root(&u.finalized_header),
                    ssz::merkleize(&u.finality_branch),
                    aggregate_root(&u.sync_aggregate),
                    ssz::uint64_root(u.signature_slot),
                ])
            }
            "LightClientFinalityUpdate" => {
                let u = LightClientFinalityUpdate::decode_for(LcFork::Gloas, &bytes).unwrap();
                ssz::container_root(&[
                    header_root(&u.attested_header),
                    header_root(&u.finalized_header),
                    ssz::merkleize(&u.finality_branch),
                    aggregate_root(&u.sync_aggregate),
                    ssz::uint64_root(u.signature_slot),
                ])
            }
            other => panic!("unexpected type {other}"),
        };
        assert_eq!(got, want, "{name}: hash_tree_root of the decoded fields");
        checked += 1;
    }
    assert_eq!(checked, 8);
}

// ---- minimal preset: slice by hand, verify with the production rules ----

/// Minimal-preset sizes (32-member sync committee).
const MIN_COMMITTEE: usize = 32;
const MIN_SYNC_COMMITTEE_SIZE: usize = MIN_COMMITTEE * 48 + 48; // 1584
const H: usize = LightClientHeader::GLOAS_SIZE;

fn minimal_committee_root(bytes: &[u8]) -> Root {
    assert_eq!(bytes.len(), MIN_SYNC_COMMITTEE_SIZE);
    let pubkey_root = |pk: &[u8]| {
        let mut c0 = [0u8; 32];
        c0.copy_from_slice(&pk[..32]);
        let mut c1 = [0u8; 32];
        c1[..16].copy_from_slice(&pk[32..48]);
        ssz::merkleize(&[c0, c1])
    };
    let keys: Vec<Root> = bytes[..MIN_COMMITTEE * 48]
        .chunks(48)
        .map(pubkey_root)
        .collect();
    ssz::container_root(&[
        ssz::merkleize(&keys),
        pubkey_root(&bytes[MIN_COMMITTEE * 48..]),
    ])
}

fn nodes(bytes: &[u8], at: usize, n: usize) -> Vec<Root> {
    (0..n)
        .map(|i| bytes[at + 32 * i..at + 32 * (i + 1)].try_into().unwrap())
        .collect()
}

/// The minimal config of these vectors: 8-slot epochs, Gloas at epoch 3.
fn minimal_schedule() -> ForkSchedule {
    ForkSchedule::new(8, &[(0, [0x06, 0, 0, 1]), (3, [0x07, 0, 0, 1])]).with_gloas_epoch(3)
}

#[test]
fn a_genuine_gloas_bootstrap_proves_at_the_gloas_gindices() {
    let b = read("minimal/light_client_sync/bootstrap.ssz");
    assert_eq!(b.len(), H + MIN_SYNC_COMMITTEE_SIZE + 11 * 32);
    let header = LightClientHeader::decode_gloas(&b[..H]).unwrap();
    let trusted =
        String::from_utf8(read("minimal/light_client_sync/trusted_block_root.txt")).unwrap();
    assert_eq!(header.beacon.hash_tree_root(), hex32(trusted.trim()));

    assert!(verify_execution_branch_at(&header, LcFork::Gloas));
    assert!(
        !verify_execution_branch_at(&header, LcFork::PreGloas),
        "812 must not accept a 2856 proof"
    );

    let committee = minimal_committee_root(&b[H..H + MIN_SYNC_COMMITTEE_SIZE]);
    let branch = nodes(&b, H + MIN_SYNC_COMMITTEE_SIZE, 11);
    let state = &header.beacon.state_root;
    assert!(ssz::verify_merkle_branch(
        &committee,
        &branch,
        spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
        spec::CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
        state
    ));
    assert!(!ssz::verify_merkle_branch(
        &committee,
        &branch,
        11,
        spec::sync_committee_gindex(11),
        state
    ));
}

#[test]
fn gloas_updates_across_the_fork_prove_at_their_slots_gindices() {
    let schedule = minimal_schedule();
    let expected = String::from_utf8(read("minimal/gloas_fork/expected.txt")).unwrap();
    let mut checked = 0;
    for line in expected.lines() {
        let name = line.split(' ').next().unwrap();
        let field = |key: &str| {
            line.split(' ')
                .find_map(|kv| kv.strip_prefix(key))
                .unwrap_or_else(|| panic!("{key} in {line}"))
                .to_string()
        };
        let u = read(&format!("minimal/gloas_fork/{name}.ssz"));
        const NSC: usize = H;
        const NSC_BRANCH: usize = NSC + MIN_SYNC_COMMITTEE_SIZE;
        const FIN: usize = NSC_BRANCH + 11 * 32;
        const FIN_BRANCH: usize = FIN + H;
        const AGG: usize = FIN_BRANCH + 9 * 32;
        assert_eq!(u.len(), AGG + (4 + 96) + 8, "{name}");

        let attested = LightClientHeader::decode_gloas(&u[..H]).unwrap();
        let finalized = LightClientHeader::decode_gloas(&u[FIN..FIN_BRANCH]).unwrap();
        assert_eq!(
            attested.beacon.hash_tree_root(),
            hex32(&field("attested_root=")),
            "{name}"
        );
        assert_eq!(
            schedule.lc_fork_at_slot(attested.beacon.slot),
            LcFork::Gloas,
            "{name}"
        );
        assert!(
            verify_execution_branch_at(&attested, LcFork::Gloas),
            "{name}: attested"
        );
        assert!(
            !verify_execution_branch_at(&attested, LcFork::PreGloas),
            "{name}: attested at 812"
        );

        // Finality: the ATTESTED slot's fork picks the gindex. Until the chain
        // finalizes past genesis the spec carries an EMPTY finalized header and
        // proves a zero leaf (the genesis checkpoint root); the spec's store
        // keeps its own finalized header then, which is what `expected.txt`
        // records. (Myotis' processors reject such updates outright — no
        // network they follow is in its first epochs — so only the proof is
        // checked here.)
        let state = &attested.beacon.state_root;
        let finality = nodes(&u, FIN_BRANCH, 9);
        let leaf = if finalized.beacon.slot == 0 {
            assert_eq!(
                finalized,
                LightClientHeader::decode_gloas(&[0u8; H]).unwrap(),
                "{name}"
            );
            [0u8; 32]
        } else {
            assert_eq!(
                finalized.beacon.hash_tree_root(),
                hex32(&field("finalized_root=")),
                "{name}"
            );
            assert_eq!(
                finalized.beacon.slot.to_string(),
                field("finalized_slot="),
                "{name}"
            );
            let fork = schedule.lc_fork_at_slot(finalized.beacon.slot);
            assert!(
                verify_execution_branch_at(&finalized, fork),
                "{name}: finalized"
            );
            finalized.beacon.hash_tree_root()
        };
        assert!(ssz::verify_merkle_branch(
            &leaf,
            &finality,
            9,
            spec::FINALIZED_ROOT_GINDEX_GLOAS,
            state
        ));
        assert!(!ssz::verify_merkle_branch(
            &leaf,
            &finality,
            9,
            spec::finalized_root_gindex(9),
            state
        ));

        let next = minimal_committee_root(&u[NSC..NSC_BRANCH]);
        let next_branch = nodes(&u, NSC_BRANCH, 11);
        assert!(ssz::verify_merkle_branch(
            &next,
            &next_branch,
            11,
            spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS,
            state
        ));
        checked += 1;
    }
    assert_eq!(checked, 3);
}

/// `upgrade_lc_header_to_gloas` on two genuine Fulu headers of the transition
/// test: the first update's attested header (slot 17) and the bootstrap's
/// (slot 16 — the block the spec's store holds as FINALIZED across the fork,
/// i.e. the header a Gloas update carries as its finalized header in the first
/// epochs after it). Block hash + [proof of the block hash inside the payload
/// header (5) ++ the payload's own branch (4)], normalized to 11. Each must
/// prove at 812 (the pre-Gloas slot's rule) with the two zero pad nodes, and
/// nowhere else.
///
/// v1.7.0-beta.2 has no Gloas-format update whose finalized header is a
/// non-genesis pre-Gloas block (its transition carries the empty genesis
/// header, then finalizes a Gloas slot), so this upgrade — the computation a
/// serving node performs — is the genuine input for that path;
/// `gloas_boundary.rs` walks it through the processor.
#[test]
fn a_fulu_header_in_the_gloas_shape_proves_at_812() {
    let u = read("minimal/gloas_fork/fulu_update.ssz");
    let attested_at = u32::from_le_bytes(u[0..4].try_into().unwrap()) as usize;
    let finalized_at = {
        let at = 4 + MIN_SYNC_COMMITTEE_SIZE + 6 * 32;
        u32::from_le_bytes(u[at..at + 4].try_into().unwrap()) as usize
    };
    let attested = LightClientHeader::decode(&u[attested_at..finalized_at]).unwrap();
    let b = read("minimal/gloas_fork/fulu_bootstrap.ssz");
    let header_at = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
    let finalized = LightClientHeader::decode(&b[header_at..]).unwrap();
    // The trusted block root of the test, and `expected.txt`'s store finality.
    assert_eq!(
        finalized.beacon.hash_tree_root(),
        hex32("b80f3f35165bdc5afb240b420faed2875d00b593d86ed17d450ac0e09b8f7019")
    );
    for (pre, slot) in [(attested, 17), (finalized, 16)] {
        assert_eq!(pre.beacon.slot, slot);
        assert!(
            verify_execution_branch_at(&pre, LcFork::PreGloas),
            "slot {slot}: genuine at gindex 25"
        );

        let p = pre.execution_payload().unwrap();
        let fields = [
            p.parent_hash,
            ssz::padded_root(&p.fee_recipient),
            p.state_root,
            p.receipts_root,
            ssz::byte_vector_root(&p.logs_bloom),
            p.prev_randao,
            ssz::uint64_root(p.block_number),
            ssz::uint64_root(p.gas_limit),
            ssz::uint64_root(p.gas_used),
            ssz::uint64_root(p.timestamp),
            ssz::byte_list_root(&p.extra_data, 1),
            p.base_fee_per_gas,
            p.block_hash,
            p.transactions_root,
            p.withdrawals_root,
            ssz::uint64_root(p.blob_gas_used),
            ssz::uint64_root(p.excess_blob_gas),
        ];
        // Proof of field 12 (block_hash) in the 32-leaf payload-header tree.
        let mut level: Vec<Root> = fields.to_vec();
        level.resize(32, [0u8; 32]);
        let (mut idx, mut proof) = (12usize, Vec::new());
        while level.len() > 1 {
            proof.push(level[idx ^ 1]);
            level = level
                .chunks(2)
                .map(|c| ssz::sha256_pair(&c[0], &c[1]))
                .collect();
            idx /= 2;
        }
        assert_eq!(level[0], p.hash_tree_root());

        let mut branch = vec![[0u8; 32]; 2];
        branch.extend(proof);
        branch.extend(pre.execution_branch.iter().copied());
        let upgraded = LightClientHeader {
            beacon: pre.beacon.clone(),
            execution: HeaderExecution::BlockHash(p.block_hash),
            execution_branch: branch,
        };
        assert!(
            verify_execution_branch_at(&upgraded, LcFork::PreGloas),
            "slot {slot}: 812, normalized"
        );
        assert!(
            !verify_execution_branch_at(&upgraded, LcFork::Gloas),
            "slot {slot}: not at 2856"
        );
        let mut dirty = upgraded.clone();
        dirty.execution_branch[0][0] = 1;
        assert!(
            !verify_execution_branch_at(&dirty, LcFork::PreGloas),
            "slot {slot}: a non-zero pad is not padding"
        );
        let mut short = upgraded;
        short.execution_branch.remove(0);
        assert!(
            !verify_execution_branch_at(&short, LcFork::PreGloas),
            "slot {slot}: the Gloas vector is 11 nodes"
        );
    }
}
