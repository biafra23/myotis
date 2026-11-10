//! ZK sync — a sync committee proven by a zero-knowledge proof instead of
//! walked to by light-client updates (docs/how-it-works/zk-sync.md).
//!
//! The proofs are Colibri's (corpus-core/colibri-stateless,
//! `src/chains/eth/zk_proof`, used with the Colibri team's permission): an SP1
//! guest program verifies ONE sync-committee handoff — the old committee's ≥2/3
//! BLS signature over an attested header whose state commits to the next
//! committee's pubkeys — and recursively verifies the proof of the previous
//! handoff, so the proof for period `N` attests the whole chain of handoffs from
//! a fixed per-network ANCHOR committee to committee `N`. The STARK is wrapped
//! in a Groth16 proof over BN254, which is what this module checks: 356 bytes, a
//! handful of pairings.
//!
//! What a verified [`ZkSyncData`] gives the light client is exactly what a
//! bootstrap gives it, minus a finalized header: the 512 pubkeys of the
//! committee of one period. The caller still needs a header signed by that
//! committee (a finality update, which every light-client server answers) to
//! initialize a store — see `LightClientProcessor::initialize_from_proven_committee`.
//!
//! Every input that can change the answer is pinned here or recomputed locally,
//! never taken from the file: the Groth16 verifying key, the SP1 program hash and
//! recursion-VK root, the anchor committee root, the period, the signing domain
//! (from this chain's own fork schedule and genesis validators root), and the
//! committee root (hashed from the pubkeys the file carries). The file supplies
//! only the proof, the pubkeys and the attested header — a server can withhold
//! a proof, never forge one.

#[allow(unused_imports)]
use alloc::{boxed::Box, format, string::{String, ToString}, vec, vec::Vec};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, PrimeField, Zero};
use sha2::{Digest, Sha256};

use crate::fork::ForkSchedule;
use crate::spec;
use crate::ssz::Root;
use crate::types::{BeaconBlockHeader, SyncCommittee, PUBKEY_SIZE};
use crate::verify;

/// Size of the SP1 v6 Groth16 proof bundle: a 4-byte VK selector, three
/// 32-byte public inputs SP1 v6 added (exit code, recursion-VK root, nonce),
/// then A (G1), B (G2), C (G1).
pub const PROOF_LEN: usize = 356;
const OFF_EXIT_CODE: usize = 4;
const OFF_VK_ROOT: usize = 36;
const OFF_NONCE: usize = 68;
const OFF_A: usize = 100;
const OFF_B: usize = 164;
const OFF_C: usize = 292;

/// The guest program's committed public values (bincode of its
/// `VerificationOutput`): anchor keys root ‖ next keys root ‖ next period (u64
/// LE) ‖ attested header root ‖ signing domain.
pub const PUBLIC_VALUES_LEN: usize = 136;

/// The SP1 program this client accepts proofs from: Colibri's `eth_sync_program`
/// guest, by its SP1 vkey hash (a BN254 scalar, big-endian). Copied from
/// `zk_verifier_constants.h` (`VK_PROGRAM_HASH`) at Colibri v0.1.2. A rotated
/// guest is a NEW program: its proofs are refused here until this pin (and the
/// anchors below, which a rotation restarts) move with a reviewed release.
pub const PROGRAM_VKEY_HASH: [u8; 32] =
    hex32("003ae92c1886644d1df602b04dac5efe659a3dc19baa4a93d2684943606e47f6");

/// SP1 v6's recursion-VK Merkle root (`VK_ROOT`): a public input of every SP1 v6
/// Groth16 proof. Pinning it refuses proofs rooted at another recursion VK set.
/// Equal to `SP1VerifierGroth16.VK_ROOT()` in succinctlabs/sp1-contracts
/// `contracts/src/v6.1.0`.
pub const SP1_VK_ROOT: [u8; 32] =
    hex32("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352");

/// The first four bytes of every proof: SP1's verifier selector, the prefix of
/// `SP1VerifierGroth16.VERIFIER_HASH()` (sp1-contracts v6.1.0). It names the
/// verifying key below, so a proof made for another SP1 release is refused as
/// such instead of failing the pairing.
pub const SP1_VERIFIER_SELECTOR: [u8; 4] = [0x43, 0x88, 0xa2, 0x1c];

/// The SP1 v6 Groth16 wrapper circuit's verifying key — the same for every SP1
/// program (the program is a public input). Each constant equals its namesake
/// in succinctlabs/sp1-contracts `contracts/src/v6.1.0/Groth16Verifier.sol`
/// (checked 2026-11-10; Colibri's `zk_verifier_constants.h` carries the same
/// values): big-endian coordinates, G2 as (x.c0, x.c1, y.c0, y.c1), the
/// beta/gamma/delta terms pre-negated for the single pairing product.
mod vk {
    use super::hex32;
    pub const ALPHA: [[u8; 32]; 2] = [
        hex32("21c7d728a5fd961fc179ec5eab938f564deba5b271e1c90c2c29a79648418fc1"),
        hex32("2317bd9b644830ef5ffec1c2d46b5442aa8029d41eb58fb8fc939fb03365e00e"),
    ];
    pub const BETA_NEG: [[u8; 32]; 4] = [
        hex32("0d964538da2653f2e62499571e6c78afb8909d3ea8107f306bd6928253680a3a"),
        hex32("1c3c9339849225980c7d3f824f80d19e2a9c2554b6ab2160fa9635528f693fc0"),
        hex32("09ec9e44c7989c61a534b716d1d6db028893c68a9934b17f3a50af2e56d1cc7d"),
        hex32("03d612368fddb0f3f83497dbc0ae760f98978cff3af02fdee725fb3562839ae9"),
    ];
    pub const GAMMA_NEG: [[u8; 32]; 4] = [
        hex32("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        hex32("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        hex32("1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d"),
        hex32("275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec"),
    ];
    pub const DELTA_NEG: [[u8; 32]; 4] = [
        hex32("1723616533dd6ae53502c9c506a81f23f543d68750b5133ebfbe1f4746b3b011"),
        hex32("11b7e9276171bb0efd647fc63e38bbfba3076f20daca8cd52bcc7284d9b1c6eb"),
        hex32("2addf202c6b971af36fbafa29888d52e2d13e3e95ea7513d6436f0c1f256f53b"),
        hex32("241dc9f1df2ecb0c7e6d9522e0d83fe29cb5f4af6571c91c49ea04640c049221"),
    ];
    /// The constant term and one base per public input: program vkey hash,
    /// public-values digest, exit code, recursion-VK root, proof nonce.
    pub const IC: [[[u8; 32]; 2]; 6] = [
        [
            hex32("2cd6bf7f164af0b6b0bbbe0fdcb06ee0c1ba07f8e6eb2f9f3943a90cb1d40290"),
            hex32("0a76f7e6e8a78d71649eb7e3132018885e2f57ccca64394738e746c63c9fa83b"),
        ],
        [
            hex32("0f5460f3b7221705435e745da21e276536379c0113c13c4255e7ae101f1e90bf"),
            hex32("022b4d6c4b7dbdeed528d5abe6eddd6f2bd4ae4b9b0450dc18901fc727da799c"),
        ],
        [
            hex32("0b0ae6e491bc04c544da9e8cd4857d201b4cfa0222dbe96aac97f044fdf1c922"),
            hex32("123e064d2ffdb7f8094b727cde1c0beea6d4d551e5743a336804f8effb7f07ac"),
        ],
        [
            hex32("097c875a6ebd0999b06e7267ff3d8a6bf859bb9635abae07cb6b3534ba409a83"),
            hex32("2d84b73fb0f397e356b524f2d0e9ddc9d0f6ac75e566041147ee8554879183ec"),
        ],
        [
            hex32("1807204ddcd27506ba72e17b55227b0bf310136ecb40c74acd52f3ccfbcba9f7"),
            hex32("011078b5c7767fe73bb54241dcd143ee805ea4383d48d46bced129482c8c2021"),
        ],
        [
            hex32("008c7b7c98d78c07a2c4be5f6be7082ba41021611f9a2dfc016f8bbb37d36bee"),
            hex32("09ce6d246baeac24b5a404ca175c2cc4a974e217176fe2ec2a6c22eb60fd65c1"),
        ],
    ];
}

/// Per-network anchors of Colibri's recursive proof chains: the pubkeys-only
/// hash_tree_root (`Vector[BLSPubkey, 512]`, NOT the `SyncCommittee` container
/// root, which mixes in the aggregate key) of the committee every proof of that
/// network starts from. Copied from Colibri's `chain_spec.c`
/// (`zk_sync_keys_root`) at v0.1.2; each is checked against the committee our
/// own light client derives in docs/how-it-works/zk-sync.md (*Anchor provenance*).
pub mod anchors {
    use super::hex32;
    /// Committee of mainnet period 1844.
    pub const MAINNET: [u8; 32] =
        hex32("c610d3cf3ff6f40248ade812e570857e7412af3545cbee9175cf54cccfa2213c");
    /// Committee of sepolia period 1347.
    pub const SEPOLIA: [u8; 32] =
        hex32("ee5c880d524166b4b1d3eddabaeacb3fdf1e40c9008f256e357e722d80ba9725");
    /// Committee of gnosis period 3642.
    pub const GNOSIS: [u8; 32] =
        hex32("1997249f4dd2f36653052f438ce4809a2db7fab8a33f49c22f6132d2a107b8e0");
}

/// Why a [`ZkSyncData`] was refused. Every variant is a refusal of THIS file —
/// the caller falls back to the light-client update walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkReject {
    /// Not a `ZKSyncData` container (length or offsets).
    Malformed(&'static str),
    /// Proved by another SP1 program than [`PROGRAM_VKEY_HASH`].
    UnknownProgram,
    /// The attested header is not in the period before the requested one.
    WrongPeriod { requested: u64, proven: u64 },
    /// This chain's geometry is not the one the guest hardcodes (8192 slots
    /// per period).
    UnsupportedGeometry,
    /// Made for another SP1 verifier, by a guest that panicked (non-zero exit
    /// code), or rooted at a foreign recursion VK set.
    BadProofHeader,
    /// A curve point or scalar is not canonical / not on the curve / not in
    /// the subgroup.
    BadEncoding,
    /// The pairing check failed for every domain this chain could have signed
    /// the attested header under.
    InvalidProof,
    /// The pubkeys are not valid BLS keys (cannot be aggregated).
    BadPubkeys,
}

impl core::fmt::Display for ZkReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZkReject::Malformed(why) => write!(f, "malformed ZKSyncData: {why}"),
            ZkReject::UnknownProgram => f.write_str("proof is from an unpinned SP1 program"),
            ZkReject::WrongPeriod { requested, proven } => {
                write!(f, "proof is for period {proven}, requested {requested}")
            }
            ZkReject::UnsupportedGeometry => {
                f.write_str("chain geometry is not 8192 slots per period")
            }
            ZkReject::BadProofHeader => {
                f.write_str("foreign SP1 verifier, non-zero exit code or foreign recursion VK root")
            },
            ZkReject::BadEncoding => f.write_str("non-canonical or off-curve proof element"),
            ZkReject::InvalidProof => f.write_str("Groth16 pairing check failed"),
            ZkReject::BadPubkeys => f.write_str("proven pubkeys are not valid BLS keys"),
        }
    }
}

/// Colibri's `ZKSyncData` container (the `period_store/<N>/zk_proof.ssz` file):
/// `vk_hash` (32) ‖ `proof` (356) ‖ `header` (`BeaconBlockHeader`, 112) ‖
/// `pubkeys` (512 × 48) ‖ offset(`checkpoint`) ‖ offset(`signatures`) ‖ the two
/// variable parts. The `checkpoint` header chain and the witness `signatures`
/// serve Colibri's own weak-subjectivity checks against third-party servers and
/// are not read here (decoded only far enough to reject a malformed container).
#[derive(Clone)]
pub struct ZkSyncData {
    pub vk_hash: [u8; 32],
    pub proof: [u8; PROOF_LEN],
    pub attested_header: BeaconBlockHeader,
    /// 512 × 48 bytes, the layout [`SyncCommittee::pubkeys`] uses.
    pub pubkeys: Vec<u8>,
}

impl core::fmt::Debug for ZkSyncData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ZkSyncData(attested slot {})", self.attested_header.slot)
    }
}

const PUBKEYS_LEN: usize = spec::SYNC_COMMITTEE_SIZE * PUBKEY_SIZE;
const FIXED_LEN: usize = 32 + PROOF_LEN + BeaconBlockHeader::ENCODED_SIZE + PUBKEYS_LEN + 4 + 4;
/// A served file is ~27 KB; anything far past that is not one.
pub const MAX_FILE_LEN: usize = 64 * 1024;

impl ZkSyncData {
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkReject> {
        if bytes.len() < FIXED_LEN || bytes.len() > MAX_FILE_LEN {
            return Err(ZkReject::Malformed("length"));
        }
        let mut o = 0;
        let mut take = |n: usize| {
            let s = &bytes[o..o + n];
            o += n;
            s
        };
        let vk_hash: [u8; 32] = take(32).try_into().unwrap();
        let proof: [u8; PROOF_LEN] = take(PROOF_LEN).try_into().unwrap();
        let attested_header = BeaconBlockHeader::decode(take(BeaconBlockHeader::ENCODED_SIZE))
            .map_err(|_| ZkReject::Malformed("header"))?;
        let pubkeys = take(PUBKEYS_LEN).to_vec();
        let off_checkpoint = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
        let off_signatures = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
        if off_checkpoint != FIXED_LEN
            || off_signatures < off_checkpoint
            || off_signatures > bytes.len()
        {
            return Err(ZkReject::Malformed("offsets"));
        }
        Ok(Self { vk_hash, proof, attested_header, pubkeys })
    }
}

/// What a verified [`ZkSyncData`] proves: the committee of `period`, complete
/// (its aggregate key recomputed from the pubkeys, so the container root is the
/// spec's), and the header its predecessor signed to hand over to it.
#[derive(Debug, Clone)]
pub struct ProvenCommittee {
    pub period: u64,
    pub committee: SyncCommittee,
    pub attested_header: BeaconBlockHeader,
}

/// The chain-specific inputs of a check: the anchor committee root this
/// network's proof chain starts from, and what the signing domain is computed
/// from.
pub struct ZkChain<'a> {
    pub anchor_keys_root: [u8; 32],
    pub fork_schedule: &'a ForkSchedule,
    pub genesis_validators_root: Root,
    pub slots_per_period: u64,
}

/// Verify `data` as the proof of the committee of `period` on `chain`.
///
/// Recomputes every public value locally — the anchor (pinned), the committee
/// root (hashed from the file's pubkeys), the period (requested, and checked
/// against the attested header's), the attested header root, the domain (this
/// chain's `DOMAIN_SYNC_COMMITTEE` under each fork version that can have signed
/// that header) — and accepts only if the Groth16 proof verifies for them.
pub fn verify_zk_sync_data(
    data: &ZkSyncData,
    period: u64,
    chain: &ZkChain<'_>,
) -> Result<ProvenCommittee, ZkReject> {
    // The guest computes the period as `slot >> 13`.
    if chain.slots_per_period != 8192 {
        return Err(ZkReject::UnsupportedGeometry);
    }
    if data.vk_hash != PROGRAM_VKEY_HASH {
        return Err(ZkReject::UnknownProgram);
    }
    let proven = data.attested_header.slot / chain.slots_per_period + 1;
    if proven != period || period == 0 {
        return Err(ZkReject::WrongPeriod { requested: period, proven });
    }

    let next_keys_root = SyncCommittee::pubkeys_root_of(&data.pubkeys);
    let header_root = data.attested_header.hash_tree_root();

    let mut verified = false;
    for version in signing_versions(chain.fork_schedule, data.attested_header.slot, chain.slots_per_period) {
        let domain = verify::compute_domain(
            &spec::DOMAIN_SYNC_COMMITTEE,
            &version,
            &chain.genesis_validators_root,
        );
        let mut public_values = [0u8; PUBLIC_VALUES_LEN];
        public_values[0..32].copy_from_slice(&chain.anchor_keys_root);
        public_values[32..64].copy_from_slice(&next_keys_root);
        public_values[64..72].copy_from_slice(&period.to_le_bytes());
        public_values[72..104].copy_from_slice(&header_root);
        public_values[104..136].copy_from_slice(&domain);
        match verify_sp1_groth16(&data.proof, &public_values) {
            Ok(true) => {
                verified = true;
                break;
            }
            Ok(false) => continue,
            Err(e) => return Err(e),
        }
    }
    if !verified {
        return Err(ZkReject::InvalidProof);
    }

    let aggregate_pubkey =
        myotis_bls::aggregate_pubkeys(&data.pubkeys).ok_or(ZkReject::BadPubkeys)?;
    Ok(ProvenCommittee {
        period,
        committee: SyncCommittee { pubkeys: data.pubkeys.clone(), aggregate_pubkey },
        attested_header: data.attested_header.clone(),
    })
}

/// The fork versions the committee of the attested header's period can have
/// signed it under: the sync aggregate sits in a later block of the SAME period
/// (the old committee signs the handoff), so its version is one active between
/// the attested epoch and that period's last epoch. Almost always one.
fn signing_versions(schedule: &ForkSchedule, attested_slot: u64, slots_per_period: u64) -> Vec<[u8; 4]> {
    let spe = schedule.slots_per_epoch();
    let first_epoch = attested_slot / spe;
    let last_epoch = ((attested_slot / slots_per_period + 1) * slots_per_period - 1) / spe;
    let mut out = vec![schedule.version_at_epoch(first_epoch)];
    for (activation, version) in schedule.forks() {
        if *activation > first_epoch && *activation <= last_epoch && !out.contains(version) {
            out.push(*version);
        }
    }
    out
}

/// Verify an SP1 v6 Groth16 proof of [`PROGRAM_VKEY_HASH`] over
/// `public_values`. `Ok(false)` for a well-formed proof that does not verify,
/// `Err` for one that is malformed (so no other domain needs trying).
pub fn verify_sp1_groth16(proof: &[u8; PROOF_LEN], public_values: &[u8]) -> Result<bool, ZkReject> {
    // The guest must have halted cleanly, inside SP1 v6's recursion VK set:
    // both are folded into the pairing below, so without pinning them a proof
    // of a panicking guest, or of one under an attacker's recursion VKs, would
    // verify.
    if proof[..4] != SP1_VERIFIER_SELECTOR {
        return Err(ZkReject::BadProofHeader);
    }
    if proof[OFF_EXIT_CODE..OFF_EXIT_CODE + 32].iter().any(|b| *b != 0) {
        return Err(ZkReject::BadProofHeader);
    }
    if proof[OFF_VK_ROOT..OFF_VK_ROOT + 32] != SP1_VK_ROOT {
        return Err(ZkReject::BadProofHeader);
    }

    let a = g1_proof_point(&proof[OFF_A..OFF_A + 64])?;
    let b = g2_proof_point(&proof[OFF_B..OFF_B + 128])?;
    let c = g1_proof_point(&proof[OFF_C..OFF_C + 64])?;

    // SP1 hashes the public values with SHA-256 and clears the top three bits
    // to land in the 253-bit scalar field.
    let mut digest: [u8; 32] = Sha256::digest(public_values).into();
    digest[0] &= 0x1f;
    let inputs = [
        fr_canonical(&PROGRAM_VKEY_HASH)?,
        fr_canonical(&digest)?,
        fr_canonical(proof[OFF_EXIT_CODE..OFF_EXIT_CODE + 32].try_into().unwrap())?,
        fr_canonical(&SP1_VK_ROOT)?,
        fr_canonical(proof[OFF_NONCE..OFF_NONCE + 32].try_into().unwrap())?,
    ];

    let ic: Vec<G1Affine> = vk::IC.iter().map(g1_const).collect();
    let mut l: G1Projective = ic[0].into_group();
    for (base, scalar) in ic[1..].iter().zip(inputs.iter()) {
        if !scalar.is_zero() {
            l += *base * *scalar;
        }
    }

    let g1 = [a, c, g1_const(&vk::ALPHA), l.into_affine()];
    let g2 = [b, g2_const(&vk::DELTA_NEG), g2_const(&vk::BETA_NEG), g2_const(&vk::GAMMA_NEG)];
    Ok(Bn254::multi_pairing(g1, g2).is_zero())
}

// --- encodings -------------------------------------------------------------

/// A field element from 32 big-endian bytes, `None` unless it is canonical
/// (< the modulus).
fn fq_canonical(be: &[u8]) -> Option<Fq> {
    Fq::from_bigint(bigint_be(be))
}

fn fr_canonical(be: &[u8; 32]) -> Result<Fr, ZkReject> {
    Fr::from_bigint(bigint_be(be)).ok_or(ZkReject::BadEncoding)
}

fn bigint_be(be: &[u8]) -> BigInt<4> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in be.rchunks_exact(8).enumerate().take(4) {
        limbs[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    BigInt::new(limbs)
}

/// A G1 proof point: canonical coordinates, on the curve (BN254 G1 has
/// cofactor 1, so that is the subgroup), not the identity.
fn g1_proof_point(b: &[u8]) -> Result<G1Affine, ZkReject> {
    let x = fq_canonical(&b[0..32]).ok_or(ZkReject::BadEncoding)?;
    let y = fq_canonical(&b[32..64]).ok_or(ZkReject::BadEncoding)?;
    let p = G1Affine::new_unchecked(x, y);
    if p.is_zero() || !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkReject::BadEncoding);
    }
    Ok(p)
}

/// A G2 proof point in EIP-197 order (x.c1, x.c0, y.c1, y.c0): canonical, on
/// the twist, AND in the prime-order subgroup — the twist has a large cofactor,
/// so the subgroup check is what keeps a small-order point out of the pairing.
fn g2_proof_point(b: &[u8]) -> Result<G2Affine, ZkReject> {
    let f = |o: usize| fq_canonical(&b[o..o + 32]).ok_or(ZkReject::BadEncoding);
    let x = Fq2::new(f(32)?, f(0)?);
    let y = Fq2::new(f(96)?, f(64)?);
    let p = G2Affine::new_unchecked(x, y);
    if p.is_zero() || !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkReject::BadEncoding);
    }
    Ok(p)
}

/// A pinned G1 constant. Checked once by the `vk_points_are_valid` test; a
/// non-canonical constant would be a build error, never a runtime input.
fn g1_const(p: &[[u8; 32]; 2]) -> G1Affine {
    G1Affine::new_unchecked(
        fq_canonical(&p[0]).expect("pinned VK coordinate"),
        fq_canonical(&p[1]).expect("pinned VK coordinate"),
    )
}

/// A pinned G2 constant in (x.c0, x.c1, y.c0, y.c1) order.
fn g2_const(p: &[[u8; 32]; 4]) -> G2Affine {
    let f = |i: usize| fq_canonical(&p[i]).expect("pinned VK coordinate");
    G2Affine::new_unchecked(Fq2::new(f(0), f(1)), Fq2::new(f(2), f(3)))
}

/// 64 hex digits → 32 bytes, at compile time.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex32 needs 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vk_points_are_valid() {
        for p in vk::IC.iter().chain(core::iter::once(&vk::ALPHA)) {
            let g = g1_const(p);
            assert!(g.is_on_curve() && !g.is_zero());
        }
        for p in [&vk::BETA_NEG, &vk::GAMMA_NEG, &vk::DELTA_NEG] {
            let g = g2_const(p);
            assert!(g.is_on_curve() && g.is_in_correct_subgroup_assuming_on_curve() && !g.is_zero());
        }
        // gamma is the G2 generator in every gnark Groth16 key: -gamma's x is the
        // generator's x, which pins the coordinate order these constants use.
        assert_eq!(g2_const(&vk::GAMMA_NEG), -G2Affine::generator());
    }

    #[test]
    fn hex32_decodes() {
        assert_eq!(hex32("00ff0000000000000000000000000000000000000000000000000000000000a1")[1], 0xff);
        assert_eq!(hex32("00ff0000000000000000000000000000000000000000000000000000000000a1")[31], 0xa1);
    }

    #[test]
    fn non_canonical_scalars_are_refused() {
        assert!(fr_canonical(&[0xff; 32]).is_err());
        assert!(fq_canonical(&[0xff; 32]).is_none());
    }

    #[test]
    fn signing_versions_cover_a_fork_inside_the_period() {
        let schedule = ForkSchedule::new(32, &[(0, [0, 0, 0, 0]), (300, [5, 0, 0, 0])]);
        // Attested at epoch 10, period 0 ends at epoch 255: only genesis.
        assert_eq!(signing_versions(&schedule, 320, 8192), vec![[0, 0, 0, 0]]);
        // Attested in period 1 (epochs 256..511) before the fork at 300: both.
        assert_eq!(
            signing_versions(&schedule, 256 * 32 + 1, 8192),
            vec![[0, 0, 0, 0], [5, 0, 0, 0]]
        );
        // After it: just the new one.
        assert_eq!(signing_versions(&schedule, 301 * 32, 8192), vec![[5, 0, 0, 0]]);
    }
}
