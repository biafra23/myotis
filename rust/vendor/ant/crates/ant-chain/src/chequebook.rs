//! SWAP / chequebook primitives — Phase 7 of M3.
//!
//! Bee's payments-above-the-pseudosettle threshold flow uses a
//! per-node *chequebook contract* on Gnosis. Each node owns its own
//! chequebook; cheques are off-chain EIP-712-signed promises of a
//! cumulative payout that the beneficiary can later cash on-chain via
//! the chequebook's `cashChequeBeneficiary(recipient, amount, sig)`
//! method.
//!
//! This module provides everything needed to **issue** a cheque
//! correctly today, **verify** an inbound cheque, and **build the
//! calldata** for chequebook deployment and on-chain cashing. It does
//! not implement:
//!
//! - The libp2p `/swap/1.0.0/swap` protocol — the wire that ships
//!   cheques between peers. That belongs in `ant-p2p`.
//! - Automatic settlement triggered by the per-peer accounting
//!   crossing `payment_threshold`. That requires a swap driver
//!   bolted onto the existing [`crate::accounting`] surface.
//!
//! The library here is the *protocol-correctness* layer: cheques
//! signed with [`sign_cheque`] are byte-identical to what bee's
//! `pkg/settlement/swap/chequebook.Cheque.Sign` produces, so the
//! moment we wire up the swap protocol the first cheque we ship
//! will be accepted by a vanilla bee node.

use ant_crypto::{
    ethereum_address_from_public_key, recover_public_key_from_prehash, sign_prehash, CryptoError,
    SECP256K1_SECRET_LEN,
};
use primitive_types::U256;
use sha3::{Digest, Keccak256};

/// EIP-712 type hash for `Cheque(address chequebook,address beneficiary,uint256 cumulativePayout)`.
///
/// Mirrors the constant bee hardcodes in
/// `pkg/settlement/swap/chequebook/cheque.go`. Recomputed here so the
/// test suite verifies our keccak path matches.
#[must_use]
pub fn cheque_type_hash() -> [u8; 32] {
    keccak(b"Cheque(address chequebook,address beneficiary,uint256 cumulativePayout)")
}

/// EIP-712 type hash for the `EIP712Domain(string name,string version,uint256 chainId)`
/// domain bee uses on the chequebook contract.
///
/// Note: bee's chequebook domain deliberately omits `verifyingContract`
/// — see `pkg/crypto/eip712/EIP712DomainType` in the bee source.
/// The chequebook address still binds the digest, but via the
/// `Cheque.chequebook` field in the struct hash, not via the domain
/// separator. Adding a `verifyingContract` here produces a digest
/// that bee's `cashChequeBeneficiary` view rejects with
/// `invalid issuer signature`.
#[must_use]
pub fn eip712_domain_type_hash() -> [u8; 32] {
    keccak(b"EIP712Domain(string name,string version,uint256 chainId)")
}

/// Domain name + version bee writes into the chequebook EIP-712 domain.
/// Hard-coded both ways so a typo on either end of the wire doesn't
/// silently produce mismatched signatures.
pub const CHEQUEBOOK_DOMAIN_NAME: &str = "Chequebook";
pub const CHEQUEBOOK_DOMAIN_VERSION: &str = "1.0";

/// Struct bee shipping back and forth on the swap protocol. Distinct
/// from a `SignedCheque` because the issuer assembles this payload,
/// signs it, then ships `(payload, sig)` together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cheque {
    /// The issuing chequebook contract — payee redeems `cashChequeBeneficiary`
    /// against this address.
    pub chequebook: [u8; 20],
    /// Beneficiary's Ethereum address (their node's overlay key).
    pub beneficiary: [u8; 20],
    /// Cumulative amount the issuer has now committed to the
    /// beneficiary across all cheques. Bee uses cumulative (rather
    /// than per-cheque) values so a lost cheque can be re-derived
    /// from the next one and the chequebook contract just pays out
    /// the diff.
    pub cumulative_payout: U256,
}

/// `Cheque + 65-byte (r ‖ s ‖ v)` signature, as carried on the swap
/// wire. `v` is in `27..=30`, matching `ant_crypto::sign_prehash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheque {
    pub cheque: Cheque,
    pub signature: [u8; 65],
}

/// Compute the EIP-712 digest a chequebook signer will sign.
///
/// `chain_id` is the chain the chequebook contract lives on (100 for
/// Gnosis). The chequebook address is *not* part of the domain
/// separator — it enters the digest through the `Cheque.chequebook`
/// field of the struct hash. See [`eip712_domain_type_hash`].
#[must_use]
pub fn cheque_digest(cheque: &Cheque, chain_id: u64) -> [u8; 32] {
    let domain_sep = eip712_domain_separator(chain_id);
    let struct_hash = cheque_struct_hash(cheque);
    let mut h = Keccak256::default();
    h.update([0x19, 0x01]);
    h.update(domain_sep);
    h.update(struct_hash);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Sign a cheque with the issuing wallet's secret. Returns the
/// 65-byte signature plus the signed digest (handy for the verifier
/// that wants to log it).
pub fn sign_cheque(
    secret: &[u8; SECP256K1_SECRET_LEN],
    cheque: &Cheque,
    chain_id: u64,
) -> Result<SignedCheque, CryptoError> {
    let digest = cheque_digest(cheque, chain_id);
    let signature = sign_prehash(secret, &digest)?;
    Ok(SignedCheque {
        cheque: cheque.clone(),
        signature,
    })
}

/// Recover the issuing chequebook's owner address from a signed
/// cheque. Caller must independently look up the chequebook's
/// `issuer()` on-chain to confirm the recovered address really is
/// authorised to issue cheques against this chequebook.
pub fn recover_cheque_signer(
    signed: &SignedCheque,
    chain_id: u64,
) -> Result<[u8; 20], CryptoError> {
    let digest = cheque_digest(&signed.cheque, chain_id);
    let vk = recover_public_key_from_prehash(&signed.signature, &digest)?;
    Ok(ethereum_address_from_public_key(&vk))
}

fn eip712_domain_separator(chain_id: u64) -> [u8; 32] {
    let mut h = Keccak256::default();
    h.update(eip712_domain_type_hash());
    h.update(keccak(CHEQUEBOOK_DOMAIN_NAME.as_bytes()));
    h.update(keccak(CHEQUEBOOK_DOMAIN_VERSION.as_bytes()));
    h.update(u256_be_word(&U256::from(chain_id)));
    let out = h.finalize();
    let mut sep = [0u8; 32];
    sep.copy_from_slice(&out);
    sep
}

fn cheque_struct_hash(cheque: &Cheque) -> [u8; 32] {
    let mut h = Keccak256::default();
    h.update(cheque_type_hash());
    h.update(pad_word_address(&cheque.chequebook));
    h.update(pad_word_address(&cheque.beneficiary));
    h.update(u256_be_word(&cheque.cumulative_payout));
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

// --- ABI calldata builders ---

/// `SimpleSwapFactory.deploySimpleSwap(address issuer, uint256 defaultHardDepositTimeoutDuration, bytes32 salt)`
/// — the bee chequebook factory's deploy entrypoint.
#[must_use]
pub fn deploy_chequebook_calldata(
    issuer: &[u8; 20],
    default_hard_deposit_timeout: U256,
    salt: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 3);
    data.extend_from_slice(&keccak(b"deploySimpleSwap(address,uint256,bytes32)")[0..4]);
    data.extend_from_slice(&pad_word_address(issuer));
    data.extend_from_slice(&u256_be_word(&default_hard_deposit_timeout));
    data.extend_from_slice(salt);
    data
}

/// `Chequebook.cashChequeBeneficiary(address recipient, uint256 cumulativePayout, bytes signature)`.
///
/// `recipient` is whoever should receive the BZZ — usually the
/// beneficiary themselves, but bee allows redirecting to a custodial
/// address. `signature` is the 65-byte EIP-712 cheque signature
/// produced by [`sign_cheque`].
#[must_use]
pub fn cash_cheque_beneficiary_calldata(
    recipient: &[u8; 20],
    cumulative_payout: U256,
    signature: &[u8; 65],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 5);
    data.extend_from_slice(&keccak(b"cashChequeBeneficiary(address,uint256,bytes)")[0..4]);
    data.extend_from_slice(&pad_word_address(recipient));
    data.extend_from_slice(&u256_be_word(&cumulative_payout));
    // dynamic-bytes ABI: offset (always 0x60 here, three 32-byte words
    // before the bytes blob), length, then padded payload.
    let offset = U256::from(3u64 * 32);
    data.extend_from_slice(&u256_be_word(&offset));
    let sig_len = U256::from(signature.len() as u64);
    data.extend_from_slice(&u256_be_word(&sig_len));
    data.extend_from_slice(signature);
    // Pad the signature blob to the next 32-byte boundary (it's 65,
    // so we pad 31 bytes).
    data.extend(std::iter::repeat_n(0u8, 32 - signature.len() % 32));
    data
}

/// `Chequebook.issuer()` selector for read-only verification that
/// the recovered cheque signer actually controls the chequebook.
#[must_use]
pub fn chequebook_issuer_selector() -> [u8; 4] {
    let h = keccak(b"issuer()");
    [h[0], h[1], h[2], h[3]]
}

/// `Chequebook.totalPaidOut()` selector — the cumulative amount
/// already cashed by **all** beneficiaries combined. Subtract from
/// `totalbalance()` to learn how much BZZ the chequebook still has on
/// its books to honour outstanding cheques.
///
/// (Bee's chequebook contract does *not* have a `totalIssued()` view
/// — issuance is purely an off-chain accounting concept; the contract
/// only sees what's been cashed.)
#[must_use]
pub fn chequebook_total_paid_out_selector() -> [u8; 4] {
    let h = keccak(b"totalPaidOut()");
    [h[0], h[1], h[2], h[3]]
}

/// `Chequebook.balance()` selector — full BZZ holdings of the
/// chequebook contract, equivalent to `BZZ.balanceOf(chequebook)`.
/// `liquidBalance()` is what's available *right now* (i.e. after
/// subtracting any pending hard deposits) — prefer `liquidBalance()`
/// when checking that a cheque can actually be cashed.
#[must_use]
pub fn chequebook_balance_selector() -> [u8; 4] {
    let h = keccak(b"balance()");
    [h[0], h[1], h[2], h[3]]
}

/// Bee's SWAP price oracle on Gnosis mainnet
/// (`pkg/config/chain.go`, `SwapPriceOracleAddress`). Its `getPrice()`
/// returns the exchange rate (PLUR per accounting unit) and the one-off
/// deduction (PLUR) every bee node uses to price a cheque, and sends in
/// its swap response headers.
pub const GNOSIS_SWAP_PRICE_ORACLE: [u8; 20] = [
    0xa5, 0x7a, 0x50, 0xa8, 0x31, 0xb3, 0x1c, 0x90, 0x4a, 0x77, 0x0e, 0xdb, 0xcb, 0x70, 0x6e, 0x03,
    0xaf, 0xcd, 0xbd, 0x94,
];

/// `PriceOracle.getPrice()` selector: `(uint256 price, uint256 deduction)`.
#[must_use]
pub fn price_oracle_get_price_selector() -> [u8; 4] {
    let h = keccak(b"getPrice()");
    [h[0], h[1], h[2], h[3]]
}

/// `Chequebook.chequeHash(address chequebook, address beneficiary, uint256 cumulativePayout)`
/// view — recomputes the EIP-712 digest exactly the way the contract
/// does internally before recovering the issuer in
/// `cashChequeBeneficiary`. `eth_call` this and compare to
/// [`cheque_digest`] to debug any signature-rejection: a mismatch
/// proves our digest is wrong, a match proves the bug is on the
/// signature side (recid byte, secret key wrong, etc.).
#[must_use]
pub fn chequebook_cheque_hash_calldata(
    chequebook: &[u8; 20],
    beneficiary: &[u8; 20],
    cumulative_payout: U256,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 3);
    data.extend_from_slice(&keccak(b"chequeHash(address,address,uint256)")[0..4]);
    data.extend_from_slice(&pad_word_address(chequebook));
    data.extend_from_slice(&pad_word_address(beneficiary));
    data.extend_from_slice(&u256_be_word(&cumulative_payout));
    data
}

/// `Chequebook.paidOut(address beneficiary)` selector — how much of
/// the cumulative payout for `beneficiary` has already been cashed.
/// Subtract from `cheque.cumulative_payout` to learn how much BZZ
/// the cheque is worth right now.
#[must_use]
pub fn chequebook_paid_out_selector() -> [u8; 4] {
    let h = keccak(b"paidOut(address)");
    [h[0], h[1], h[2], h[3]]
}

/// `Chequebook.liquidBalance()` selector — BZZ available to pay out
/// right now (`balance` minus the sum of all open hard deposits).
/// `cashChequeBeneficiary` reverts with `liquid balance not
/// sufficient` when the requested cheque diff exceeds this.
#[must_use]
pub fn chequebook_liquid_balance_selector() -> [u8; 4] {
    let h = keccak(b"liquidBalance()");
    [h[0], h[1], h[2], h[3]]
}

/// `SimpleSwap.withdraw(uint256 amount)` calldata: move `amount` xBZZ
/// (PLUR) out of the chequebook back to its issuer. The contract only
/// lets the issuer call it, and reverts above `liquidBalance()`. Nothing
/// stops it withdrawing funds that back cheques already issued but not
/// yet cashed (the chain doesn't know about those), so callers cap the
/// amount themselves; see
/// [`crate::chequebook_store::withdraw_from_chequebook`].
#[must_use]
pub fn chequebook_withdraw_calldata(amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&keccak(b"withdraw(uint256)")[0..4]);
    data.extend_from_slice(&u256_be_word(&amount));
    data
}

/// Encode a `paidOut(beneficiary)` call's full calldata.
#[must_use]
pub fn chequebook_paid_out_calldata(beneficiary: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&chequebook_paid_out_selector());
    data.extend_from_slice(&pad_word_address(beneficiary));
    data
}

// --- SimpleSwapFactory ABI helpers ---

/// Mainnet (Gnosis chain) Swarm chequebook factory address —
/// `SimpleSwapFactory` at
/// <https://gnosisscan.io/address/0xC2d5A532cf69AA9A1378737D8ccDEF884B6E7420>.
/// Bee's `chequeStore.ReceiveCheque` only accepts cheques drawn on
/// chequebooks where `factory.deployedContracts(chequebook) == true`,
/// so `antd` MUST deploy through this contract for its cheques to
/// be honoured by mainnet bee peers.
pub const GNOSIS_CHEQUEBOOK_FACTORY: [u8; 20] = [
    0xc2, 0xd5, 0xa5, 0x32, 0xcf, 0x69, 0xaa, 0x9a, 0x13, 0x78, 0x73, 0x7d, 0x8c, 0xcd, 0xef, 0x88,
    0x4b, 0x6e, 0x74, 0x20,
];

/// BZZ token contract address on Gnosis mainnet — the only ERC-20
/// the chequebook factory's deployed swaps will denominate
/// payouts in. We expose it as 20 raw bytes (siblings of the
/// `0x...` `&'static str` `crate::GNOSIS_BZZ_TOKEN`) for the
/// deploy + funding paths to avoid round-tripping
/// `factory.ERC20Address()` for something that's effectively
/// constant on mainnet, while still allowing callers to verify
/// against the factory if they want.
pub const GNOSIS_BZZ_TOKEN_BYTES: [u8; 20] = [
    0xdb, 0xf3, 0xea, 0x6f, 0x5b, 0xee, 0x45, 0xc0, 0x22, 0x55, 0xb2, 0xc2, 0x6a, 0x16, 0xf3, 0x00,
    0x50, 0x2f, 0x68, 0xda,
];

/// Bee's hard-deposit timeout default, in seconds (24 h). Matches
/// `pkg/node/devnode.go::FactoryDefaultDepositTimeoutDuration` and
/// the value bee's own `chequebook.Init` uses when bootstrapping a
/// new node. Picked deliberately so a chequebook deployed by `antd`
/// looks indistinguishable from one deployed by bee itself.
pub const DEFAULT_HARD_DEPOSIT_TIMEOUT_SECS: u64 = 86_400;

/// Topic[0] of `SimpleSwapDeployed(address)`. Pinned as a literal
/// (not computed at runtime) so the tests below can fail loudly if
/// anyone ever changes the event signature in the factory ABI.
/// This exact value is verifiable by inspecting the runtime
/// bytecode at <https://gnosisscan.io/address/0xC2d5A532cf69AA9A1378737D8ccDEF884B6E7420#code>:
/// the literal appears as a `PUSH32` immediately preceding `LOG1`
/// at the end of `deploySimpleSwap`.
pub const SIMPLE_SWAP_DEPLOYED_TOPIC: [u8; 32] = [
    0xc0, 0xff, 0xc5, 0x25, 0xa1, 0xc7, 0x68, 0x95, 0x49, 0xd7, 0xf7, 0x9b, 0x49, 0xec, 0xa9, 0x00,
    0xe6, 0x1a, 0xc4, 0x9b, 0x43, 0xd9, 0x77, 0xf6, 0x80, 0xbc, 0xc3, 0xb3, 0x62, 0x24, 0xc0, 0x04,
];

/// Encode `SimpleSwapFactory.deployedContracts(address) -> bool`.
/// Returns 32 bytes; non-zero last byte means "deployed by us".
/// Used both by `antctl chequebook verify` and by the `antd`
/// startup factory check.
#[must_use]
pub fn factory_deployed_contracts_calldata(chequebook: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&keccak(b"deployedContracts(address)")[0..4]);
    data.extend_from_slice(&pad_word_address(chequebook));
    data
}

/// Encode `SimpleSwapFactory.ERC20Address() -> address`. Lets the
/// deploy path verify the factory was constructed for the BZZ
/// token we expect, before we sign any tx.
#[must_use]
pub fn factory_erc20_address_calldata() -> Vec<u8> {
    keccak(b"ERC20Address()")[0..4].to_vec()
}

/// Generate a random 32-byte CREATE2 salt for a chequebook
/// deploy. Bee picks a fresh salt on every deploy so a re-run
/// against the same `(issuer, default_hard_deposit_timeout)` pair
/// doesn't collide with an existing chequebook (CREATE2 +
/// identical args + identical salt → identical address). We do
/// the same.
#[must_use]
pub fn random_chequebook_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("OS RNG");
    salt
}

/// Decode a `SimpleSwapDeployed(address)` log emitted by the
/// factory in the same tx as a `deploySimpleSwap` call. The
/// parameter is non-indexed, so the address sits right-padded in
/// the first 32-byte word of `data`. Returns `None` if no matching
/// log is in the receipt — the deploy probably reverted partway
/// through, in which case the caller should dump the full receipt.
#[must_use]
pub fn extract_deployed_chequebook(receipt: &crate::tx::TxReceipt) -> Option<[u8; 20]> {
    receipt
        .logs
        .iter()
        .find(|l| l.topics.first() == Some(&SIMPLE_SWAP_DEPLOYED_TOPIC) && l.data.len() >= 32)
        .map(|l| {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&l.data[12..32]);
            addr
        })
}

fn pad_word_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(addr);
    w
}

fn u256_be_word(v: &U256) -> [u8; 32] {
    v.to_big_endian()
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let h = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::random_secp256k1_secret;
    use k256::ecdsa::SigningKey;

    /// Sign with a fresh key; the recovered signer must match the key's
    /// derived Ethereum address. Catches every off-by-one in the
    /// EIP-712 digest, the recid translation, and the signature shape.
    #[test]
    fn sign_then_recover_round_trip() {
        let secret = random_secp256k1_secret();
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let want_addr = ethereum_address_from_public_key(sk.verifying_key());

        let cheque = Cheque {
            chequebook: [0x11u8; 20],
            beneficiary: [0x22u8; 20],
            cumulative_payout: U256::from(1_000_000_000_000_000u64),
        };
        let signed = sign_cheque(&secret, &cheque, 100).unwrap();
        assert_eq!(signed.cheque, cheque);

        let recovered = recover_cheque_signer(&signed, 100).unwrap();
        assert_eq!(recovered, want_addr);
    }

    /// Different chequebook contract → different `Cheque.chequebook`
    /// field in the struct hash → different digest → recovered signer
    /// must change. Bee's chequebook EIP-712 domain deliberately
    /// omits `verifyingContract`, so the chequebook address binds the
    /// digest through the struct hash, not the domain separator.
    #[test]
    fn struct_hash_binds_chequebook_address() {
        let secret = random_secp256k1_secret();
        let cheque1 = Cheque {
            chequebook: [0x11u8; 20],
            beneficiary: [0x22u8; 20],
            cumulative_payout: U256::from(1u64),
        };
        let mut cheque2 = cheque1.clone();
        cheque2.chequebook = [0x33u8; 20];

        let d1 = cheque_digest(&cheque1, 100);
        let d2 = cheque_digest(&cheque2, 100);
        assert_ne!(d1, d2, "chequebook address must affect the digest");

        // Sanity: recovering the wrong chequebook's signature against
        // cheque1's digest must NOT yield the original signer.
        let signed1 = sign_cheque(&secret, &cheque1, 100).unwrap();
        let mut signed_with_swapped_meta = signed1.clone();
        signed_with_swapped_meta.cheque.chequebook = [0x33u8; 20];
        let recover1 = recover_cheque_signer(&signed1, 100).unwrap();
        let recover2 = recover_cheque_signer(&signed_with_swapped_meta, 100).unwrap();
        assert_ne!(recover1, recover2);
    }

    /// Different chain id changes the digest. Cross-chain replay
    /// protection.
    #[test]
    fn chain_id_binds_signature() {
        let cheque = Cheque {
            chequebook: [0x11u8; 20],
            beneficiary: [0x22u8; 20],
            cumulative_payout: U256::from(1u64),
        };
        assert_ne!(cheque_digest(&cheque, 1), cheque_digest(&cheque, 100));
    }

    /// Verify the canonical EIP-712 type hashes match keccak-derived
    /// values from a fresh computation. If bee changes the type
    /// strings these tests catch it immediately.
    #[test]
    fn eip712_type_hashes() {
        let cheque_th = cheque_type_hash();
        let domain_th = eip712_domain_type_hash();

        assert_eq!(
            hex::encode(cheque_th),
            hex::encode(keccak(
                b"Cheque(address chequebook,address beneficiary,uint256 cumulativePayout)"
            )),
        );
        // Bee's chequebook domain has only 3 fields — see
        // `pkg/crypto/eip712/EIP712DomainType` upstream.
        assert_eq!(
            hex::encode(domain_th),
            hex::encode(keccak(
                b"EIP712Domain(string name,string version,uint256 chainId)"
            )),
        );
    }

    /// `cashChequeBeneficiary` calldata layout: 4-byte selector + 5
    /// 32-byte words (recipient, payout, dyn-bytes offset = 0x60,
    /// length = 65, sig blob padded to 96 bytes).
    #[test]
    fn cash_cheque_calldata_layout() {
        let recipient = [0x11u8; 20];
        let payout = U256::from(123u64);
        let sig = [0xaau8; 65];
        let data = cash_cheque_beneficiary_calldata(&recipient, payout, &sig);
        // 4 + 3 fixed words + offset hop = 4 + 96 + 32 (length) + 96 (padded blob).
        assert_eq!(data.len(), 4 + 32 * 3 + 32 + 96);
        // Selector matches `cashChequeBeneficiary(address,uint256,bytes)`.
        let want_sel = &keccak(b"cashChequeBeneficiary(address,uint256,bytes)")[0..4];
        assert_eq!(&data[0..4], want_sel);
        // Dynamic-bytes offset word should be 0x60.
        let off_word = &data[4 + 32 * 2..4 + 32 * 3];
        let mut expected = [0u8; 32];
        expected[31] = 0x60;
        assert_eq!(off_word, &expected[..]);
    }

    /// `deploySimpleSwap(address,uint256,bytes32)` selector check.
    /// Bee's chequebook factory uses this exact signature on Gnosis.
    #[test]
    fn deploy_chequebook_selector() {
        let want = &keccak(b"deploySimpleSwap(address,uint256,bytes32)")[0..4];
        let calldata = deploy_chequebook_calldata(&[0u8; 20], U256::from(86400u64), &[0u8; 32]);
        assert_eq!(&calldata[0..4], want);
        assert_eq!(calldata.len(), 4 + 32 * 3);
    }

    /// Read-method selectors round-trip through keccak. Each
    /// selector matches a real public view on bee's mainnet
    /// chequebook contract — checked off-chain by inspecting bee's
    /// `pkg/settlement/swap/chequebook` ABI bindings.
    #[test]
    fn chequebook_read_selectors() {
        assert_eq!(
            chequebook_issuer_selector().to_vec(),
            keccak(b"issuer()")[0..4].to_vec()
        );
        assert_eq!(
            chequebook_total_paid_out_selector().to_vec(),
            keccak(b"totalPaidOut()")[0..4].to_vec()
        );
        assert_eq!(
            chequebook_balance_selector().to_vec(),
            keccak(b"balance()")[0..4].to_vec()
        );
        assert_eq!(
            chequebook_liquid_balance_selector().to_vec(),
            keccak(b"liquidBalance()")[0..4].to_vec()
        );
        assert_eq!(
            chequebook_paid_out_selector().to_vec(),
            keccak(b"paidOut(address)")[0..4].to_vec()
        );
    }

    /// `withdraw(uint256)` selector + ABI layout: the amount
    /// left-padded to one 32-byte word.
    #[test]
    fn withdraw_calldata_layout() {
        let data = chequebook_withdraw_calldata(U256::from(0x1234u64));
        assert_eq!(hex::encode(&data[..4]), "2e1a7d4d");
        assert_eq!(data.len(), 36);
        assert_eq!(&data[34..], &[0x12, 0x34]);
        assert!(data[4..34].iter().all(|&b| b == 0));
    }

    /// `deployedContracts(address)` selector + ABI layout. Used by
    /// the daemon startup factory check and `antctl chequebook
    /// verify`. If the selector is wrong the `eth_call` returns
    /// "execution reverted" with no useful info — guard against
    /// that with a unit test rather than an embarrassing prod boot.
    #[test]
    fn factory_deployed_contracts_selector() {
        let cb = [0x11u8; 20];
        let calldata = factory_deployed_contracts_calldata(&cb);
        let want_sel = &keccak(b"deployedContracts(address)")[0..4];
        assert_eq!(&calldata[0..4], want_sel);
        assert_eq!(calldata.len(), 4 + 32);
        // Address is right-padded to 32 bytes.
        assert_eq!(&calldata[4..16], &[0u8; 12][..]);
        assert_eq!(&calldata[16..36], &cb[..]);
    }

    #[test]
    fn factory_erc20_address_selector_matches() {
        let calldata = factory_erc20_address_calldata();
        assert_eq!(calldata.len(), 4);
        assert_eq!(&calldata[..], &keccak(b"ERC20Address()")[0..4]);
    }

    /// The literal we pinned for `SimpleSwapDeployed(address)` must
    /// equal keccak256 of the canonical event signature. If bee
    /// ever rev's the factory ABI this assertion catches it.
    #[test]
    fn simple_swap_deployed_topic_matches_keccak() {
        let want = keccak(b"SimpleSwapDeployed(address)");
        assert_eq!(SIMPLE_SWAP_DEPLOYED_TOPIC, want);
    }

    /// `extract_deployed_chequebook` pulls the right address out of a
    /// hand-crafted log mimicking the factory's emit.
    #[test]
    fn extract_deployed_chequebook_finds_address() {
        let cb = [0xab; 20];
        let mut data = vec![0u8; 32];
        data[12..32].copy_from_slice(&cb);
        let receipt = crate::tx::TxReceipt {
            tx_hash: [0u8; 32],
            block_number: 1,
            logs: vec![crate::tx::EventLog {
                address: GNOSIS_CHEQUEBOOK_FACTORY,
                topics: vec![SIMPLE_SWAP_DEPLOYED_TOPIC],
                data,
            }],
        };
        assert_eq!(extract_deployed_chequebook(&receipt), Some(cb));
    }

    /// Receipt without the factory's `SimpleSwapDeployed` log →
    /// `None`, so the caller can dump a useful error.
    #[test]
    fn extract_deployed_chequebook_none_without_topic() {
        let receipt = crate::tx::TxReceipt {
            tx_hash: [0u8; 32],
            block_number: 1,
            logs: vec![crate::tx::EventLog {
                address: [0u8; 20],
                topics: vec![[0xff; 32]],
                data: vec![0u8; 32],
            }],
        };
        assert_eq!(extract_deployed_chequebook(&receipt), None);
    }

    #[test]
    fn gnosis_factory_address_literal() {
        assert_eq!(
            hex::encode(GNOSIS_CHEQUEBOOK_FACTORY),
            "c2d5a532cf69aa9a1378737d8ccdef884b6e7420"
        );
    }

    #[test]
    fn gnosis_bzz_token_bytes_matches_string_const() {
        let s = crate::GNOSIS_BZZ_TOKEN.trim_start_matches("0x");
        let want = hex::decode(s).unwrap();
        assert_eq!(GNOSIS_BZZ_TOKEN_BYTES.to_vec(), want);
    }
}
