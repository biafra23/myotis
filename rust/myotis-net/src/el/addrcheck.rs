//! The per-entry check of an address-history candidate against verified chain data (part 6
//! of #899; `.claude/agent/data-sources.md`, the carve-out for Swarm reads of the address
//! index, "What it is trusted for").
//!
//! An entry of the addr1 index says: `address` appears in block `block`, at `slot` (0 for
//! the block itself, `txIndex + 1` for a transaction), with these roles. Each role is checked
//! against a block whose header, transactions and withdrawals are verified (the block read's
//! trust gate) and, where a role is about logs, against the block's verified receipts. The
//! rules are the index's detection rules (eth2swarm `docs/address-index.md`, "Detection
//! rules"), read as checks: a role is **confirmed** when the address is where the rule puts
//! it, **contradicted** when the data that would hold it is there and the address is not,
//! and **unchecked** when nothing verified can say (`TRACE`, an uncle's miner, a log role
//! without the receipts).
//!
//! The entry is *contradicted* if any role is, *verified* if at least one role is confirmed
//! and none contradicted, else *unverified*. Pure: the caller fetches.

use myotis_core::keccak::keccak256;
use myotis_core::rlp;

use crate::el::reader::{VerifiedBlock, VerifiedReceipt};

/// The role bits (eth2swarm `docs/address-index.md`, Appearances).
pub mod role {
    pub const FROM: u8 = 0x01;
    pub const TO: u8 = 0x02;
    pub const EMITTER: u8 = 0x04;
    pub const TOPIC: u8 = 0x08;
    pub const WORD: u8 = 0x10;
    pub const TRACE: u8 = 0x20;
    pub const BLOCK: u8 = 0x40;
    pub const AUTH: u8 = 0x80;
    /// The roles only a block's receipts can confirm (log ones; `WORD` partly).
    pub const NEEDS_RECEIPTS: u8 = EMITTER | TOPIC | WORD;
}

/// What the check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Verified,
    Contradicted,
    Unverified,
}

/// The check of one entry: its state and, per role bit, what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub state: State,
    pub confirmed: u8,
    pub contradicted: u8,
    pub unchecked: u8,
    /// For a transaction entry: the transaction's hash, from the verified body.
    pub tx_hash: Option<[u8; 32]>,
    pub from: Option<[u8; 20]>,
    /// `None` for a contract creation.
    pub to: Option<[u8; 20]>,
    /// Minimal big-endian wei.
    pub value: Vec<u8>,
    /// The first ERC-20/721 `Transfer` log the address is a party of, if any.
    pub transfer: Option<Transfer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub token: [u8; 20],
    pub from: [u8; 20],
    pub to: [u8; 20],
    /// The log's data: the amount (ERC-20) — empty for ERC-721, whose id is a topic.
    pub data: Vec<u8>,
}

/// keccak256("Transfer(address,address,uint256)").
const TRANSFER: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// secp256k1's group order `n` and `n / 2`, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// keccak256 of the empty RLP list: the `ommersHash` of a block without uncles.
const EMPTY_OMMERS: [u8; 32] = crate::el::eth::messages::EMPTY_OMMERS_HASH;

fn padded(address: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

/// The 32-byte windows of `data` from `offset`, those that fit completely.
fn words(data: &[u8], offset: usize) -> impl Iterator<Item = &[u8; 32]> {
    data.get(offset..).unwrap_or(&[]).as_chunks::<32>().0.iter()
}

fn left_pad32(b: &[u8]) -> Option<[u8; 32]> {
    let b = &b[b.iter().take_while(|x| **x == 0).count()..];
    if b.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Some(out)
}

/// The authorities and code addresses of a type-4 transaction's authorization list, with the
/// index's rule for which entries count: `y_parity ∈ {0, 1}`, `0 < r < n`, `0 < s ≤ n/2` and a
/// recoverable authority of `keccak256(0x05 ‖ rlp([chain_id, address, nonce]))`. Code
/// addresses count whatever the entry's validity (the `WORD` rule). Empty for other types.
pub fn authorizations(raw_tx: &[u8]) -> (Vec<[u8; 20]>, Vec<[u8; 20]>) {
    let (mut authorities, mut code) = (Vec::new(), Vec::new());
    if raw_tx.first() != Some(&0x04) {
        return (authorities, code);
    }
    let Ok(fields) = rlp::raw_list_items(&raw_tx[1..]) else {
        return (authorities, code);
    };
    let Some(list) = fields.get(9) else {
        return (authorities, code);
    };
    let Ok(entries) = rlp::raw_list_items(list) else {
        return (authorities, code);
    };
    for entry in entries {
        let Ok(items) = rlp::raw_list_items(entry) else { continue };
        let Ok(decoded) = rlp::decode(entry) else { continue };
        let Ok(parts) = decoded.as_list() else { continue };
        if parts.len() != 6 || items.len() != 6 {
            continue;
        }
        let Ok(address) = parts[1].as_fixed_bytes(20) else { continue };
        let address: [u8; 20] = address.try_into().expect("20");
        code.push(address);
        let (Ok(y), Ok(r), Ok(s)) = (parts[3].as_u64(), parts[4].as_bytes(), parts[5].as_bytes()) else {
            continue;
        };
        let (Some(r), Some(s)) = (left_pad32(r), left_pad32(s)) else { continue };
        let zero = [0u8; 32];
        if y > 1 || r == zero || r >= N || s == zero || s > HALF_N {
            continue;
        }
        let signed = rlp::encode_list_payload(&[items[0], items[1], items[2]].concat());
        let hash = keccak256(&[&[0x05u8][..], &signed].concat());
        let mut sig = [0u8; 65];
        sig[..32].copy_from_slice(&r);
        sig[32..64].copy_from_slice(&s);
        sig[64] = y as u8;
        if let Ok(public) = myotis_core::nodekey::recover_public_key(&hash, &sig) {
            authorities.push(keccak256(&public)[12..].try_into().expect("20"));
        }
    }
    (authorities, code)
}

/// The address a creation by `sender` at `nonce` deploys: `keccak256(rlp([sender, nonce]))`.
fn created_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let payload = [rlp::encode_bytes(sender), rlp::encode_bytes(&rlp::u64_to_minimal_be(nonce))].concat();
    keccak256(&rlp::encode_list_payload(&payload))[12..].try_into().expect("20")
}

/// Check one entry. `receipts` are the block's verified receipts, `None` when they were not
/// fetched (the log roles then stay unchecked).
pub fn check(
    address: &[u8; 20],
    slot: u32,
    roles: u8,
    block: &VerifiedBlock,
    receipts: Option<&[VerifiedReceipt]>,
) -> Check {
    let mut c = Check {
        state: State::Unverified,
        confirmed: 0,
        contradicted: 0,
        unchecked: roles & role::TRACE,
        tx_hash: None,
        from: None,
        to: None,
        value: Vec::new(),
        transfer: None,
    };
    let me = padded(address);
    let mark = |c: &mut Check, bit: u8, outcome: Option<bool>| {
        if roles & bit == 0 {
            return;
        }
        match outcome {
            Some(true) => c.confirmed |= bit,
            Some(false) => c.contradicted |= bit,
            None => c.unchecked |= bit,
        }
    };
    if slot == 0 {
        // Block-level: only BLOCK (and TRACE's reward author, unchecked) live here.
        let beneficiary = block.header.beneficiary.as_slice() == address.as_slice();
        let withdrawal = block.withdrawals.as_ref().is_some_and(|w| {
            w.iter().any(|item| {
                rlp::decode(item)
                    .ok()
                    .and_then(|v| v.as_list().ok().and_then(|f| f.get(2).and_then(|a| a.as_fixed_bytes(20).ok().map(|a| a == address))))
                    .unwrap_or(false)
            })
        });
        let has_uncles = block.header.ommers_hash != EMPTY_OMMERS;
        let outcome = if beneficiary || withdrawal {
            Some(true)
        } else if has_uncles {
            None // an uncle's miner: its header is not kept
        } else {
            Some(false)
        };
        mark(&mut c, role::BLOCK, outcome);
        for bit in [role::FROM, role::TO, role::EMITTER, role::TOPIC, role::WORD, role::AUTH] {
            mark(&mut c, bit, Some(false));
        }
        return finish(c);
    }
    let index = slot as usize - 1;
    let Some(raw) = block.raw_transactions.iter().nth(index) else {
        // No such transaction in the verified body: every role is contradicted.
        for bit in [role::FROM, role::TO, role::EMITTER, role::TOPIC, role::WORD, role::AUTH, role::BLOCK] {
            mark(&mut c, bit, Some(false));
        }
        return finish(c);
    };
    c.tx_hash = block.tx_hashes.get(index).copied();
    let summary = crate::el::tx::decode_summary(raw);
    let receipt = receipts.and_then(|r| r.get(index));
    if let Some(s) = &summary {
        c.from = s.from;
        c.to = s.to;
        c.value = s.value.clone();
    }
    let (authorities, code) = authorizations(raw);
    // FROM: the sender (unchecked if the signature does not recover).
    mark(&mut c, role::FROM, summary.as_ref().and_then(|s| s.from).map(|f| &f == address));
    // TO: the recipient, or the address a creation deploys.
    let to = summary.as_ref().and_then(|s| match (s.to, s.from) {
        (Some(to), _) => Some(to == *address),
        (None, Some(from)) => Some(created_address(&from, s.nonce) == *address),
        (None, None) => None,
    });
    mark(&mut c, role::TO, to);
    // AUTH: an authority of the authorization list.
    mark(&mut c, role::AUTH, Some(authorities.contains(address)));
    // BLOCK is never a transaction's role.
    mark(&mut c, role::BLOCK, Some(false));
    let logs = receipt.map(|r| r.receipt.logs.as_slice());
    // EMITTER and TOPIC need the logs.
    mark(&mut c, role::EMITTER, logs.map(|l| l.iter().any(|log| log.address.as_slice() == address.as_slice())));
    mark(&mut c, role::TOPIC, logs.map(|l| l.iter().any(|log| log.topics.iter().any(|t| t.as_slice() == me))));
    // WORD: the input's words after the selector, a 7702 code address, or a log's data word.
    let in_tx = summary.as_ref().is_some_and(|s| words(&s.input, 4).any(|w| *w == me)) || code.contains(address);
    let word = if in_tx {
        Some(true)
    } else {
        logs.map(|l| l.iter().any(|log| words(&log.data, 0).any(|w| *w == me)))
    };
    mark(&mut c, role::WORD, word);
    // The token transfer the row shows, if any.
    if let Some(l) = logs {
        c.transfer = l.iter().find_map(|log| {
            let (t0, t1, t2) = (log.topics.first()?, log.topics.get(1)?, log.topics.get(2)?);
            if t0.as_slice() != TRANSFER || (t1.as_slice() != me && t2.as_slice() != me) {
                return None;
            }
            let addr = |w: &[u8]| -> Option<[u8; 20]> { w.get(12..32)?.try_into().ok() };
            Some(Transfer {
                token: log.address.as_slice().try_into().ok()?,
                from: addr(t1)?,
                to: addr(t2)?,
                data: log.data.clone(),
            })
        });
    }
    finish(c)
}

fn finish(mut c: Check) -> Check {
    c.state = if c.contradicted != 0 {
        State::Contradicted
    } else if c.confirmed != 0 {
        State::Verified
    } else {
        State::Unverified
    };
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::el::eth::messages::RawList;
    use crate::el::receipt::{DecodedReceipt, ReceiptLog};
    use myotis_core::header::BlockHeader;

    fn legacy_tx(to: &[u8; 20], input: &[u8], nonce: u64, key: &myotis_core::nodekey::NodeKey) -> Vec<u8> {
        // An EIP-155 legacy transaction on chain 1, signed by `key`.
        let enc = |b: &[u8]| rlp::encode_bytes(b);
        let n = |x: u64| enc(&rlp::u64_to_minimal_be(x));
        let fields = |v: &[u8], r: &[u8], s: &[u8]| {
            [n(nonce), n(1_000_000_000), n(21_000), enc(to), n(5), enc(input), enc(v), enc(r), enc(s)].concat()
        };
        let unsigned = rlp::encode_list_payload(&fields(&[1], &[], &[]));
        let sig = key.sign_hash(&keccak256(&unsigned)).unwrap();
        let v = 37 + sig[64] as u64; // chain 1: 35 + 2·1 + recid
        let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
        rlp::encode_list_payload(&fields(&rlp::u64_to_minimal_be(v), &strip(&sig[..32]), &strip(&sig[32..64])))
    }

    fn block_with(txs: &[Vec<u8>], beneficiary: [u8; 20]) -> VerifiedBlock {
        let mut raw = RawList::new();
        for t in txs {
            raw.push(t);
        }
        VerifiedBlock {
            hash: [1; 32],
            header: BlockHeader {
                number: 100,
                beneficiary: beneficiary.to_vec(),
                ommers_hash: EMPTY_OMMERS,
                ..Default::default()
            },
            tx_hashes: txs.iter().map(|t| keccak256(t)).collect(),
            full_transactions: None,
            raw_transactions: raw,
            withdrawals: None,
        }
    }

    fn receipt_with(logs: Vec<ReceiptLog>) -> VerifiedReceipt {
        VerifiedReceipt {
            tx_hash: [0; 32],
            tx_index: 0,
            block_hash: [1; 32],
            block_number: 100,
            gas_used: 21_000,
            log_index_base: 0,
            receipt: DecodedReceipt {
                ty: 0,
                has_status: true,
                success: true,
                cumulative_gas_used: 21_000,
                logs_bloom: vec![0; 256],
                logs,
            },
            tx: None,
            effective_gas_price: None,
            contract_address: None,
        }
    }

    #[test]
    fn transaction_roles_are_confirmed_or_contradicted() {
        let key = myotis_core::nodekey::NodeKey::from_secret_bytes(&[7u8; 32]).unwrap();
        let sender: [u8; 20] = keccak256(&key.public_key_bytes())[12..].try_into().unwrap();
        let to = [0x22u8; 20];
        let other = [0x33u8; 20];
        // Input: a selector, then `other` as a word.
        let input = [&[0xa9, 0x05, 0x9c, 0xbb][..], &padded(&other)].concat();
        let tx = legacy_tx(&to, &input, 3, &key);
        let block = block_with(&[tx], [0x44; 20]);
        let transfer = ReceiptLog {
            address: vec![0x55; 20],
            topics: vec![TRANSFER.to_vec(), padded(&sender).to_vec(), padded(&other).to_vec()],
            data: vec![0, 1],
        };
        let receipts = vec![receipt_with(vec![transfer])];

        let c = check(&sender, 1, role::FROM | role::TOPIC, &block, Some(&receipts));
        assert_eq!((c.state, c.confirmed), (State::Verified, role::FROM | role::TOPIC));
        assert_eq!(c.from, Some(sender));
        assert_eq!(c.tx_hash, Some(block.tx_hashes[0]));
        assert_eq!(c.transfer.as_ref().map(|t| (t.token, t.from, t.to)), Some(([0x55; 20], sender, other)));

        let c = check(&to, 1, role::TO, &block, None);
        assert_eq!(c.state, State::Verified);
        // `other` is an input word and a Transfer topic, and emitted nothing.
        let c = check(&other, 1, role::WORD | role::TOPIC, &block, Some(&receipts));
        assert_eq!(c.state, State::Verified, "{c:?}");
        let c = check(&other, 1, role::EMITTER, &block, Some(&receipts));
        assert_eq!((c.state, c.contradicted), (State::Contradicted, role::EMITTER));
        // Without the receipts a log role stays unchecked, never contradicted.
        let c = check(&other, 1, role::EMITTER, &block, None);
        assert_eq!((c.state, c.unchecked), (State::Unverified, role::EMITTER));
        // A wrong sender is contradicted; TRACE alone is unverified.
        assert_eq!(check(&to, 1, role::FROM, &block, None).state, State::Contradicted);
        assert_eq!(check(&to, 1, role::TRACE, &block, None).state, State::Unverified);
        // A slot beyond the block's transactions contradicts every role.
        assert_eq!(check(&sender, 2, role::FROM, &block, None).state, State::Contradicted);
    }

    #[test]
    fn block_roles() {
        let block = block_with(&[], [0x44; 20]);
        assert_eq!(check(&[0x44; 20], 0, role::BLOCK, &block, None).state, State::Verified);
        assert_eq!(check(&[0x45; 20], 0, role::BLOCK, &block, None).state, State::Contradicted);
        // A block with uncles: another address may be an uncle's miner.
        let mut uncles = block_with(&[], [0x44; 20]);
        uncles.header.ommers_hash = [9; 32];
        assert_eq!(check(&[0x45; 20], 0, role::BLOCK, &uncles, None).state, State::Unverified);
        // A withdrawal recipient.
        let mut w = RawList::new();
        let item = rlp::encode_list_payload(
            &[rlp::encode_bytes(&[1]), rlp::encode_bytes(&[2]), rlp::encode_bytes(&[0x66; 20]), rlp::encode_bytes(&[3])].concat(),
        );
        w.push(&item);
        let mut shanghai = block_with(&[], [0x44; 20]);
        shanghai.withdrawals = Some(w);
        assert_eq!(check(&[0x66; 20], 0, role::BLOCK, &shanghai, None).state, State::Verified);
        // A transaction role at slot 0 is not where it says.
        assert_eq!(check(&[0x44; 20], 0, role::FROM, &block, None).state, State::Contradicted);
    }

    #[test]
    fn creation_address() {
        // The well-known example: sender 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, nonce 0
        // deploys 0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d.
        let unhex = |s: &str| -> [u8; 20] {
            (0..20).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap()
        };
        assert_eq!(
            created_address(&unhex("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"), 0),
            unhex("cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d")
        );
    }

    #[test]
    fn eip7702_authorities_follow_the_index_rule() {
        let key = myotis_core::nodekey::NodeKey::from_secret_bytes(&[9u8; 32]).unwrap();
        let authority: [u8; 20] = keccak256(&key.public_key_bytes())[12..].try_into().unwrap();
        let code = [0x77u8; 20];
        let n = |x: u64| rlp::encode_bytes(&rlp::u64_to_minimal_be(x));
        let signed = rlp::encode_list_payload(&[n(1), rlp::encode_bytes(&code), n(0)].concat());
        let sig = key.sign_hash(&keccak256(&[&[0x05u8][..], &signed].concat())).unwrap();
        let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
        let auth = |s: &[u8]| {
            rlp::encode_list_payload(
                &[n(1), rlp::encode_bytes(&code), n(0), n(sig[64] as u64), rlp::encode_bytes(&strip(&sig[..32])), rlp::encode_bytes(s)]
                    .concat(),
            )
        };
        let tx = |auths: &[Vec<u8>]| {
            let fields = [
                n(1), n(0), n(1), n(2), n(50_000), rlp::encode_bytes(&[0x11; 20]), n(0), rlp::encode_bytes(&[]),
                rlp::encode_list_payload(&[]), rlp::encode_list_payload(&auths.concat()), n(0), rlp::encode_bytes(&[1]),
                rlp::encode_bytes(&[1]),
            ]
            .concat();
            [&[0x04u8][..], &rlp::encode_list_payload(&fields)].concat()
        };
        let good = auth(&strip(&sig[32..64]));
        assert_eq!(authorizations(&tx(&[good])), (vec![authority], vec![code]));
        // A zero s is not a valid entry; its code address still counts as a WORD.
        let bad = auth(&[]);
        assert_eq!(authorizations(&tx(&[bad])), (vec![], vec![code]));
        assert_eq!(authorizations(&[0x02, 0xc0]), (vec![], vec![]));
    }
}
