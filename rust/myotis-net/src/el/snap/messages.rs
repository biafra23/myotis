//! snap/1 sub-protocol messages (EL-A6), twin of the Java
//! `networking.snap.messages` package (docs/reimplementation/02 §7).
//!
//! Pure encode/decode; the verify-on-fetch flow lives in [`super::fetch`].
//! Snap uses `GetAccountRange`/`GetStorageRanges` (which return full
//! root-to-leaf boundary proofs), NOT `GetTrieNodes`. Message codes are
//! DYNAMIC: `base = 0x10 + eth_protocol_length` (17 → base 0x21 for eth/67-68,
//! 18 → base 0x22 for eth/69); see [`SnapCodes`].

use myotis_core::rlp::{self, Item};
use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
use myotis_core::CoreError;

/// The absolute wire codes for the snap messages, derived from the negotiated
/// eth protocol length. Offsets from `base` are fixed by the snap/1 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapCodes {
    pub get_account_range: u64,
    pub account_range: u64,
    pub get_storage_ranges: u64,
    pub storage_ranges: u64,
    pub get_byte_codes: u64,
    pub byte_codes: u64,
    pub get_trie_nodes: u64,
    pub trie_nodes: u64,
}

impl SnapCodes {
    /// `base = 0x10 + eth_protocol_length`. eth/67-68 has length 17 (base
    /// 0x21); eth/69 adds BlockRangeUpdate → length 18 (base 0x22).
    pub fn for_eth_version(eth_version: u64) -> SnapCodes {
        let base = if eth_version >= 69 { 0x22 } else { 0x21 };
        SnapCodes {
            get_account_range: base,
            account_range: base + 1,
            get_storage_ranges: base + 2,
            storage_ranges: base + 3,
            get_byte_codes: base + 4,
            byte_codes: base + 5,
            get_trie_nodes: base + 6,
            trie_nodes: base + 7,
        }
    }
}

const FULL_LIMIT_HASH: [u8; 32] = [0xff; 32];

// ---------------------------------------------------------------------------
// GetAccountRange / AccountRange.
// ---------------------------------------------------------------------------

/// Encode `GetAccountRange: [reqId, stateRoot, startingHash, limitHash,
/// responseBytes]`. For a single-account lookup pass `starting =
/// keccak256(address)` and a small `response_bytes` — the peer still returns
/// one account PLUS the complete boundary proof (doc 02 §7.3).
pub fn encode_get_account_range(
    request_id: u64,
    state_root: &[u8; 32],
    starting_hash: &[u8; 32],
    limit_hash: &[u8; 32],
    response_bytes: u64,
) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::Bytes(state_root.to_vec()),
        Item::Bytes(starting_hash.to_vec()),
        Item::Bytes(limit_hash.to_vec()),
        Item::Bytes(rlp::u64_to_minimal_be(response_bytes)),
    ]))
}

/// Convenience: a single-account request over `[keccak(addr), 0xff…ff]`.
pub fn encode_get_account(
    request_id: u64,
    state_root: &[u8; 32],
    account_hash: &[u8; 32],
    response_bytes: u64,
) -> Vec<u8> {
    encode_get_account_range(request_id, state_root, account_hash, &FULL_LIMIT_HASH, response_bytes)
}

/// The slim account body from an AccountRange pair: `[nonce, balance,
/// storageRoot?, codeHash?]` with empty storageRoot/codeHash defaulting to the
/// EMPTY_ROOT / EMPTY_CODE_HASH. NOTE: this is the PEER'S claim — the
/// trustworthy account comes from the MPT-verified proof leaf (README §11.8),
/// so [`super::fetch`] does not trust these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlimAccount {
    pub account_hash: [u8; 32],
    pub nonce: u64,
    /// Minimal big-endian wei balance.
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// A decoded AccountRange response: `(reqId, accounts, proof_nodes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRange {
    pub request_id: u64,
    pub accounts: Vec<SlimAccount>,
    pub proof: Vec<Vec<u8>>,
}

/// Decode `AccountRange: [reqId, [[accountHash, slimBody], …], [proofNode, …]]`.
pub fn decode_account_range(rlp_bytes: &[u8]) -> Result<AccountRange, CoreError> {
    let top = rlp::decode(rlp_bytes)?;
    let items = top.as_list()?;
    if items.is_empty() {
        return Err(CoreError("AccountRange: empty".into()));
    }
    let request_id = items[0].as_u64()?;

    let mut accounts = Vec::new();
    if let Some(Item::List(pairs)) = items.get(1) {
        for pair in pairs {
            let fields = pair.as_list()?;
            if fields.len() < 2 {
                return Err(CoreError("AccountRange: malformed pair".into()));
            }
            let mut account_hash = [0u8; 32];
            account_hash.copy_from_slice(fields[0].as_fixed_bytes(32)?);
            accounts.push(decode_slim_account(account_hash, &fields[1])?);
        }
    }
    let proof = decode_proof(items.get(2));
    Ok(AccountRange {
        request_id,
        accounts,
        proof,
    })
}

/// The slim body is either a nested list `[nonce, balance, root?, codeHash?]`
/// or a byte-string wrapping that list's RLP (go-ethereum's `[]byte` form).
fn decode_slim_account(account_hash: [u8; 32], body: &Item) -> Result<SlimAccount, CoreError> {
    let fields_owned;
    let fields: &[Item] = match body {
        Item::List(f) => f,
        Item::Bytes(b) => {
            fields_owned = rlp::decode(b)?;
            fields_owned.as_list()?
        }
    };
    let nonce = fields.first().map_or(Ok(0), Item::as_u64)?;
    let balance = fields.get(1).map_or(Ok(Vec::new()), |b| b.as_bytes().map(<[u8]>::to_vec))?;
    let storage_root = slim_hash(fields.get(2), &EMPTY_TRIE_ROOT)?;
    let code_hash = slim_hash(fields.get(3), &EMPTY_CODE_HASH)?;
    Ok(SlimAccount {
        account_hash,
        nonce,
        balance,
        storage_root,
        code_hash,
    })
}

/// A slim-encoded 32-byte hash: empty defaults to `default`.
fn slim_hash(item: Option<&Item>, default: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    match item {
        None => Ok(*default),
        Some(it) => {
            let b = it.as_bytes()?;
            if b.is_empty() {
                Ok(*default)
            } else if b.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(b);
                Ok(out)
            } else {
                Err(CoreError(format!("slim account: hash is {} bytes", b.len())))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GetStorageRanges / StorageRanges.
// ---------------------------------------------------------------------------

/// Encode `GetStorageRanges: [reqId, stateRoot, [accountHash], startingHash,
/// limitHash, responseBytes]` for a single account.
pub fn encode_get_storage_ranges(
    request_id: u64,
    state_root: &[u8; 32],
    account_hash: &[u8; 32],
    starting_hash: &[u8; 32],
    limit_hash: &[u8; 32],
    response_bytes: u64,
) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::Bytes(state_root.to_vec()),
        Item::List(vec![Item::Bytes(account_hash.to_vec())]),
        Item::Bytes(starting_hash.to_vec()),
        Item::Bytes(limit_hash.to_vec()),
        Item::Bytes(rlp::u64_to_minimal_be(response_bytes)),
    ]))
}

/// Convenience: a single-slot request over `[keccak(slot), 0xff…ff]`.
pub fn encode_get_storage_slot(
    request_id: u64,
    state_root: &[u8; 32],
    account_hash: &[u8; 32],
    slot_hash: &[u8; 32],
    response_bytes: u64,
) -> Vec<u8> {
    encode_get_storage_ranges(request_id, state_root, account_hash, slot_hash, &FULL_LIMIT_HASH, response_bytes)
}

/// One storage slot from the wire. INFORMATIONAL ONLY — the trusted value
/// comes from the MPT proof (`fetch::verify_storage`), never this field.
///
/// NOTE the representation differs from the Java twin: Rust keeps the raw trie
/// value `rlp(trimmed_uint256)` (one wire layer stripped by our Item decode),
/// whereas Java's `StorageRangesMessage.stripRlpIntegerHeader` strips a second
/// layer to the bare integer bytes. Harmless because neither side trusts it;
/// named `raw_trie_value` to avoid a future porter misreading it as the integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlot {
    pub slot_hash: [u8; 32],
    /// The raw trie value bytes (`rlp(trimmed_uint256)`) — not the integer.
    pub raw_trie_value: Vec<u8>,
}

/// A decoded StorageRanges response: `(reqId, first-account slots, proof)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRanges {
    pub request_id: u64,
    pub slots: Vec<StorageSlot>,
    pub proof: Vec<Vec<u8>>,
}

/// Decode `StorageRanges: [reqId, [[slots-for-account-0], …], [proofNode, …]]`,
/// reading the FIRST account's slots (we always query one account).
pub fn decode_storage_ranges(rlp_bytes: &[u8]) -> Result<StorageRanges, CoreError> {
    let top = rlp::decode(rlp_bytes)?;
    let items = top.as_list()?;
    if items.is_empty() {
        return Err(CoreError("StorageRanges: empty".into()));
    }
    let request_id = items[0].as_u64()?;

    let mut slots = Vec::new();
    if let Some(Item::List(per_account)) = items.get(1) {
        if let Some(Item::List(account_slots)) = per_account.first() {
            for pair in account_slots {
                let fields = pair.as_list()?;
                if fields.len() < 2 {
                    return Err(CoreError("StorageRanges: malformed slot".into()));
                }
                let mut slot_hash = [0u8; 32];
                slot_hash.copy_from_slice(fields[0].as_fixed_bytes(32)?);
                // fields[1] is the trie value (already unwrapped by our Item
                // decode — the outer wrap is the RLP bytes item itself).
                slots.push(StorageSlot {
                    slot_hash,
                    raw_trie_value: fields[1].as_bytes()?.to_vec(),
                });
            }
        }
    }
    let proof = decode_proof(items.get(2));
    Ok(StorageRanges {
        request_id,
        slots,
        proof,
    })
}

// ---------------------------------------------------------------------------
// GetByteCodes / ByteCodes.
// ---------------------------------------------------------------------------

/// Encode `GetByteCodes: [reqId, [codeHash, …], responseBytes]`.
pub fn encode_get_byte_codes(request_id: u64, hashes: &[[u8; 32]], response_bytes: u64) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::List(hashes.iter().map(|h| Item::Bytes(h.to_vec())).collect()),
        Item::Bytes(rlp::u64_to_minimal_be(response_bytes)),
    ]))
}

/// Decode `ByteCodes: [reqId, [bytecode, …]]` → `(reqId, codes)`. The caller
/// hashes each and matches it against the requested codeHash.
pub fn decode_byte_codes(rlp_bytes: &[u8]) -> Result<(u64, Vec<Vec<u8>>), CoreError> {
    let top = rlp::decode(rlp_bytes)?;
    let items = top.as_list()?;
    if items.is_empty() {
        return Err(CoreError("ByteCodes: empty".into()));
    }
    let request_id = items[0].as_u64()?;
    let mut codes = Vec::new();
    if let Some(Item::List(list)) = items.get(1) {
        for c in list {
            codes.push(c.as_bytes()?.to_vec());
        }
    }
    Ok((request_id, codes))
}

// ---------------------------------------------------------------------------
// Empty responders (a wallet answers inbound snap Get* with empty responses so
// peers don't time out — doc 02 §7.3). Encoders live here; WIRING them into an
// inbound read loop is EL-A7 (the single-shot request model here has no place
// to service unsolicited requests). Kept public so EL-A7 consumes them.
// ---------------------------------------------------------------------------

/// `[reqId, [], []]` — an empty AccountRange or StorageRanges response.
pub fn encode_empty_range(request_id: u64) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::List(vec![]),
        Item::List(vec![]),
    ]))
}

/// `[reqId, []]` — an empty ByteCodes / TrieNodes response.
pub fn encode_empty_codes(request_id: u64) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::List(vec![]),
    ]))
}

/// The leading request id of any snap response `[reqId, …]`.
pub fn response_request_id(payload: &[u8]) -> Option<u64> {
    let items = rlp::raw_list_items(payload).ok()?;
    rlp::decode(items.first()?).ok()?.as_u64().ok()
}

fn decode_proof(item: Option<&Item>) -> Vec<Vec<u8>> {
    match item {
        Some(Item::List(nodes)) => nodes
            .iter()
            .filter_map(|n| match n {
                Item::Bytes(b) => Some(b.clone()),
                Item::List(_) => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::keccak::keccak256;

    #[test]
    fn snap_codes_by_eth_version() {
        assert_eq!(SnapCodes::for_eth_version(68).get_account_range, 0x21);
        assert_eq!(SnapCodes::for_eth_version(68).byte_codes, 0x26);
        assert_eq!(SnapCodes::for_eth_version(69).get_account_range, 0x22);
        assert_eq!(SnapCodes::for_eth_version(69).byte_codes, 0x27);
    }

    #[test]
    fn get_account_range_encoding() {
        let root = keccak256(b"state");
        let acct = keccak256(b"addr");
        let msg = encode_get_account(7, &root, &acct, 4096);
        let items = rlp::decode(&msg).unwrap();
        let f = items.as_list().unwrap();
        assert_eq!(f.len(), 5);
        assert_eq!(f[0].as_u64().unwrap(), 7);
        assert_eq!(f[1].as_fixed_bytes(32).unwrap(), &root);
        assert_eq!(f[3].as_fixed_bytes(32).unwrap(), &FULL_LIMIT_HASH);
        assert_eq!(f[4].as_u64().unwrap(), 4096);
    }

    #[test]
    fn account_range_decode_both_slim_forms() {
        let acct_hash = keccak256(b"account");
        let sroot = keccak256(b"storage");
        let chash = keccak256(b"code");
        // Inline-list form: [nonce, balance, storageRoot, codeHash].
        let inline = Item::List(vec![
            Item::List(vec![
                Item::Bytes(acct_hash.to_vec()),
                Item::List(vec![
                    Item::Bytes(rlp::u64_to_minimal_be(5)),
                    Item::Bytes(vec![0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]),
                    Item::Bytes(sroot.to_vec()),
                    Item::Bytes(chash.to_vec()),
                ]),
            ]),
        ]);
        let msg = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(1)),
            inline,
            Item::List(vec![]),
        ]));
        let decoded = decode_account_range(&msg).unwrap();
        assert_eq!(decoded.accounts.len(), 1);
        let a = &decoded.accounts[0];
        assert_eq!(a.account_hash, acct_hash);
        assert_eq!(a.nonce, 5);
        assert_eq!(a.storage_root, sroot);
        assert_eq!(a.code_hash, chash);

        // Bytes-wrapped form: the body is a byte string of the same RLP.
        let body_rlp = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(5)),
            Item::Bytes(vec![0x01]),
            Item::Bytes(Vec::new()), // empty storageRoot → EMPTY_TRIE_ROOT
            Item::Bytes(Vec::new()), // empty codeHash → EMPTY_CODE_HASH
        ]));
        let wrapped = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(1)),
            Item::List(vec![Item::List(vec![
                Item::Bytes(acct_hash.to_vec()),
                Item::Bytes(body_rlp),
            ])]),
            Item::List(vec![]),
        ]));
        let d2 = decode_account_range(&wrapped).unwrap();
        assert_eq!(d2.accounts[0].storage_root, EMPTY_TRIE_ROOT);
        assert_eq!(d2.accounts[0].code_hash, EMPTY_CODE_HASH);
    }

    #[test]
    fn byte_codes_round_trip() {
        let h = keccak256(b"code");
        let msg = encode_get_byte_codes(3, &[h], 8192);
        let items = rlp::decode(&msg).unwrap();
        assert_eq!(items.as_list().unwrap().len(), 3);
        let resp = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(3)),
            Item::List(vec![Item::Bytes(vec![0x60, 0x00])]),
        ]));
        let (id, codes) = decode_byte_codes(&resp).unwrap();
        assert_eq!(id, 3);
        assert_eq!(codes, vec![vec![0x60, 0x00]]);
    }

    #[test]
    fn empty_responders() {
        assert!(decode_account_range(&encode_empty_range(9)).unwrap().accounts.is_empty());
        assert_eq!(decode_byte_codes(&encode_empty_codes(9)).unwrap(), (9, vec![]));
    }
}
