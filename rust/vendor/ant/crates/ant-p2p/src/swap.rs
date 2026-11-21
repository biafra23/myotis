//! Bee-compatible `/swarm/swap/1.0.0/swap` wire protocol — Phase 7
//! of M3.
//!
//! # What this is
//!
//! Bee's payments-above-pseudosettle layer settles per-peer debt by
//! exchanging **off-chain EIP-712-signed cheques**. The cheque is a
//! cumulative promise: cheque N supersedes cheque N-1 because both
//! are signed against the same `(chequebook, beneficiary)` pair and
//! the on-chain `cashChequeBeneficiary` only ever pays out
//! `cumulative_payout - already_paid`. Lost cheques are harmless;
//! the next cheque catches the beneficiary up.
//!
//! The cheque object itself is built and signed by
//! [`ant_chain::chequebook`]. This module owns the **wire layer**:
//! how cheques traverse the libp2p stream between peers.
//!
//! # The protocol (bee 2.7.x and 2.8.0)
//!
//! Bee 2.8.0 reshapes the BZZ handshake (new signed preimage; nonce /
//! timestamp / chequebook moved into `BzzAddress`) but does not touch
//! the swap stream itself. Cheque issue / receive remains the same
//! wire format and is unaffected by the cutover.
//!
//! `/swarm/swap/1.0.0/swap` is a single-direction stream:
//!
//! ```text
//! dialer → listener : varint + Headers pb (empty)            // bee headers preamble
//! listener → dialer : varint + Headers pb { exchange, deduction }
//! dialer → listener : varint + EmitCheque{ Cheque: bytes }   // JSON-encoded SignedCheque
//! listener          : FullClose when it accepted the cheque, Reset when not
//! ```
//!
//! The listener's response headers carry its price oracle's `exchange`
//! rate (PLUR per accounting unit) and `deduction` (PLUR). Bee pays
//! `debt × exchange + deduction` and credits `(paid − deduction) /
//! exchange` units ([`SettlementRates`], used by retrieval payments).
//!
//! `EmitCheque.Cheque` is **bee's `chequebook.SignedCheque`
//! JSON-marshalled** (NOT the binary cheque encoding); see
//! `pkg/settlement/swap/swapprotocol/swapprotocol.go::EmitCheque`. The
//! JSON shape go-ethereum produces by default is what the wire
//! carries:
//!
//! ```json
//! {
//!   "Chequebook": "0x...",        // 0x-hex 20 bytes (geth common.Address)
//!   "Beneficiary": "0x...",
//!   "CumulativePayout": 12345,    // bare number (big.Int's MarshalJSON)
//!   "Signature": "..."            // base64 65-byte r ‖ s ‖ v (default []byte JSON)
//! }
//! ```
//!
//! The receiving side validates the signature, recovers the issuer,
//! and credits the chequebook's beneficiary balance. Bee then asks
//! the chain whether `chequebook.issuer()` matches the recovered
//! signer; we expose [`recover_cheque_signer`](ant_chain::chequebook::recover_cheque_signer)
//! so callers can do the same lookup once they have a
//! [`ant_chain::ChainClient`].
//!
//! # What this module does
//!
//! - [`PROTOCOL_SWAP`] constant for protocol negotiation.
//! - [`EmitChequePb`]: the protobuf framing.
//! - [`encode_signed_cheque_json`] / [`decode_signed_cheque_json`]:
//!   bee-shape JSON for the wire's `Cheque` payload.
//! - [`CreditLedger`]: per-`chequebook` cumulative-paid-in tracking
//!   with crash-safe JSON persistence (atomic write + fsync), so a
//!   restart can't accept a replayed older cheque.
//! - [`run_inbound`]: listener task that drains accepted streams,
//!   verifies cheques, and updates the ledger.
//! - [`emit_cheque`]: outbound dialer that ships a signed cheque.
//! - [`open_settlement`] / [`write_cheque`] / [`await_processed`]: the
//!   steps of bee's `swapprotocol.EmitCheque` that the node's payer
//!   (`crate::PushsyncSwap`) runs, pricing each cheque from the
//!   recipient's rate headers.
//!
//! # What this module does **not** do (yet)
//!
//! - On-chain `chequebook(Cheque.Chequebook).issuer()` validation.
//!   The ledger pins the `(chequebook → expected_signer)` binding on
//!   first sight; subsequent cheques must match. A future hardening
//!   step is a one-shot RPC at first contact to confirm the signer
//!   really controls the chequebook.
//! - Auto-cashout. Cashing the highest-cumulative cheque on-chain
//!   requires a wallet that can pay xDAI gas; today we just store
//!   the cheque. The operator can pull a snapshot from the ledger
//!   and call [`ant_chain::chequebook::cash_cheque_beneficiary_calldata`]
//!   manually.
//!
//! Settlement triggering lives with the callers: pushsync debt in
//! [`crate::pushsync_swap`], retrieval debt in
//! [`ant_retrieval::accounting`] paying through it (issue #121), with
//! [`open_settlement`], [`write_cheque`] and [`await_processed`].
//!
//! Everything here is wire-compatible with bee: a cheque we emit
//! reaches bee's `s.swap.ReceiveCheque` and would be accepted modulo
//! the on-chain issuer check; a cheque bee emits to us is parsed by
//! [`run_inbound`].

use crate::sinks::{HEADERS_MAX, STREAM_TIMEOUT};
use ant_chain::chequebook::{recover_cheque_signer, sign_cheque, Cheque, SignedCheque};
use ant_crypto::{CryptoError, SECP256K1_SECRET_LEN};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::StreamExt;
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::{Control, IncomingStreams};
use libp2p_swarm::Stream;
use primitive_types::U256;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Bee's swap stream path. Built as `/swarm/<name>/<version>/<stream>`
/// where `name="swap"`, `version="1.0.0"`, and `stream="swap"` (see
/// `pkg/settlement/swap/swapprotocol/swapprotocol.go`).
pub const PROTOCOL_SWAP: &str = "/swarm/swap/1.0.0/swap";

/// Hard cap on the protobuf body of an `EmitCheque`. The JSON cheque
/// inside is ~250 bytes (3 × 0x-hex 20-byte addresses + decimal int +
/// base64 65-byte sig + JSON quoting). 4 KiB gives a generous
/// headroom for any future schema growth without risking a malicious
/// peer feeding us megabyte cheques.
const EMIT_CHEQUE_MAX: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum SwapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("protobuf encode: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("decimal: {0}")]
    Decimal(String),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("cheque rejected: {0}")]
    Rejected(String),
}

/// Bee `swapprotocol/pb/swap.proto::EmitCheque`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct EmitChequePb {
    /// JSON-encoded `chequebook.SignedCheque`.
    #[prost(bytes = "vec", tag = "1")]
    pub cheque: Vec<u8>,
}

/// Bee-shaped JSON for `chequebook.SignedCheque`. Must be a
/// byte-for-byte match of what go's `encoding/json` produces over
/// `chequebook.SignedCheque`:
///
/// - `Chequebook` / `Beneficiary`: 0x-prefixed hex (geth's
///   `common.Address.MarshalJSON`).
/// - `CumulativePayout`: a bare JSON number. Go's `*big.Int` implements
///   `json.Marshaler` (`MarshalJSON` writes the decimal digits
///   unquoted), and its `UnmarshalJSON` refuses a quoted string
///   (`math/big: cannot unmarshal "\"123\"" into a *big.Int`), so bee's
///   swap handler resets the stream on a quoted payout and never
///   credits the cheque (issue #121). Decoding also accepts the quoted
///   form, which earlier Ant versions sent.
/// - `Signature`: base64 standard-padding (geth `[]byte` default).
#[derive(Debug, Serialize, Deserialize)]
struct SignedChequeJson {
    #[serde(rename = "Chequebook")]
    chequebook: String,
    #[serde(rename = "Beneficiary")]
    beneficiary: String,
    #[serde(rename = "CumulativePayout")]
    cumulative_payout: Box<serde_json::value::RawValue>,
    #[serde(rename = "Signature")]
    signature: String,
}

/// JSON-encode a [`SignedCheque`] into the wire bytes carried inside
/// an `EmitCheque.Cheque` field. Lossless round-trip with
/// [`decode_signed_cheque_json`].
#[must_use]
pub fn encode_signed_cheque_json(signed: &SignedCheque) -> Vec<u8> {
    let body = SignedChequeJson {
        chequebook: format!("0x{}", hex::encode(signed.cheque.chequebook)),
        beneficiary: format!("0x{}", hex::encode(signed.cheque.beneficiary)),
        cumulative_payout: serde_json::value::RawValue::from_string(
            signed.cheque.cumulative_payout.to_string(),
        )
        .expect("decimal digits are a JSON number"),
        signature: BASE64.encode(signed.signature),
    };
    serde_json::to_vec(&body).expect("SignedChequeJson serialises")
}

/// Decode bee-shape JSON back into a [`SignedCheque`].
pub fn decode_signed_cheque_json(bytes: &[u8]) -> Result<SignedCheque, SwapError> {
    let body: SignedChequeJson = serde_json::from_slice(bytes)?;
    let chequebook = parse_addr_0x(&body.chequebook)?;
    let beneficiary = parse_addr_0x(&body.beneficiary)?;
    let payout = body.cumulative_payout.get().trim();
    let payout = payout
        .strip_prefix('"')
        .and_then(|p| p.strip_suffix('"'))
        .unwrap_or(payout);
    if payout.is_empty() || !payout.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SwapError::Decimal(format!(
            "cumulative_payout: not a decimal integer: {payout}"
        )));
    }
    let cumulative_payout = U256::from_dec_str(payout)
        .map_err(|e| SwapError::Decimal(format!("cumulative_payout: {e}")))?;
    let sig_bytes = BASE64.decode(body.signature.trim())?;
    if sig_bytes.len() != 65 {
        return Err(SwapError::Rejected(format!(
            "signature length {} (expected 65)",
            sig_bytes.len(),
        )));
    }
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&sig_bytes);
    Ok(SignedCheque {
        cheque: Cheque {
            chequebook,
            beneficiary,
            cumulative_payout,
        },
        signature,
    })
}

fn parse_addr_0x(s: &str) -> Result<[u8; 20], SwapError> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 20 {
        return Err(SwapError::Rejected(format!(
            "address length {} (expected 20)",
            bytes.len(),
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Per-chequebook record stored in the [`CreditLedger`]. Bee's swap
/// layer reasons in cumulative terms, so all we need to remember is
/// the highest cumulative payout we've accepted from this chequebook
/// plus the signer we pinned the chequebook to on first sight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChequebookCredit {
    /// Lower-case hex (no 0x) of the issuer EOA we recovered from the
    /// first cheque this chequebook produced. Subsequent cheques whose
    /// signature recovers to a different EOA are rejected; protects
    /// against a peer swapping its issuer key out from under us mid-
    /// session.
    pub issuer_eoa_hex: String,
    /// Highest accepted `cumulative_payout` for this chequebook,
    /// stored as a decimal string so it round-trips through serde
    /// without losing precision (U256 doesn't impl serde itself).
    pub cumulative_payout_dec: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LedgerSnapshot {
    /// Map keyed on chequebook address (lower-case hex, no `0x`).
    cheques: HashMap<String, ChequebookCredit>,
}

/// In-memory + on-disk per-chequebook credit ledger. The ledger is
/// the **trust anchor**: every accepted cheque must
///
/// 1. carry a `cumulative_payout` strictly greater than what we have
///    on file for that chequebook — except the first cheque after a
///    damaged figure (see below), which has nothing to compare against
///    and is accepted as the new baseline with no monotonic check,
/// 2. recover to the same issuer EOA that signed the first cheque
///    we ever accepted from that chequebook (sticky binding), and
/// 3. signature-verify against the cheque's own `Chequebook` /
///    `Beneficiary` / `CumulativePayout` triple at the configured
///    chain id.
///
/// Persistence is atomic: every `record_accepted` flushes a fresh
/// JSON snapshot to a temp file, fsyncs, and renames over the live
/// path. A crash mid-write leaves the previous snapshot intact and
/// the new cheque unrecorded — bee's cumulative model means the
/// peer just re-emits the same (or higher) cheque on the next
/// connection and we accept it then.
///
/// A stored `cumulative_payout_dec` that isn't a decimal number
/// (bee#5656: an empty string, which `U256::from_dec_str` reads as
/// zero) is not dropped: [`Self::open`] keeps the entry, so the issuer
/// pin (rule 2) still holds, and logs a warning for it. The next cheque
/// from that chequebook is checked against rules 2 and 3 only and
/// becomes the new baseline, crediting nothing (`rebaseline`); rule 1
/// applies again from the cheque after it. The true previous figure is
/// gone, so a cheque at or below it can't be told apart from a new
/// payment once the baseline is set; see `rebaseline` for what that
/// costs.
pub struct CreditLedger {
    inner: Mutex<LedgerSnapshot>,
    persist_path: Option<PathBuf>,
    chain_id: u64,
    /// Beneficiary address all accepted cheques must target — i.e.
    /// our own node's EOA. A cheque with a different beneficiary is
    /// rejected (the issuer is paying someone else and the wire
    /// is presumably misrouted).
    our_beneficiary: [u8; 20],
}

impl CreditLedger {
    /// Build an empty ledger backed by `persist_path` (or memory-only
    /// if `None`). Loads any existing snapshot if the file exists; an
    /// unreadable / unparseable snapshot is treated as empty after
    /// logging — better to lose history than refuse to start. An entry
    /// whose cumulative isn't a decimal number is kept (its issuer pin
    /// still applies) with a warning; the next cheque rebaselines it.
    pub fn open(persist_path: Option<PathBuf>, chain_id: u64, our_beneficiary: [u8; 20]) -> Self {
        let inner = match &persist_path {
            Some(p) if p.exists() => match std::fs::read(p) {
                Ok(bytes) => match serde_json::from_slice::<LedgerSnapshot>(&bytes) {
                    Ok(snap) => {
                        info!(
                            target: "ant_p2p::swap",
                            path = %p.display(),
                            chequebooks = snap.cheques.len(),
                            "loaded credit ledger snapshot",
                        );
                        for (k, c) in &snap.cheques {
                            if parse_stored_cumulative(&c.cumulative_payout_dec).is_none() {
                                warn!(
                                    target: "ant_p2p::swap",
                                    path = %p.display(),
                                    chequebook = %k,
                                    stored = ?c.cumulative_payout_dec,
                                    "stored cumulative is not a decimal number; \
                                     the next cheque from this chequebook \
                                     becomes its baseline and credits nothing",
                                );
                            }
                        }
                        snap
                    }
                    Err(e) => {
                        warn!(
                            target: "ant_p2p::swap",
                            path = %p.display(),
                            "ledger snapshot unparseable: {e}; starting empty",
                        );
                        LedgerSnapshot::default()
                    }
                },
                Err(e) => {
                    warn!(
                        target: "ant_p2p::swap",
                        path = %p.display(),
                        "ledger snapshot unreadable: {e}; starting empty",
                    );
                    LedgerSnapshot::default()
                }
            },
            _ => LedgerSnapshot::default(),
        };
        Self {
            inner: Mutex::new(inner),
            persist_path,
            chain_id,
            our_beneficiary,
        }
    }

    /// Apply `signed` to the ledger, returning the previous
    /// cumulative payout for that chequebook (zero on first sight; the
    /// cheque's own cumulative when the stored one is damaged, see
    /// [`rebaseline`]). Validates: signature, beneficiary, sticky-issuer
    /// binding, and monotonicity against the stored figure (skipped when
    /// that figure is damaged and this cheque becomes the baseline). A pure read-only check (no ledger mutation) is
    /// available via [`Self::would_accept`].
    pub fn record_accepted(&self, signed: &SignedCheque) -> Result<U256, SwapError> {
        if signed.cheque.beneficiary != self.our_beneficiary {
            return Err(SwapError::Rejected(format!(
                "cheque beneficiary 0x{} != our 0x{}",
                hex::encode(signed.cheque.beneficiary),
                hex::encode(self.our_beneficiary),
            )));
        }
        let recovered = recover_cheque_signer(signed, self.chain_id)?;
        let chequebook_key = hex::encode(signed.cheque.chequebook);
        let recovered_hex = hex::encode(recovered);
        let mut guard = self.inner.lock().expect("ledger mutex poisoned");
        let warn_rebaseline = true;
        let stored = match guard.cheques.get(&chequebook_key) {
            Some(c) => {
                if c.issuer_eoa_hex != recovered_hex {
                    return Err(SwapError::Rejected(format!(
                        "issuer for chequebook 0x{chequebook_key} changed: \
                         saw 0x{recovered_hex}, pinned to 0x{}",
                        c.issuer_eoa_hex,
                    )));
                }
                parse_stored_cumulative(&c.cumulative_payout_dec)
            }
            None => Some(U256::zero()),
        };
        let prev_cum = match stored {
            Some(prev) => prev,
            None => rebaseline(&chequebook_key, signed, warn_rebaseline),
        };
        if signed.cheque.cumulative_payout <= prev_cum && stored.is_some() {
            return Err(SwapError::Rejected(format!(
                "non-monotonic cheque for 0x{chequebook_key}: cum={} <= stored={}",
                signed.cheque.cumulative_payout, prev_cum,
            )));
        }
        guard.cheques.insert(
            chequebook_key,
            ChequebookCredit {
                issuer_eoa_hex: recovered_hex,
                cumulative_payout_dec: signed.cheque.cumulative_payout.to_string(),
            },
        );
        if let Some(path) = &self.persist_path {
            if let Err(e) = persist_snapshot(path, &guard) {
                warn!(
                    target: "ant_p2p::swap",
                    path = %path.display(),
                    "ledger persist failed: {e}; in-memory state still updated",
                );
            }
        }
        Ok(prev_cum)
    }

    /// Read-only validation. Returns the would-be previous cumulative
    /// payout on success, the rejection reason on failure. Pure — no
    /// ledger mutation.
    pub fn would_accept(&self, signed: &SignedCheque) -> Result<U256, SwapError> {
        if signed.cheque.beneficiary != self.our_beneficiary {
            return Err(SwapError::Rejected(format!(
                "cheque beneficiary 0x{} != our 0x{}",
                hex::encode(signed.cheque.beneficiary),
                hex::encode(self.our_beneficiary),
            )));
        }
        let recovered = recover_cheque_signer(signed, self.chain_id)?;
        let chequebook_key = hex::encode(signed.cheque.chequebook);
        let recovered_hex = hex::encode(recovered);
        let guard = self.inner.lock().expect("ledger mutex poisoned");
        let warn_rebaseline = false;
        let stored = match guard.cheques.get(&chequebook_key) {
            Some(c) => {
                if c.issuer_eoa_hex != recovered_hex {
                    return Err(SwapError::Rejected(format!(
                        "issuer for chequebook 0x{chequebook_key} changed",
                    )));
                }
                parse_stored_cumulative(&c.cumulative_payout_dec)
            }
            None => Some(U256::zero()),
        };
        let prev_cum = match stored {
            Some(prev) => prev,
            None => rebaseline(&chequebook_key, signed, warn_rebaseline),
        };
        if signed.cheque.cumulative_payout <= prev_cum && stored.is_some() {
            return Err(SwapError::Rejected(format!(
                "non-monotonic cumulative payout {} <= stored {}",
                signed.cheque.cumulative_payout, prev_cum,
            )));
        }
        Ok(prev_cum)
    }

    /// Latest accepted cheque amount for `chequebook` (zero if none).
    /// Used by [`issue_and_emit`] callers that want to mint
    /// `cumulative_payout = stored + amount` for an outbound cheque.
    #[must_use]
    pub fn cumulative_for(&self, chequebook: &[u8; 20]) -> U256 {
        let key = hex::encode(chequebook);
        let guard = self.inner.lock().expect("ledger mutex poisoned");
        match guard.cheques.get(&key) {
            Some(c) => parse_stored_cumulative(&c.cumulative_payout_dec).unwrap_or(U256::zero()),
            None => U256::zero(),
        }
    }

    /// The beneficiary address accepted cheques must target (our own
    /// node's EOA). Exposed so the accounting snapshot can render the
    /// `lastreceived.beneficiary` field of `GET /chequebook/cheque`.
    #[must_use]
    pub fn beneficiary(&self) -> [u8; 20] {
        self.our_beneficiary
    }

    /// Snapshot copy of every chequebook record we know about.
    /// Useful for `antctl swap list` (future) and for the cashout
    /// helper that wants to know the highest cheque per peer.
    pub fn snapshot(&self) -> Vec<(String, ChequebookCredit)> {
        let guard = self.inner.lock().expect("ledger mutex poisoned");
        guard
            .cheques
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// A stored cumulative as a `U256`: a non-empty string of ASCII digits
/// that fits. `None` for anything else — an empty string, a sign, an
/// exponent, spaces, too large. Stricter than `U256::from_dec_str`, which
/// reads `""` as zero (bee#5656).
fn parse_stored_cumulative(s: &str) -> Option<U256> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    U256::from_dec_str(s).ok()
}

/// The previous cumulative for `signed` when the stored one is damaged
/// (bee#5656). That figure is not zero — read as zero, a re-sent old
/// cheque would be credited in full again — and not a reason to refuse
/// the chequebook for good either. The incoming cheque becomes the new
/// baseline instead: it is accepted and recorded, and the previous
/// cumulative reported for it is its own, so it credits nothing. Cheques
/// after it credit their increase as usual.
///
/// This is not exact in either direction, because the real previous
/// figure is lost. An honest peer, whose next cheque is above it, loses
/// that one cheque's increase. A peer that instead re-sends its older
/// cheques in ascending order gets the first one as the baseline and
/// every increase after it, up to the lost figure, credited a second
/// time; the stored figure meanwhile drops back to the replayed value
/// until the peer's cheques pass it again. What can be credited twice is
/// bounded by the lost figure minus the replayed baseline (at most the
/// lost figure) and is accounting credit only: the chequebook pays out on
/// the highest cumulative, so no extra money is cashed.
fn rebaseline(key: &str, signed: &SignedCheque, log: bool) -> U256 {
    if log {
        warn!(
            target: "ant_p2p::swap",
            chequebook = %key,
            cumulative = %signed.cheque.cumulative_payout,
            "stored cumulative for chequebook is not a decimal number; \
             taking this cheque as the new baseline, crediting nothing for it",
        );
    }
    signed.cheque.cumulative_payout
}

fn persist_snapshot(path: &Path, snap: &LedgerSnapshot) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(snap).map_err(std::io::Error::other)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Sign a fresh cheque with `cumulative_payout = previous + amount`
/// (where `previous` comes from the ledger's outbound mirror — see
/// [`OutboundLedger`]) and return the signed object ready to feed
/// into [`emit_cheque`].
pub fn issue_cheque(
    secret: &[u8; SECP256K1_SECRET_LEN],
    chequebook: [u8; 20],
    beneficiary: [u8; 20],
    cumulative_payout: U256,
    chain_id: u64,
) -> Result<SignedCheque, SwapError> {
    let cheque = Cheque {
        chequebook,
        beneficiary,
        cumulative_payout,
    };
    Ok(sign_cheque(secret, &cheque, chain_id)?)
}

/// Companion to [`CreditLedger`] for OUTBOUND cheques: tracks the
/// last cumulative amount one chequebook issued to each peer's
/// beneficiary so the next cheque is monotonically larger.
///
/// Cumulatives belong to a `(chequebook, beneficiary)` pair: bee keeps
/// its `lastReceived` per chequebook, and a chequebook's liability
/// (what [`Self::total_issued`] reports) is only its own cheques. So the
/// file holds one section per chequebook and a ledger opened for one
/// chequebook reads and rewrites only its own section. Switching the
/// data dir to another chequebook (`--chequebook`, a fresh deploy after
/// a rejected one) starts that chequebook from zero, and switching back
/// finds the first one's cumulatives where they were.
///
/// On disk it stays the flat `string → decimal string` map releases
/// before the sections wrote, with each entry keyed
/// `<chequebook hex>:<beneficiary hex>`, so a downgraded release still
/// parses the file: it loads the entries (finding none under its bare
/// beneficiary keys, so its pushsync cheques restart from zero) and
/// writes them all back with its own, instead of failing to parse and
/// replacing every chequebook's figures (PR #126 R4-M3).
///
/// The in-memory cumulatives are the source of truth while the process
/// runs; the file is read only when a chequebook's ledger opens (or
/// retries a failed read). A cheque doesn't rewrite it (issue #140: that
/// cost one read, re-serialisation and fsync of the whole ledger per
/// cheque, under one lock, and paid throughput fell as the ledger grew).
/// Each cheque appends one line, `{"<chequebook>:<beneficiary>":"<cum>"}`,
/// to a journal next to it, `<name>.journal`, and the cheque goes out only
/// once that line is fsynced ([`Self::stage_issued`], [`PendingWrite`]).
/// Cheques issued together share one write and fsync (group commit), and
/// the work per cheque doesn't depend on how many peers the ledger holds.
/// Reading takes the larger figure of the file and every journal line
/// (cumulatives only grow), so a line repeated or replayed is harmless.
///
/// The journal is folded back into the file (compaction) once it holds
/// as many lines as the file has entries (at least
/// [`COMPACT_MIN_LINES`]), when the first ledger on the file opens, and
/// when the last one closes. Compaction renames the journal to
/// `<name>.journal.old` (new cheques start a fresh journal), writes the
/// merged file (temp file, fsync, rename) and only then deletes the old
/// journal; a crash at any step leaves every figure in the file or a
/// journal, and the next open finishes the job. It reads the file like an
/// open does, so it never writes over a file it couldn't read, and it
/// keeps the sections of every chequebook in it.
///
/// A downgraded release reads only the file, so it misses the cheques
/// still in a journal: after a clean stop there are none (the last ledger
/// closing compacts), after a crash, start this release once first (the
/// open compacts). The journal must travel with the file (ant-ffi's
/// account parking moves both).
///
/// Bare `beneficiary → cumulative` entries — a file from before the
/// sections, or ones a downgraded release added — are adopted by the
/// first chequebook that opens the file (the larger figure wins against
/// one it already has) and rewritten under it at once, so a second
/// chequebook can't adopt them too. Only pushsync cheques were ever
/// written that way, a few million PLUR at most.
///
/// Clones (and ledgers opened on the same file and chequebook while one
/// is alive) share one state, and with it the locks that serialise
/// issuing cheques ([`Self::beneficiary_lock`], [`Self::funds_gate`]).
///
/// A file that isn't JSON of either shape is moved aside to
/// `<name>.corrupt-<unix secs>[-n]` and every chequebook in it starts
/// from zero: its figures can't be recovered by reading it again, and
/// refusing every cheque until someone repairs it by hand would stop
/// uploads for good. Nothing is paid twice by restarting — a peer only
/// credits a cheque above the cumulative it already holds — but a peer
/// this chequebook had paid up to `C` refuses each new cheque until the
/// restarted cumulative passes `C`. The payer can't see those refusals
/// (bee resets the stream, which rust-yamux reports as a clean end, see
/// [`await_processed`]), so it would lower its debt mirror as if paid,
/// run up real debt with that peer, and be disconnected or blocklisted
/// by the very peers it paid — which also costs it their free tier.
///
/// So a move aside also leaves a marker, `<name>.lost`, and while it
/// exists every chequebook on the file counts as having lost its
/// figures ([`Self::lost_figures`]): its issued total is unknown,
/// the node pays no cheques from it, for downloads or uploads
/// (`PushsyncSwap::pays_retrieval`), and `/chequebook/balance` says so
/// (until #127 upload cheques went on regardless). The
/// marker never clears by itself, only by an operator confirming the
/// chequebook's outstanding liability ([`confirm_cheque_liability`]:
/// `antd --confirm-cheque-liability`, `ant_confirm_cheque_liability`)
/// (PR #126 R4-M1). That also works on a marker that can't be parsed:
/// it is replaced by one that still counts every other chequebook as
/// lost, so nobody has to delete it by hand. Two kinds of chequebook
/// are exempt without an operator, since their figures are known
/// (PR #126 R1-M3): one deployed after the loss
/// ([`note_fresh_chequebook`]), which has never issued a cheque, and one
/// whose ledger was open in this process, with its figures known, when
/// the file was lost — its cumulatives survived in memory, so it is
/// exempt at once for this run and for good once it has written them to
/// the new file. A ledger still lost to an earlier loss holds only what
/// it issued since, so a new loss doesn't exempt it (PR #126 R2-F1).
#[derive(Clone)]
pub struct OutboundLedger {
    chequebook: [u8; 20],
    shared: Arc<OutboundShared>,
    persist_path: Option<PathBuf>,
}

/// What every [`OutboundLedger`] open on one `(file, chequebook)` shares.
#[derive(Default)]
struct OutboundShared {
    state: Mutex<OutboundState>,
    /// One lock per beneficiary, held from reading its last cumulative
    /// to recording the new one (bee's `chequebook.Issue` lock). Shared
    /// so an old service still finishing a cheque and a new one on the
    /// same chequebook can't both sign `C + a` and `C + b` on the same
    /// `C` (PR #126 R3-M1).
    issuing: Mutex<HashMap<[u8; 20], Arc<tokio::sync::Mutex<()>>>>,
    /// Held from checking the funds left to recording a cheque against
    /// them, across every service on the chequebook.
    funds: Mutex<()>,
    /// The chequebook's figures were read from the file at least once,
    /// so the in-memory cumulatives hold everything it ever issued from
    /// this file (they only grow, and every cheque is recorded here).
    loaded: AtomicBool,
    /// The file was lost while this state was `loaded`: the figures in
    /// memory are still complete, so the loss doesn't apply to this
    /// chequebook. Cleared once they are rewritten to the new file and
    /// the marker records the chequebook as known.
    survived_loss: AtomicBool,
    /// Bumped every time [`Self::survived_loss`] is set, so clearing it
    /// after a rewrite can tell whether another loss came in between.
    loss_gen: AtomicU64,
    /// Where cheques are journaled; `None` for a ledger without a file.
    store: Option<Arc<JournalStore>>,
}

/// One chequebook's cumulatives, shared by every [`OutboundLedger`]
/// open on the same `(file, chequebook)` in this process.
#[derive(Default)]
struct OutboundState {
    cumulatives: HashMap<String, U256>,
    /// Sum of `cumulatives`, kept up to date so the funds check on the
    /// pay path is O(1).
    total: U256,
    /// The file couldn't be read (an I/O error, not "missing"), so the
    /// chequebook's recorded cumulatives are unknown. Nothing is written
    /// and no cheque is issued until a read succeeds
    /// ([`OutboundLedger::ensure_readable`]): starting from zero would
    /// let the next write erase the file's figures and the next cheque
    /// repeat a cumulative the peer already holds.
    unread: Option<String>,
}

impl OutboundState {
    /// Raise `beneficiary`'s cumulative to `v` (cumulatives only grow)
    /// and return the figure it holds now.
    fn raise(&mut self, beneficiary: String, v: U256) -> U256 {
        let cur = self.cumulatives.entry(beneficiary).or_default();
        if v > *cur {
            self.total = self.total.saturating_add(v - *cur);
            *cur = v;
        }
        *cur
    }
}

/// Fewest journal lines that trigger a compaction; above it, the journal
/// may grow to as many lines as the file has entries, so the cost of
/// compacting stays proportional to the cheques that paid for it.
pub const COMPACT_MIN_LINES: u64 = 4096;

/// After a compaction fails (the file can't be read, say), wait this
/// long before the next try, instead of retrying at every cheque.
const COMPACT_RETRY: std::time::Duration = std::time::Duration::from_secs(10);

/// `<name><suffix>` next to `path`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// The journal cheques are appended to: `<name>.journal`.
fn journal_path(path: &Path) -> PathBuf {
    sibling(path, ".journal")
}

/// A journal being compacted: `<name>.journal.old`.
fn journal_old_path(path: &Path) -> PathBuf {
    sibling(path, ".journal.old")
}

/// fsync `path`'s directory, so a file created or renamed in it is still
/// there after a crash.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The journal of one ledger file, shared by every chequebook's ledger
/// on it in this process (see [`OutboundLedger`]). Lock order: the file
/// lock ([`OUTBOUND_FILE_LOCK`]) before `io`, `io` before `queue`; a
/// ledger's state lock may be held while staging (`queue`), never while
/// writing (`io`).
struct JournalStore {
    /// The ledger file the journal belongs to.
    path: PathBuf,
    /// Lines staged and not yet written.
    queue: Mutex<JournalQueue>,
    /// The open journal. Held across one append + fsync: whoever holds it
    /// writes every line staged so far (group commit).
    io: Mutex<JournalIo>,
    /// Lines up to this sequence number are on disk.
    durable: AtomicU64,
    /// Entries in the file as last read or written; the compaction
    /// threshold.
    snapshot_entries: AtomicU64,
    /// A compaction is running in the background.
    compacting: AtomicBool,
    /// When the last compaction failed.
    compact_failed: Mutex<Option<std::time::Instant>>,
}

#[derive(Default)]
struct JournalQueue {
    buf: Vec<u8>,
    lines: u64,
    /// Sequence number of the last line staged.
    staged: u64,
}

#[derive(Default)]
struct JournalIo {
    file: Option<std::fs::File>,
    /// Lines in the current journal.
    lines: u64,
    /// The ledger's files were (or are about to be) moved away from its
    /// path by someone else — an account switch parking the data dir
    /// ([`hold_ledger_files`], PR #141 R1-M1/R2-F1): this store no longer
    /// owns the path. Its handle is closed and it never writes, reopens,
    /// compacts or folds anything again: the path belongs to whoever is
    /// there now, and the moved files may come back to it later (a switch
    /// back), where a handle kept open would be a second writer next to
    /// the store that reopens them. A cheque staged on it fails instead
    /// of going out.
    retired: bool,
    /// Bytes in the current journal up to its last durable group commit.
    len: u64,
    /// The last durable commit mark in the current journal (see
    /// [`journal_intact_len`]). Advanced only once a group commit is
    /// synced: a write that fails is cut off before the retry
    /// ([`Self::resume`]), so the retry takes the failed write's number
    /// and its mark follows the last durable one with no gap — a crash
    /// tearing the retry then reads as a torn tail, not damage
    /// (PR #141 R5-M1).
    marks: u64,
    /// A write failed and its handle was dropped: where the journal ends
    /// as far as anything acknowledged goes. The next open cuts it back
    /// to there (PR #141 R4-F1).
    resume: Option<Resume>,
}

/// See [`JournalIo::resume`].
struct Resume {
    /// The journal's length at its last durable group commit.
    len: u64,
    /// The journal it is about, so it is never applied to another file
    /// that took the path.
    file: std::fs::Metadata,
    /// [`JournalIo::marks`] at the failure: the last durable mark, the
    /// failed write's own not counted.
    marks: u64,
}

impl JournalIo {
    /// See [`Self::retired`].
    fn retire(&mut self) {
        self.retired = true;
        self.close();
    }

    /// Drop the handle on a journal that was moved away (compacted,
    /// quarantined, retired): the next open starts on whatever is at the
    /// path then.
    fn close(&mut self) {
        self.file = None;
        self.lines = 0;
        self.len = 0;
        self.marks = 0;
        self.resume = None;
    }

    /// Append `buf` (whole lines) to the journal as one group commit and
    /// fsync it. On error the handle is dropped, and reopening it cuts the
    /// journal back to its last durable commit: the failed write's bytes
    /// may read back fine now (from the page cache) and be zeros after a
    /// crash, and a retry appended after them would put an acknowledged
    /// commit behind a zeroed range that [`journal_intact_len`] could read
    /// as the torn tail of one write (PR #141 R4-F1). It also means a
    /// retry never glues a line onto a torn one.
    fn append(&mut self, path: &Path, buf: &[u8]) -> std::io::Result<()> {
        use std::io::{Read, Seek, Write};
        if self.file.is_none() {
            if self.retired {
                return Err(retired_error());
            }
            let jp = journal_path(path);
            if let Some(parent) = jp.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let existed = jp.try_exists()?;
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&jp)?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            let resume = self.resume.as_ref().filter(|r| {
                usize::try_from(r.len).is_ok_and(|n| n <= bytes.len())
                    && f.metadata().is_ok_and(|m| same_file(&m, &r.file))
            });
            let (good, marks) = if let Some(r) = resume {
                (usize::try_from(r.len).expect("checked above"), r.marks)
            } else {
                let good = journal_intact_len(&bytes);
                if bytes[good..].contains(&0) {
                    keep_torn_copy(&jp, &bytes)?;
                }
                let marks = bytes[..good]
                    .rsplit(|b| *b == b'\n')
                    .find_map(commit_mark)
                    .unwrap_or(0);
                (good, marks)
            };
            if good != bytes.len() {
                f.set_len(good as u64)?;
            }
            f.seek(std::io::SeekFrom::Start(good as u64))?;
            if !existed {
                sync_parent_dir(&jp)?;
            }
            // Once per opened handle, not per cheque. Cheque lines only,
            // not the commit marks.
            let lines = bytes[..good]
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty() && commit_mark(l).is_none())
                .count();
            self.lines = lines as u64;
            self.len = good as u64;
            self.marks = marks;
            self.resume = None;
            self.file = Some(f);
        }
        let f = self.file.as_mut().expect("opened above");
        // The commit mark closes the group commit: see
        // [`journal_intact_len`].
        // `marks` advances only once this commit is durable: see
        // [`Self::marks`].
        let mark = self.marks + 1;
        let mut group = Vec::with_capacity(buf.len() + 24);
        group.extend_from_slice(buf);
        group.extend_from_slice(format!("#{mark}\n").as_bytes());
        let written = f
            .write_all(&group)
            .and_then(|()| f.sync_data())
            .and_then(|()| sync_failure_hook());
        if written.is_ok() {
            self.len += group.len() as u64;
            self.marks = mark;
        } else {
            // Without the handle's metadata the next open can't be sure
            // it reopened this file, and falls back to
            // `journal_intact_len`: the failed write's mark is then still
            // in the file, so the retry's comes after a gap, and a crash
            // zeroing the failed write reads as damage (a loss), never as
            // a torn tail.
            self.resume = f.metadata().ok().map(|file| Resume {
                len: self.len,
                file,
                marks: self.marks,
            });
            self.file = None;
        }
        written
    }
}

/// The error a retired journal store ([`JournalIo::retired`]) fails with.
fn retired_error() -> std::io::Error {
    std::io::Error::other(
        "the outbound ledger's files were moved away from its path (account \
         switched); this ledger no longer writes them",
    )
}

/// How much of a journal's bytes is intact: the complete lines before
/// the first one a crash may have torn. A last line without its newline
/// was cut off mid-write; so was a line holding a NUL byte, which no
/// journal line ever does — a filesystem that zero-fills the extents of
/// a write not yet synced (XFS, ext4 without `data=ordered`) leaves
/// those after a crash, possibly with a later part of the same write
/// intact after them (PR #141 R2-M3).
///
/// That can only be the last group commit: every append is fsynced
/// before the next starts, a failed one is cut off before the retry
/// ([`JournalIo::append`], PR #141 R4-F1), and each one ends in a commit
/// mark, `#<n>`, numbered from 1 in each journal. So a NUL is a torn
/// write only when the marks around it say so: no mark after it, or
/// exactly one — the file's last line — numbered one past the last mark
/// before it. Everything from the NUL's line on then belongs to that
/// one write, which was never acknowledged (no cheque went out on it)
/// and is dropped whole. Any other mark after a NUL means synced,
/// acknowledged lines were zeroed — a later commit followed, or a mark
/// is missing because the zeroed range swallowed the end of an earlier
/// commit (PR #141 R4-M1) — and cheques went out on them: that is
/// damage, not a torn write, so every complete line is kept for
/// [`load_journal`] to find the damaged one and quarantine the journal
/// as a loss (PR #141 R3-F1). Damage that runs to the end of the file,
/// taking every later mark with it, can't be told from a torn write and
/// still reads as torn; the dropped bytes are kept in a copy then
/// ([`keep_torn_copy`]).
fn journal_intact_len(bytes: &[u8]) -> usize {
    let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let Some(nul) = bytes[..complete].iter().position(|b| *b == 0) else {
        return complete;
    };
    let line_start = bytes[..nul]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let before = bytes[..line_start]
        .rsplit(|b| *b == b'\n')
        .find_map(commit_mark)
        .unwrap_or(0);
    // The lines after the NUL's own line (it ends before `complete`).
    let after_start = nul
        + bytes[nul..complete]
            .iter()
            .position(|b| *b == b'\n')
            .expect("`complete` ends in a newline")
        + 1;
    let after = &bytes[after_start..complete];
    let marks: Vec<u64> = after
        .split(|b| *b == b'\n')
        .filter_map(commit_mark)
        .collect();
    let last_line = after
        .strip_suffix(b"\n")
        .and_then(|a| a.rsplit(|b| *b == b'\n').next());
    let torn = match marks[..] {
        [] => true,
        [only] => only == before + 1 && last_line.and_then(commit_mark) == Some(only),
        _ => false,
    };
    if torn {
        line_start
    } else {
        complete
    }
}

/// The number of a commit mark line (`#<n>`, see [`journal_intact_len`]).
fn commit_mark(line: &[u8]) -> Option<u64> {
    let digits = line.strip_prefix(b"#")?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// Copy `bytes`, the journal `part` holding a zeroed range about to be
/// dropped as a torn write, to `<part>.torn-<unix secs>[-n]` first: if it
/// was damage instead (see [`journal_intact_len`]), what is left of the
/// lines stays for whoever wants to look (PR #141 R4-M1). Not a loss and
/// no marker — nothing on record says those lines were acknowledged.
/// Fails, and nothing is dropped, if the copy can't be written.
fn keep_torn_copy(part: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let copy = free_aside_name(part, "torn")
        .ok_or_else(|| std::io::Error::other("no free name for a copy of a torn journal"))?;
    std::fs::write(&copy, bytes)?;
    std::fs::File::open(&copy)?.sync_all()?;
    sync_parent_dir(&copy)?;
    warn!(
        target: "ant_p2p::swap",
        file = %part.display(),
        copy = %copy.display(),
        "outbound ledger: the cheque journal ends in a zero-filled range a crash \
         left in its last, unacknowledged write; dropping it (a copy is kept)",
    );
    Ok(())
}

/// A name `<part>.<tag>-<unix secs>[-n]` next to `part` that no file has.
/// `rename` replaces an existing file, so a name is never reused: a
/// second move within the same second would lose the first copy (PR #126
/// R4-M2). Callers hold `OUTBOUND_FILE_LOCK`, so nothing in this process
/// takes the name between the check and its use.
fn free_aside_name(part: &Path, tag: &str) -> Option<PathBuf> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (0u32..1000)
        .map(|n| {
            let mut name = part.file_name().unwrap_or_default().to_os_string();
            name.push(format!(".{tag}-{secs}"));
            if n > 0 {
                name.push(format!("-{n}"));
            }
            part.with_file_name(name)
        })
        .find(|p| matches!(p.try_exists(), Ok(false)))
}

/// `a` and `b` are the same file (inode); always true where that can't
/// be told.
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        true
    }
}

/// Live journals by ledger file. Guarded by [`OUTBOUND_FILE_LOCK`].
static JOURNALS: Mutex<Vec<(PathBuf, Weak<JournalStore>)>> = Mutex::new(Vec::new());

/// The live journal on `path`, if any.
fn live_journal(path: &Path) -> Option<Arc<JournalStore>> {
    JOURNALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(p, _)| p == path)
        .and_then(|(_, w)| w.upgrade())
}

#[cfg(test)]
thread_local! {
    /// Test hook: make compactions on this thread stop with an error
    /// right after step `n` (1: journal renamed, 2: file rewritten).
    static COMPACT_STOP_AFTER: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn compact_step(n: u8) -> std::io::Result<()> {
    if COMPACT_STOP_AFTER.with(std::cell::Cell::get) == n {
        return Err(std::io::Error::other(format!(
            "test: compaction stopped after step {n}"
        )));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test hook: the next journal fsync on this thread reports an error
    /// after the bytes were written, like an `EIO` from `fsync`.
    static FAIL_NEXT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn sync_failure_hook() -> std::io::Result<()> {
    if FAIL_NEXT_SYNC.with(|f| f.replace(false)) {
        return Err(std::io::Error::other("test: fsync failed"));
    }
    Ok(())
}

/// Test hook (see `FAIL_NEXT_SYNC`); never fails outside tests.
#[cfg(not(test))]
#[allow(clippy::unnecessary_wraps)]
#[inline]
fn sync_failure_hook() -> std::io::Result<()> {
    Ok(())
}

/// Test hook (see `COMPACT_STOP_AFTER`); never fails outside tests.
#[cfg(not(test))]
#[allow(clippy::unnecessary_wraps)]
#[inline]
fn compact_step(_n: u8) -> std::io::Result<()> {
    Ok(())
}

impl JournalStore {
    /// The journal on `path`, shared with live ledgers on it. A new one
    /// (first ledger on the file in this process) folds journals a
    /// previous run left behind into the file. Caller holds
    /// [`OUTBOUND_FILE_LOCK`].
    fn for_path(path: &Path) -> Arc<Self> {
        if let Some(live) = live_journal(path) {
            if !live.retire_if_moved() {
                return live;
            }
            warn!(
                target: "ant_p2p::swap",
                file = %path.display(),
                "outbound ledger: the cheque journal still open from an earlier ledger \
                 was moved away (account switched); starting a new one on this path",
            );
            // Possibly its last owner: closing it folds, under the lock
            // this thread holds (PR #141 R2-M2).
            release_after_unlock(live);
        }
        let store = Arc::new(Self {
            path: path.to_path_buf(),
            queue: Mutex::default(),
            io: Mutex::default(),
            durable: AtomicU64::new(0),
            snapshot_entries: AtomicU64::new(0),
            compacting: AtomicBool::new(false),
            compact_failed: Mutex::new(None),
        });
        {
            let mut reg = JOURNALS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.retain(|(p, w)| p != path && w.strong_count() > 0);
            reg.push((path.to_path_buf(), Arc::downgrade(&store)));
        }
        if let Err(e) = store.compact_locked() {
            warn!(
                target: "ant_p2p::swap",
                file = %path.display(),
                "outbound ledger: can't fold the cheque journal into the file: {e}; \
                 it is kept and read along with the file",
            );
        }
        store
    }

    /// Whether this store's open journal is no longer the file at its
    /// path — moved away outside this process's ledger code, which only
    /// ever moves the journal with the handle closed (an account switch
    /// parks the data dir while a blocking cheque write outlived the
    /// node's shutdown, and nothing held the files for the move with
    /// [`hold_ledger_files`]). Retires the store if so (closing its
    /// handle, see [`JournalIo::retired`]), and a new store takes the
    /// path.
    /// Caller holds [`OUTBOUND_FILE_LOCK`].
    fn retire_if_moved(&self) -> bool {
        let mut io = self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if io.retired {
            return true;
        }
        let Some(f) = &io.file else {
            return false;
        };
        let moved = match (f.metadata(), std::fs::metadata(journal_path(&self.path))) {
            (Ok(open), Ok(at_path)) => !same_file(&open, &at_path),
            (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => true,
            // Can't tell: keep using it, as before.
            _ => false,
        };
        if moved {
            io.retire();
        }
        moved
    }

    /// See [`JournalIo::retired`].
    fn is_retired(&self) -> bool {
        self.io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retired
    }

    /// Stage `entries` (`<chequebook>:<beneficiary>` → cumulative) as
    /// journal lines. Returns the sequence number to wait for.
    fn stage<'a>(&self, entries: impl IntoIterator<Item = (&'a str, &'a str, U256)>) -> u64 {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (chequebook, beneficiary, v) in entries {
            q.buf.extend_from_slice(
                format!("{{\"{chequebook}:{beneficiary}\":\"{v}\"}}\n").as_bytes(),
            );
            q.lines += 1;
            q.staged += 1;
        }
        q.staged
    }

    fn is_durable(&self, seq: u64) -> bool {
        self.durable.load(Ordering::SeqCst) >= seq
    }

    /// Block until every line up to `seq` is on disk, writing it (and
    /// everything else staged) unless a concurrent caller already did.
    fn commit(self: &Arc<Self>, seq: u64) -> std::io::Result<()> {
        if self.is_durable(seq) {
            return Ok(());
        }
        let mut io = self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_durable(seq) {
            return Ok(());
        }
        let (buf, lines, upto) = {
            let mut q = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lines = std::mem::take(&mut q.lines);
            (std::mem::take(&mut q.buf), lines, q.staged)
        };
        if let Err(e) = io.append(&self.path, &buf) {
            // Put the lines back in front of anything staged since, for
            // the next commit to retry.
            let mut q = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut back = buf;
            back.extend_from_slice(&q.buf);
            q.buf = back;
            q.lines += lines;
            return Err(e);
        }
        self.durable.store(upto, Ordering::SeqCst);
        io.lines += lines;
        let due = io.lines >= COMPACT_MIN_LINES.max(self.snapshot_entries.load(Ordering::SeqCst));
        drop(io);
        if due {
            self.compact_in_background();
        }
        Ok(())
    }

    /// Compact on a thread of its own, so no cheque waits for it.
    fn compact_in_background(self: &Arc<Self>) {
        let recently_failed = self
            .compact_failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|t| t.elapsed() < COMPACT_RETRY);
        if recently_failed || self.compacting.swap(true, Ordering::SeqCst) {
            return;
        }
        let store = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("ledger-compact".into())
            .spawn(move || {
                let r = {
                    let _file = lock_file();
                    store.compact_locked()
                };
                if let Err(e) = r {
                    warn!(
                        target: "ant_p2p::swap",
                        file = %store.path.display(),
                        "outbound ledger: compaction failed: {e}; the cheque journal is \
                         kept and retried later",
                    );
                    *store
                        .compact_failed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(std::time::Instant::now());
                }
                store.compacting.store(false, Ordering::SeqCst);
            });
        if spawned.is_err() {
            self.compacting.store(false, Ordering::SeqCst);
        }
    }

    /// Fold the journal into the file (see [`OutboundLedger`]). Caller
    /// holds [`OUTBOUND_FILE_LOCK`]. A `.journal.old` left by an earlier,
    /// interrupted compaction is folded first, then the current journal.
    fn compact_locked(&self) -> std::io::Result<()> {
        if self.is_retired() {
            return Ok(());
        }
        loop {
            let old = journal_old_path(&self.path);
            let leftover = old.try_exists()?;
            if !leftover {
                let jp = journal_path(&self.path);
                let mut io = self
                    .io
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !jp.try_exists()? {
                    return Ok(());
                }
                std::fs::rename(&jp, &old)?;
                io.close();
            }
            compact_step(1)?;
            // Read like an open does: an unreadable file fails the
            // compaction (and the journal stays), an unparseable one is
            // moved aside.
            let mut file = read_outbound_file(&self.path)?.unwrap_or_default();
            for line in load_journal(&self.path, &old)? {
                file.merge_flat(line);
            }
            write_outbound_file(&self.path, &file)?;
            sync_parent_dir(&self.path)?;
            compact_step(2)?;
            self.snapshot_entries
                .store(file.entries() as u64, Ordering::SeqCst);
            match std::fs::remove_file(&old) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
            if !leftover {
                return Ok(());
            }
        }
    }
}

impl Drop for JournalStore {
    /// The last ledger on the file closed: write out anything still
    /// staged and fold the journal into the file, so a downgraded release
    /// finds every cheque there. Nothing for a retired store (its path
    /// is someone else's now). Code holding the file lock never drops
    /// its last reference (it hands it to [`release_after_unlock`]); if
    /// that slips, this is skipped (the journal stays, and the next open
    /// folds it) rather than deadlocking on the lock or folding in the
    /// middle of a read or a move.
    fn drop(&mut self) {
        if self
            .io
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retired
        {
            return;
        }
        if HOLDS_FILE_LOCK.with(std::cell::Cell::get) {
            debug_assert!(false, "last JournalStore dropped under the file lock");
            return;
        }
        let _file = lock_file();
        let io = self
            .io
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let q = self
            .queue
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !q.buf.is_empty() {
            if let Err(e) = io.append(&self.path, &q.buf) {
                warn!(
                    target: "ant_p2p::swap",
                    file = %self.path.display(),
                    "outbound ledger: can't journal {} cheque line(s) at close: {e}",
                    q.lines,
                );
            }
        }
        if let Err(e) = self.compact_locked() {
            warn!(
                target: "ant_p2p::swap",
                file = %self.path.display(),
                "outbound ledger: can't fold the cheque journal into the file at close: {e}; \
                 it is kept and read along with the file",
            );
        }
    }
}

/// Read the journal `part` of the ledger at `path`: one flat map per
/// line. A torn tail ([`journal_intact_len`]: a last line without its
/// newline, or a NUL-filled range a crash left) was cut off mid-write and
/// never confirmed (no cheque went out on it), so it is skipped; any other line
/// that doesn't parse, or holds a cumulative that isn't a decimal number
/// ([`bad_cumulative`]), means the journal is damaged, and it is moved aside
/// like an unparseable file (its figures count as lost), reading as empty.
/// `Ok(vec![])` when it doesn't exist; an I/O error is returned.
fn load_journal(path: &Path, part: &Path) -> std::io::Result<Vec<HashMap<String, String>>> {
    let bytes = match std::fs::read(part) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let complete = journal_intact_len(&bytes);
    if bytes[complete..].contains(&0) {
        keep_torn_copy(part, &bytes)?;
    }
    let mut lines = Vec::new();
    for (n, line) in bytes[..complete].split(|b| *b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) || commit_mark(line).is_some() {
            continue;
        }
        match serde_json::from_slice::<HashMap<String, String>>(line) {
            Ok(m) => {
                if let Some(bad) = bad_cumulative(&m) {
                    quarantine_outbound_file(path, part, &format!("line {}: {bad}", n + 1))?;
                    return Ok(Vec::new());
                }
                lines.push(m);
            }
            Err(e) => {
                quarantine_outbound_file(path, part, &format!("line {}: {e}", n + 1))?;
                return Ok(Vec::new());
            }
        }
    }
    Ok(lines)
}

/// A cheque recorded in memory whose journal line may not be on disk
/// yet. Send the cheque only after [`Self::durable`] (or [`Self::wait`])
/// returned `Ok`: then a crash can't forget it.
#[must_use = "a cheque may only be sent once its record is durable"]
pub struct PendingWrite {
    pending: Option<Pending>,
}

struct Pending {
    store: Arc<JournalStore>,
    seq: u64,
    /// The ledger's figures survived a loss and this write rewrote all of
    /// them: once durable, record the chequebook as known in the marker.
    /// Holds the ledger's state alive meanwhile, so a ledger reopened on
    /// the chequebook shares it instead of reading the file without this
    /// line.
    shared: Arc<OutboundShared>,
    note_known: Option<(String, u64)>,
}

impl std::fmt::Debug for PendingWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingWrite")
            .field("seq", &self.pending.as_ref().map(|p| p.seq))
            .finish()
    }
}

impl PendingWrite {
    /// Block until the record is on disk.
    pub fn wait(self) -> std::io::Result<()> {
        let Some(p) = self.pending else {
            return Ok(());
        };
        p.store.commit(p.seq)?;
        if let Some((chequebook, generation)) = p.note_known {
            let _file = lock_file();
            // The files moved away (account switch) since: the marker at
            // the path is another account's.
            if p.store.is_retired() {
                return Ok(());
            }
            // Not if another loss came in since this rewrite was staged:
            // the rewrite may have been moved aside with the journal, so
            // the chequebook is still lost on disk (and stays flagged, to
            // be rewritten again at its next cheque). Losses are recorded
            // under the file lock held here, so none can slip in between
            // this check and the marker update.
            if p.shared.loss_gen.load(Ordering::SeqCst) != generation {
                return Ok(());
            }
            match note_known(&p.store.path, &chequebook) {
                Ok(()) => p.shared.survived_loss.store(false, Ordering::SeqCst),
                Err(e) => warn!(
                    target: "ant_p2p::swap",
                    chequebook = %chequebook,
                    "can't record in the lost-ledger marker that this chequebook's \
                     figures were rewritten: {e}; retrying at its next cheque",
                ),
            }
        }
        Ok(())
    }

    /// [`Self::wait`] on the blocking pool, unless it is already on disk
    /// (a concurrent cheque's fsync covered it).
    pub async fn durable(self) -> std::io::Result<()> {
        match &self.pending {
            None => return Ok(()),
            Some(p) if p.note_known.is_none() && p.store.is_durable(p.seq) => return Ok(()),
            Some(_) => {}
        }
        tokio::task::spawn_blocking(move || self.wait())
            .await
            .map_err(std::io::Error::other)?
    }
}

/// The outbound ledger file, read into sections: `chequebook hex →
/// (beneficiary hex → cumulative as a decimal string)`, with bare
/// (pre-section) entries under the empty key until a chequebook adopts
/// them. On disk it is flat (see [`OutboundLedger`] and
/// [`write_outbound_file`]); this nested shape was only written by
/// unreleased builds of PR #126 and is still read.
#[derive(Default, Serialize, Deserialize)]
struct OutboundFile {
    chequebooks: HashMap<String, HashMap<String, String>>,
}

impl OutboundFile {
    /// Split a flat on-disk map into sections.
    fn from_flat(flat: HashMap<String, String>) -> Self {
        let mut file = Self::default();
        for (k, v) in flat {
            let (chequebook, beneficiary) = k.split_once(':').unwrap_or(("", k.as_str()));
            file.chequebooks
                .entry(chequebook.to_string())
                .or_default()
                .insert(beneficiary.to_string(), v);
        }
        file
    }

    /// Raise this file's figures to a flat map's (a journal line):
    /// cumulatives only grow.
    fn merge_flat(&mut self, flat: HashMap<String, String>) {
        for (chequebook, entries) in Self::from_flat(flat).chequebooks {
            let section = self.chequebooks.entry(chequebook).or_default();
            for (beneficiary, v) in parse_cumulatives(entries) {
                let cur = section
                    .get(&beneficiary)
                    .and_then(|c| U256::from_dec_str(c).ok());
                if cur.is_none_or(|c| v > c) {
                    section.insert(beneficiary, v.to_string());
                }
            }
        }
    }

    /// Entries in the flat on-disk map.
    fn entries(&self) -> usize {
        self.chequebooks.values().map(HashMap::len).sum()
    }

    /// The flat on-disk map: bare entries keep their bare key.
    fn to_flat(&self) -> HashMap<String, String> {
        self.chequebooks
            .iter()
            .flat_map(|(chequebook, section)| {
                section.iter().map(move |(beneficiary, v)| {
                    let key = if chequebook.is_empty() {
                        beneficiary.clone()
                    } else {
                        format!("{chequebook}:{beneficiary}")
                    };
                    (key, v.clone())
                })
            })
            .collect()
    }
}

/// Serialises read-modify-write of outbound ledger files across every
/// ledger in the process (two services — an old chequebook's still
/// finishing a cheque, the new one's — can share one file), and guards
/// [`OUTBOUND_LEDGERS`] and [`JOURNALS`]. Taken before a ledger's state
/// lock, never after; recording a cheque doesn't take it at all.
static OUTBOUND_FILE_LOCK: Mutex<()> = Mutex::new(());

/// Live ledger states by `(file, chequebook)`. A second ledger opened on
/// the same chequebook and file while the first is alive (settlement
/// disabled and re-enabled while the old service still finishes a
/// cheque) shares the first one's state instead of keeping its own copy,
/// so neither can write back a stale cumulative over the other's newer
/// one. Guarded by [`OUTBOUND_FILE_LOCK`].
type OutboundRegistry = Vec<((PathBuf, [u8; 20]), Weak<OutboundShared>)>;
static OUTBOUND_LEDGERS: Mutex<OutboundRegistry> = Mutex::new(Vec::new());

fn parse_cumulatives(map: HashMap<String, String>) -> HashMap<String, U256> {
    map.into_iter()
        .filter_map(|(k, v)| U256::from_dec_str(&v).ok().map(|u| (k, u)))
        .collect()
}

/// The live ledgers on `path` whose figures are complete in memory right
/// now, so a loss of the file about to happen spares them (see
/// [`OutboundShared::survived_loss`]): loaded from the file, *and* not
/// already lost to an earlier, unconfirmed loss — a ledger loaded after
/// that loss holds only what it issued since, and must stay lost through
/// the next one (PR #126 R2-F1). Call before recording the new loss;
/// flag the result with [`flag_survivors`] once it is recorded. `except`
/// is never a survivor. Caller
/// holds [`OUTBOUND_FILE_LOCK`] and not [`OUTBOUND_LEDGERS`].
fn known_survivors(path: &Path, except: Option<[u8; 20]>) -> Vec<Arc<OutboundShared>> {
    let live: Vec<_> = OUTBOUND_LEDGERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|((p, chequebook), _)| p == path && Some(*chequebook) != except)
        .filter_map(|((_, chequebook), w)| Some((*chequebook, w.upgrade()?)))
        .collect();
    let (known, other): (Vec<_>, Vec<_>) = live.into_iter().partition(|(chequebook, shared)| {
        shared.loaded.load(Ordering::SeqCst)
            && (shared.survived_loss.load(Ordering::SeqCst)
                || lost_figures_at(path, chequebook).is_none())
    });
    // The caller holds the file lock; any of these may be the last
    // reference (PR #141 R2-M2).
    release_after_unlock(other);
    known.into_iter().map(|(_, shared)| shared).collect()
}

/// Mark `survivors` (from [`known_survivors`]) as having survived the
/// loss just recorded.
fn flag_survivors(survivors: &[Arc<OutboundShared>]) {
    for shared in survivors {
        shared.loss_gen.fetch_add(1, Ordering::SeqCst);
        shared.survived_loss.store(true, Ordering::SeqCst);
    }
}

/// Read `path`. `Ok(None)` when it doesn't exist. A file that is
/// neither shape, or holds a cumulative that isn't a decimal number
/// ([`bad_cumulative`]), is moved aside (see [`OutboundLedger`]) and reads as
/// missing; an I/O error, which may pass, is returned.
fn read_outbound_file(path: &Path) -> std::io::Result<Option<OutboundFile>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let file = match serde_json::from_slice::<HashMap<String, String>>(&bytes) {
        Ok(flat) => {
            if let Some(bad) = bad_cumulative(&flat) {
                quarantine_outbound_file(path, path, &bad)?;
                return Ok(None);
            }
            OutboundFile::from_flat(flat)
        }
        Err(e) => {
            let Ok(nested) = serde_json::from_slice::<OutboundFile>(&bytes) else {
                quarantine_outbound_file(path, path, &e)?;
                return Ok(None);
            };
            nested
        }
    };
    if let Some(bad) = file.chequebooks.values().find_map(bad_cumulative) {
        quarantine_outbound_file(path, path, &bad)?;
        return Ok(None);
    }
    Ok(Some(file))
}

/// The first entry of a stored `key → cumulative` map whose cumulative
/// isn't a decimal number that fits a `U256` (empty, a sign, an exponent,
/// any non-digit, too large), described for the quarantine message. Such
/// an entry can't be skipped as absent: its cheques would restart from
/// zero (`0 + amount`, which the peer rejects as not increasing), the
/// issued total would read low, and the next write would replace the
/// real figure with the lower one (bee#5656). The ledger it is in is
/// moved aside instead, its figures lost, like unparseable JSON.
fn bad_cumulative(map: &HashMap<String, String>) -> Option<String> {
    map.iter()
        .find(|(_, v)| parse_stored_cumulative(v).is_none())
        .map(|(k, v)| format!("entry {k:?} has cumulative {v:?}, not a decimal number"))
}

/// Move `part` — the outbound ledger at `path` or one of its journals —
/// out of the way as unparseable, keeping it for whoever wants to look at
/// it, and record that the figures of every chequebook on the file are
/// lost. Fails (and the file stays, unread) only if it can't be moved.
fn quarantine_outbound_file(
    path: &Path,
    part: &Path,
    parse_error: &dyn std::fmt::Display,
) -> std::io::Result<()> {
    let aside = free_aside_name(part, "corrupt").ok_or_else(|| {
        std::io::Error::other(format!(
            "unparseable ({parse_error}) and no free name to move it aside to"
        ))
    })?;
    // The marker goes first: a move without it would let retrieval
    // pay from figures we just lost. If it can't be written the file
    // stays where it is, unread, and the move is retried later.
    let survivors = known_survivors(path, None);
    mark_figures_lost(path, &aside).map_err(|e| {
        std::io::Error::other(format!(
            "unparseable ({parse_error}) and can't record that its figures are lost: {e}"
        ))
    })?;
    flag_survivors(&survivors);
    release_after_unlock(survivors);
    // The live journal is moved with its handle closed, so no cheque is
    // appended to the copy set aside.
    let live = (part == journal_path(path))
        .then(|| live_journal(path))
        .flatten();
    let mut io = live.as_ref().map(|j| {
        j.io.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    std::fs::rename(part, &aside).map_err(|e| {
        std::io::Error::other(format!(
            "unparseable ({parse_error}) and can't be moved aside: {e}"
        ))
    })?;
    if let Some(io) = io.as_mut() {
        io.close();
    }
    drop(io);
    release_after_unlock(live);
    warn!(
        target: "ant_p2p::swap",
        file = %part.display(),
        moved_to = %aside.display(),
        "outbound ledger is unparseable ({parse_error}); moved it aside. Its \
         chequebooks' cheque totals are lost: the node pays no cheques, for \
         downloads or uploads (both stay on the free tier), from any chequebook \
         that used this file until an operator confirms its outstanding \
         liability (antd --confirm-cheque-liability <chequebook>, or \
         ant_confirm_cheque_liability)",
    );
    Ok(())
}

/// The marker [`quarantine_outbound_file`] leaves next to a ledger file
/// whose figures were lost: `<name>.lost`.
fn lost_marker_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lost");
    path.with_file_name(name)
}

/// The `<name>.lost` marker: where the lost figures were moved, the
/// chequebooks whose outstanding liability an operator has confirmed
/// since the last loss, and the ones whose figures are known without an
/// operator (deployed after the loss, or rewritten from memory that
/// outlived it).
#[derive(Default, Clone, Serialize, Deserialize)]
struct LostMarker {
    #[serde(default)]
    moved_aside: Vec<String>,
    #[serde(default)]
    confirmed: Vec<String>,
    #[serde(default)]
    known: Vec<String>,
}

impl LostMarker {
    fn clears(&self, key: &str) -> bool {
        self.confirmed
            .iter()
            .chain(&self.known)
            .any(|c| c.eq_ignore_ascii_case(key))
    }

    /// The marker that replaces one we can't parse: a loss is on record,
    /// but neither where it went nor who was confirmed is known. The
    /// entry is stamped with when it was written, so it never reads the
    /// same as a list of losses on record before (PR #156 R5-M2).
    fn replacing_unreadable(e: &std::io::Error) -> Self {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            moved_aside: vec![format!(
                "unknown: the previous marker was unreadable ({e}); replaced at {at}"
            )],
            ..Self::default()
        }
    }
}

/// Read the marker. `Ok(None)` when there is none; a marker that isn't
/// valid JSON is an `InvalidData` error, any other error is I/O (and may
/// pass).
fn read_lost_marker(path: &Path) -> std::io::Result<Option<LostMarker>> {
    match std::fs::read(lost_marker_path(path)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// What identifies one version of the marker file: `None` when there is
/// none. A rewrite replaces the file (a new inode), and a hand edit
/// changes its length or mtime.
type MarkerStamp = Option<(u64, u64, Option<std::time::SystemTime>)>;

fn marker_stamp(marker_path: &Path) -> std::io::Result<MarkerStamp> {
    match std::fs::metadata(marker_path) {
        Ok(m) => {
            #[cfg(unix)]
            let ino = std::os::unix::fs::MetadataExt::ino(&m);
            #[cfg(not(unix))]
            let ino = 0;
            Ok(Some((ino, m.len(), m.modified().ok())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The last marker read per marker path, with the stamp it was read at.
type MarkerCache = HashMap<PathBuf, (MarkerStamp, Result<Option<LostMarker>, String>)>;
static LOST_MARKERS: Mutex<Option<MarkerCache>> = Mutex::new(None);

/// [`read_lost_marker`] for the hot readers ([`OutboundLedger::lost_figures`]
/// runs on the swarm loop and before every retrieval cheque): no
/// [`OUTBOUND_FILE_LOCK`], so it never waits behind a ledger rewrite's
/// fsync (the marker is only ever replaced whole, by rename), and the
/// file is parsed again only when it changed — usually all it costs is
/// a `stat` of a file that doesn't exist (PR #126 R1-M1).
fn cached_lost_marker(path: &Path) -> Result<Option<LostMarker>, String> {
    let marker_path = lost_marker_path(path);
    let stamp = marker_stamp(&marker_path).map_err(|e| e.to_string())?;
    let mut cache = LOST_MARKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some((s, m)) = cache.get(&marker_path) {
        if *s == stamp {
            return m.clone();
        }
    }
    let read = match stamp {
        None => Ok(None),
        Some(_) => match read_lost_marker(path) {
            Err(e) if e.kind() != std::io::ErrorKind::InvalidData => {
                // An I/O error may pass: don't remember it.
                return Err(e.to_string());
            }
            r => r.map_err(|e| e.to_string()),
        },
    };
    cache.insert(marker_path, (stamp, read.clone()));
    read
}

fn write_lost_marker(path: &Path, marker: &LostMarker) -> std::io::Result<()> {
    use std::io::Write;
    let marker_path = lost_marker_path(path);
    let mut tmp_name = marker_path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = marker_path.with_file_name(tmp_name);
    let bytes = serde_json::to_vec_pretty(marker).map_err(std::io::Error::other)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &marker_path)?;
    if let Some(cache) = LOST_MARKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        cache.remove(&marker_path);
    }
    Ok(())
}

/// Record that `path`'s figures were lost (moved to `aside`): every
/// chequebook on it is unknown again, including ones confirmed after an
/// earlier loss. An earlier marker that can't be parsed is replaced (the
/// new one confirms nothing either, so that only ever widens the loss);
/// one that can't be read for another reason fails the call, so a
/// passing I/O error doesn't drop the record of earlier losses.
fn mark_figures_lost(path: &Path, aside: &Path) -> std::io::Result<()> {
    mark_figures_lost_sparing(path, &aside.display().to_string(), Vec::new())
}

/// [`mark_figures_lost`], recording the loss as `moved` and keeping
/// `spared` known through it: chequebooks the caller has shown the lost
/// figures can't belong to (and that weren't lost before it).
fn mark_figures_lost_sparing(path: &Path, moved: &str, spared: Vec<String>) -> std::io::Result<()> {
    let mut marker = match read_lost_marker(path) {
        Ok(m) => m.unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            LostMarker::replacing_unreadable(&e)
        }
        Err(e) => return Err(e),
    };
    marker.moved_aside.push(moved.to_string());
    marker.confirmed.clear();
    marker.known = spared;
    write_lost_marker(path, &marker)
}

/// The chequebooks with a section of their own in the ledger at `path`
/// (file and journals), whose figures aren't lost to an earlier,
/// unconfirmed loss. Caller holds [`OUTBOUND_FILE_LOCK`]. While a
/// pre-section ledger is on the file none of them adopted it — a
/// chequebook adopts it on its first load unless it was deployed fresh —
/// so a loss of the pre-section figures alone needn't gate them
/// (PR #156 R3-M2). A marker that can't be read clears none.
fn sectioned_known(path: &Path) -> std::io::Result<Vec<String>> {
    let mut file = read_outbound_file(path)?.unwrap_or_default();
    let mut journaled = load_journal(path, &journal_old_path(path))?;
    journaled.extend(load_journal(path, &journal_path(path))?);
    for line in journaled {
        file.merge_flat(line);
    }
    let marker = read_lost_marker(path);
    Ok(file
        .chequebooks
        .into_keys()
        .filter(|k| !k.is_empty())
        .filter(|k| match &marker {
            Ok(None) => true,
            Ok(Some(m)) => m.clears(k),
            Err(_) => false,
        })
        .collect())
}

/// Record that the pre-section figures in the ledger at `path` may be
/// lost to or misread by some chequebook (`why`), sparing every
/// chequebook that provably doesn't own them ([`sectioned_known`]) and
/// the live ledgers whose figures are complete in memory
/// ([`known_survivors`]), except `except`. Caller holds
/// [`OUTBOUND_FILE_LOCK`].
fn mark_legacy_figures_lost(
    path: &Path,
    why: &str,
    except: Option<[u8; 20]>,
) -> std::io::Result<()> {
    let except_key = except.map(hex::encode);
    let spared: Vec<String> = sectioned_known(path)?
        .into_iter()
        .filter(|k| except_key.as_ref() != Some(k))
        .collect();
    let survivors = known_survivors(path, except);
    mark_figures_lost_sparing(path, why, spared)?;
    flag_survivors(&survivors);
    release_after_unlock(survivors);
    Ok(())
}

/// Prefix of a loss in [`LostMarker::moved_aside`] that isn't a ledger
/// moved aside to the path it names: the rest of the entry says what it
/// was (PR #156 R4-M2).
const NOT_MOVED: &str = "not moved: ";

/// One recorded loss, worded for the operator: a ledger moved aside to
/// the path an entry names, or an entry's own description.
fn describe_loss(entry: &str) -> String {
    if let Some(why) = entry.strip_prefix(NOT_MOVED) {
        why.to_string()
    } else if entry.starts_with("unknown: ") {
        entry.to_string()
    } else {
        format!("the outbound cheque ledger was unparseable and moved aside to {entry}")
    }
}

/// Why `chequebook`'s figures in the ledger at `path` are unknown, or
/// `None` if they are known. A marker that can't be read counts as a
/// loss: the answer gates money.
fn lost_figures_at(path: &Path, chequebook: &[u8; 20]) -> Option<String> {
    let key = hex::encode(chequebook);
    match cached_lost_marker(path) {
        Ok(None) => None,
        Ok(Some(m)) if m.clears(&key) => None,
        Ok(Some(m)) => Some(format!(
            "outbound cheque figures may have been lost ({}), so the cheques \
             chequebook 0x{key} issued before are unknown; downloads and uploads stay \
             on the free tier until an operator confirms its outstanding liability \
             (antd --confirm-cheque-liability 0x{key}, or ant_confirm_cheque_liability)",
            m.moved_aside
                .iter()
                .map(|l| describe_loss(l))
                .collect::<Vec<_>>()
                .join("; "),
        )),
        Err(e) => Some(format!(
            "can't read the lost-ledger marker {} ({e}), so chequebook 0x{key}'s cheque \
             figures count as lost; downloads and uploads stay on the free tier until an operator \
             confirms its outstanding liability (antd --confirm-cheque-liability 0x{key}, \
             or ant_confirm_cheque_liability), which replaces an unparseable marker",
            lost_marker_path(path).display(),
        )),
    }
}

/// The operator's confirmation that `chequebook`'s cheques issued before
/// the ledger at `path` was lost are outstanding liability the node can
/// no longer see — peers it paid before may refuse new cheques, and
/// disconnect it, until the restarted cumulatives pass what they hold —
/// and that retrieval may pay from it again. Clears the chequebook's
/// lost state ([`OutboundLedger::lost_figures`]) until the next loss.
/// Returns `false` when there was nothing to confirm (no loss on record,
/// or this chequebook already confirmed). A marker that can't be parsed
/// is replaced by one that confirms only this chequebook — every other
/// chequebook stays lost — so it never needs deleting by hand; an I/O
/// error is returned. A running node picks it up at its next
/// retrieval-funds read.
pub fn confirm_cheque_liability(path: &Path, chequebook: [u8; 20]) -> std::io::Result<bool> {
    let _file = lock_file();
    let mut marker = match read_lost_marker(path) {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            warn!(
                target: "ant_p2p::swap",
                marker = %lost_marker_path(path).display(),
                "lost-ledger marker is unparseable ({e}); replacing it, every \
                 chequebook but the confirmed one stays lost",
            );
            LostMarker::replacing_unreadable(&e)
        }
        Err(e) => return Err(e),
    };
    let key = hex::encode(chequebook);
    if marker
        .confirmed
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&key))
    {
        return Ok(false);
    }
    marker.confirmed.push(key.clone());
    write_lost_marker(path, &marker)?;
    warn!(
        target: "ant_p2p::swap",
        chequebook = %format!("0x{key}"),
        "operator confirmed the outstanding liability of cheques lost with the \
         outbound ledger; downloads and uploads may pay from this chequebook again",
    );
    Ok(true)
}

/// Record that `chequebook` was just deployed, so it has issued no
/// cheques and a loss of the ledger at `path` recorded before now
/// doesn't apply to it (PR #126 R1-M3). Call right after a successful
/// deploy, before any ledger on the chequebook issues. No-op without a
/// loss on record. A marker that can't be read is left alone (the
/// chequebook stays lost until an operator confirms it) and the error
/// returned.
///
/// It also records `chequebook` as fresh in `<path>.fresh`, so a ledger
/// written before per-chequebook sections is never adopted into it: those
/// cumulatives were issued from some earlier chequebook, and carried into
/// one that has paid nobody they would make its first cheque to each of
/// those beneficiaries claim the old total. Bee credits a cheque as its
/// cumulative minus the last one *from that chequebook*, so the peer
/// would book (and could cash) far more than it was owed, and our own
/// funds check would count the old totals as issued and drain the
/// deposit in minutes. Seen live on 2026-10-12: a fresh 0.01 xBZZ
/// chequebook read as spent two minutes after deploy.
///
/// If the fresh record fails while a pre-section ledger is (or may be)
/// on the file, the chequebook is *not* recorded as known either: it
/// stays behind the loss gate, since after a restart it would adopt
/// those cumulatives (PR #156 R2-M1). With no loss on record a new one
/// is recorded for it, sparing the chequebooks with sections of their
/// own (PR #156 R3-M1). Until a restart this process also remembers it
/// as fresh, so it adopts nothing, and retries the record at each load
/// and, at most every [`FRESH_RETRY_INTERVAL`], from
/// [`OutboundLedger::ensure_readable`] (which runs before every cheque),
/// so it lands even once the ledger is live (PR #156 R5-M1); once it
/// lands, the gate it was put behind is lifted again (PR #156 R4-M1).
/// Without a pre-section ledger the
/// fresh record doesn't matter and the known record is made anyway. The
/// error names which record failed (and the consequence).
pub fn note_fresh_chequebook(path: &Path, chequebook: [u8; 20]) -> std::io::Result<()> {
    let _file = lock_file();
    let key = hex::encode(chequebook);
    let fresh = note_fresh(path, &key).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "can't record it as fresh in {}: {e}; a ledger written before \
                 per-chequebook sections may be adopted into it",
                fresh_marker_path(path).display(),
            ),
        )
    });
    // A failed fresh record only matters if there's a pre-section
    // ledger to adopt; if that can't be read either, assume there is.
    let adoption_risk = fresh.is_err()
        && read_outbound_file(path)
            .map_or(true, |f| f.is_some_and(|f| f.chequebooks.contains_key("")));
    let known = if adoption_risk {
        // Across a restart only the loss gate holds: put one on record
        // for it if there is none (sparing every chequebook that provably
        // doesn't own the pre-section figures). Only the retried fresh
        // record lifts it ([`lift_fresh_gate`]).
        let gated = match read_lost_marker(path) {
            Ok(None) => mark_legacy_figures_lost(
                path,
                &format!(
                    "{NOT_MOVED}chequebook 0x{key} was deployed fresh but couldn't be \
                     recorded as such in {}, so it may adopt the cheque ledger written \
                     before per-chequebook sections",
                    fresh_marker_path(path).display(),
                ),
                Some(chequebook),
            )
            .map_err(|e| format!("and the loss gate can't be put on record ({e})")),
            Ok(Some(m)) if m.clears(&key) => Err("and it is already cleared".to_string()),
            Ok(Some(_)) => Ok(()),
            Err(e) => Err(format!("and the lost-ledger marker can't be read ({e})")),
        };
        // This process remembers it as fresh whatever happened above, and
        // retries the record ([`retry_fresh_record`]). With the gate in
        // place, the losses on record then: once the record lands, the
        // gate is lifted unless the list changed meanwhile (PR #156
        // R4-M1, R5-M2).
        let gate = gated
            .is_ok()
            .then(|| read_lost_marker(path).ok().flatten().map(|m| m.moved_aside))
            .flatten();
        unrecorded_fresh_insert(path, &key, gate);
        Err(std::io::Error::other(match gated {
            Ok(()) => "not recorded as known in the lost-ledger marker either, so it can't \
                 pay before adopting another chequebook's cumulatives; downloads and uploads \
                 stay on the free tier until an operator confirms its liability"
                .to_string(),
            Err(why) => format!(
                "not gated behind the lost-ledger marker {why}; this process won't adopt the \
                 pre-section ledger into it, but after a restart it may"
            ),
        }))
    } else {
        note_known(path, &key).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "can't record it in the lost-ledger marker: {e}; downloads and uploads \
                     stay on the free tier until an operator confirms the loss",
                ),
            )
        })
    };
    match (fresh, known) {
        (Err(a), Err(b)) => Err(std::io::Error::new(a.kind(), format!("{a}; and {b}"))),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// A chequebook deployed fresh in this process whose fresh record
/// couldn't be written (PR #156 R3-M1).
struct UnrecordedFresh {
    path: PathBuf,
    key: String,
    /// Set when [`note_fresh_chequebook`] put it behind the loss gate
    /// instead: the losses the marker held then. The gate only stands in
    /// for the missing record, so it is lifted once the record lands,
    /// unless the losses on record changed since (PR #156 R4-M1): a
    /// count wouldn't do, since a marker replaced when unparsable starts
    /// over at one (PR #156 R5-M2).
    gate: Option<Vec<String>>,
    /// When the record was last tried, to space out the retries from
    /// [`OutboundLedger::ensure_readable`].
    last_try: std::time::Instant,
}

/// How often [`OutboundLedger::ensure_readable`] retries a failed fresh
/// record ([`retry_fresh_record`]); a ledger load always does.
const FRESH_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// [`UnrecordedFresh`] chequebooks, all ledger files.
static UNRECORDED_FRESH: Mutex<Vec<UnrecordedFresh>> = Mutex::new(Vec::new());

fn unrecorded_fresh_set() -> std::sync::MutexGuard<'static, Vec<UnrecordedFresh>> {
    UNRECORDED_FRESH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Add `key` to [`UNRECORDED_FRESH`] for `path`, or update its gate.
fn unrecorded_fresh_insert(path: &Path, key: &str, gate: Option<Vec<String>>) {
    let mut set = unrecorded_fresh_set();
    let last_try = std::time::Instant::now();
    match set.iter_mut().find(|u| u.path == path && u.key == key) {
        Some(u) => {
            u.gate = gate;
            u.last_try = last_try;
        }
        None => set.push(UnrecordedFresh {
            path: path.to_path_buf(),
            key: key.to_string(),
            gate,
            last_try,
        }),
    }
}

/// Lift the loss gate [`note_fresh_chequebook`] put `key` behind in
/// place of its fresh record, now that the record is written: a
/// chequebook deployed fresh issued no cheques before any loss on record
/// then. Not if a loss came in since (the losses on record aren't
/// exactly `gate`: more were added, or the marker was replaced): the
/// chequebook may have paid in between, after an operator confirmed it.
/// Caller holds [`OUTBOUND_FILE_LOCK`].
fn lift_fresh_gate(path: &Path, key: &str, gate: &[String]) {
    let lifted = match read_lost_marker(path) {
        Ok(Some(m)) if m.moved_aside == gate && !m.clears(key) => note_known(path, key),
        Ok(_) => return,
        Err(e) => Err(e),
    };
    match lifted {
        Ok(()) => info!(
            target: "ant_p2p::swap",
            chequebook = %key,
            "recorded the freshly deployed chequebook at last; lifted the loss gate \
             that stood in for the record",
        ),
        Err(e) => warn!(
            target: "ant_p2p::swap",
            chequebook = %key,
            "recorded the freshly deployed chequebook at last, but can't lift the loss \
             gate that stood in for the record ({e}); it stays on the free tier until an \
             operator confirms its liability",
        ),
    }
}

/// Whether `key` counts as deployed fresh for the ledger at `path`:
/// listed in the fresh marker, or deployed in this process with a fresh
/// record that failed (retried now, [`retry_fresh_record`]). Caller
/// holds [`OUTBOUND_FILE_LOCK`].
fn is_fresh(path: &Path, key: &str) -> std::io::Result<bool> {
    if retry_fresh_record(path, key, None) {
        return Ok(true);
    }
    Ok(listed_fresh(&fresh_chequebooks(path)?, key))
}

/// Retry the fresh record of `key`, deployed in this process, if it
/// failed ([`note_fresh_chequebook`]); once it lands, lift the loss gate
/// standing in for it ([`lift_fresh_gate`]). With `min_interval`, not if
/// the last try was more recent. Returns whether `key` was pending.
/// Caller holds [`OUTBOUND_FILE_LOCK`].
fn retry_fresh_record(path: &Path, key: &str, min_interval: Option<std::time::Duration>) -> bool {
    let gate = {
        let mut set = unrecorded_fresh_set();
        let Some(u) = set.iter_mut().find(|u| u.path == path && u.key == key) else {
            return false;
        };
        if min_interval.is_some_and(|min| u.last_try.elapsed() < min) {
            return true;
        }
        u.last_try = std::time::Instant::now();
        u.gate.clone()
    };
    match note_fresh(path, key) {
        Ok(()) => {
            unrecorded_fresh_set().retain(|u| !(u.path == path && u.key == key));
            if let Some(gate) = gate {
                lift_fresh_gate(path, key, &gate);
            }
        }
        Err(e) => warn!(
            target: "ant_p2p::swap",
            chequebook = %key,
            "still can't record a freshly deployed chequebook in {}: {e}",
            fresh_marker_path(path).display(),
        ),
    }
    true
}

/// Whether a fresh record for `key` at `path` is waiting to be retried
/// ([`retry_fresh_record`]). Takes no file lock.
fn fresh_record_pending(path: &Path, key: &str) -> bool {
    unrecorded_fresh_set()
        .iter()
        .any(|u| u.path == path && u.key == key)
}

/// Where [`note_fresh_chequebook`] lists the chequebooks deployed fresh
/// next to the ledger at `path`.
fn fresh_marker_path(path: &Path) -> PathBuf {
    path.with_extension("json.fresh")
}

/// In the fresh marker in place of a chequebook: any chequebook may be
/// fresh, so the pre-section ledger is adopted into none. Written over a
/// marker that couldn't be parsed ([`recover_fresh_marker`]).
const ANY_FRESH: &str = "*";

/// Whether `key` counts as deployed fresh in `fresh`.
fn listed_fresh(fresh: &[String], key: &str) -> bool {
    fresh.iter().any(|k| k == key || k == ANY_FRESH)
}

/// Chequebooks recorded as freshly deployed for the ledger at `path`.
/// Caller holds [`OUTBOUND_FILE_LOCK`]. A missing marker lists none. A
/// marker that can't be read is an error, not an empty list: read as
/// empty it would let the pre-section ledger be adopted into a fresh
/// chequebook, and written back it would erase every fresh entry it
/// held. One that can't be parsed is replaced ([`recover_fresh_marker`]).
fn fresh_chequebooks(path: &Path) -> std::io::Result<Vec<String>> {
    let marker = fresh_marker_path(path);
    let bytes = match std::fs::read(&marker) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    match serde_json::from_slice::<Vec<String>>(&bytes) {
        Ok(fresh) => Ok(fresh),
        Err(e) => recover_fresh_marker(path, &e),
    }
}

/// Replace a fresh marker that can't be parsed (PR #156 R2-M2). Which
/// chequebooks were fresh is gone, so the pre-section ledger can't be
/// told apart from a fresh chequebook's: it is adopted into none (the
/// marker becomes [`ANY_FRESH`]), and if there is one its figures count
/// as lost, the same as a ledger moved aside: the chequebook that owns
/// them stays on the free tier until an operator confirms its liability.
/// Which one that is isn't known, but it has no section of its own yet
/// (a chequebook adopts the pre-section ledger on its first load unless
/// it was deployed fresh), so every chequebook with a section, unless
/// already lost, stays known (PR #156 R3-M2) — as do ledgers whose
/// figures are in memory, as in [`quarantine_outbound_file`]. The unparsable marker is kept next to
/// it. Fails, leaving it as it was, if any of that can't be written.
fn recover_fresh_marker(
    path: &Path,
    parse_error: &dyn std::fmt::Display,
) -> std::io::Result<Vec<String>> {
    let marker = fresh_marker_path(path);
    let unparsable = |what: String| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "fresh-chequebook marker {} unparsable ({parse_error}) and {what}",
                marker.display()
            ),
        )
    };
    let aside = free_aside_name(&marker, "corrupt")
        .ok_or_else(|| unparsable("no free name to move it aside to".into()))?;
    let legacy = read_outbound_file(path)
        .map_err(|e| unparsable(format!("the ledger can't be read: {e}")))?
        .is_some_and(|f| f.chequebooks.contains_key(""));
    if legacy {
        // The loss goes on record first: the pre-section figures stop
        // being adopted by anyone once the marker is replaced. Only their
        // owner loses them, and it has no section of its own yet.
        let why = format!(
            "{NOT_MOVED}the fresh-chequebook marker {} was unparsable (kept as {}), so \
             which chequebook owns the cheque ledger written before per-chequebook \
             sections is unknown",
            marker.display(),
            aside.display(),
        );
        mark_legacy_figures_lost(path, &why, None)
            .map_err(|e| unparsable(format!("can't record the loss: {e}")))?;
    }
    std::fs::copy(&marker, &aside)
        .map_err(|e| unparsable(format!("can't be copied aside: {e}")))?;
    write_fresh_marker(&marker, &[ANY_FRESH.to_string()])
        .map_err(|e| unparsable(format!("can't be replaced: {e}")))?;
    warn!(
        target: "ant_p2p::swap",
        marker = %marker.display(),
        moved_to = %aside.display(),
        "fresh-chequebook marker is unparsable ({parse_error}); replaced it. The \
         outbound ledger written before per-chequebook sections is adopted into no \
         chequebook{}",
        if legacy {
            ", and its figures count as lost: no cheques, for downloads or uploads, \
             from any chequebook on this ledger without a section of its own until \
             an operator confirms its outstanding liability (antd --confirm-cheque-liability <chequebook>, or \
             ant_confirm_cheque_liability)"
        } else {
            ""
        },
    );
    Ok(vec![ANY_FRESH.to_string()])
}

/// Write the fresh marker whole and durably.
fn write_fresh_marker(marker: &Path, fresh: &[String]) -> std::io::Result<()> {
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = marker.with_extension("fresh.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(fresh).map_err(std::io::Error::other)?,
    )?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, marker)?;
    sync_parent_dir(marker)
}

/// Add `key` to the fresh marker (durably). Caller holds
/// [`OUTBOUND_FILE_LOCK`]. A marker that can't be read is left as it is
/// (one that can't be parsed is replaced first, see [`fresh_chequebooks`]).
fn note_fresh(path: &Path, key: &str) -> std::io::Result<()> {
    let mut fresh = fresh_chequebooks(path)?;
    if fresh.iter().any(|k| k == key) {
        return Ok(());
    }
    fresh.push(key.to_string());
    write_fresh_marker(&fresh_marker_path(path), &fresh)
}

/// Add `key` to the marker's known chequebooks. Caller holds
/// [`OUTBOUND_FILE_LOCK`].
fn note_known(path: &Path, key: &str) -> std::io::Result<()> {
    let Some(mut marker) = read_lost_marker(path)? else {
        return Ok(());
    };
    if marker.clears(key) {
        return Ok(());
    }
    marker.known.push(key.to_string());
    write_lost_marker(path, &marker)
}

/// Read `path` and its journals (caller holds [`OUTBOUND_FILE_LOCK`]),
/// adopting a file from before the sections for `key`'s chequebook, and
/// raise `state`'s cumulatives to what they hold (cumulatives only grow).
/// Returns how many entries the file holds. On error `state` is
/// untouched.
fn load_outbound_section(
    path: &Path,
    key: &str,
    state: &mut OutboundState,
) -> std::io::Result<usize> {
    let mut file = read_outbound_file(path)?.unwrap_or_default();
    let entries = file.entries();
    // Never into a chequebook deployed fresh: see `note_fresh_chequebook`.
    // If the fresh marker can't be read, whether `key` is fresh is
    // unknown: fail the load (no cheques until it reads) rather than
    // adopt old cumulatives into what may be a fresh chequebook. One
    // that can't be parsed is replaced by "adopt into none".
    if file.chequebooks.contains_key("") && is_fresh(path, key)? {
        info!(
            target: "ant_p2p::swap",
            chequebook = %key,
            "not adopting the pre-section outbound ledger into a chequebook that may be \
             freshly deployed: it has paid nobody",
        );
    } else if let Some(legacy) = file.chequebooks.remove("") {
        info!(
            target: "ant_p2p::swap",
            chequebook = %key,
            "adopting an outbound ledger written before per-chequebook sections",
        );
        let mine = file.chequebooks.entry(key.to_string()).or_default();
        for (k, v) in parse_cumulatives(legacy) {
            let cur = mine
                .get(&k)
                .and_then(|c| U256::from_dec_str(c).ok())
                .unwrap_or_default();
            if v >= cur {
                mine.insert(k, v.to_string());
            }
        }
        if let Err(e) = write_outbound_file(path, &file) {
            warn!(target: "ant_p2p::swap", "outbound ledger migrate: {e}");
        }
    }
    // Both journals are read before anything is taken, so a failed
    // read leaves `state` as it was.
    let mut journaled = load_journal(path, &journal_old_path(path))?;
    journaled.extend(load_journal(path, &journal_path(path))?);
    for line in journaled {
        file.merge_flat(line);
    }
    if let Some(section) = file.chequebooks.remove(key) {
        for (k, v) in parse_cumulatives(section) {
            state.raise(k, v);
        }
    }
    state.unread = None;
    Ok(entries)
}

thread_local! {
    /// This thread holds [`OUTBOUND_FILE_LOCK`].
    static HOLDS_FILE_LOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

thread_local! {
    /// References to drop once this thread releases the file lock (see
    /// [`release_after_unlock`]).
    static RELEASE_AFTER_UNLOCK: std::cell::RefCell<Vec<Box<dyn std::any::Any>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drop `v` once this thread releases [`OUTBOUND_FILE_LOCK`] instead of
/// now. For references code holding the lock took only for a moment
/// (upgraded from a registry's `Weak`): if it turns out to be the last
/// one, the journal it closes is written out and folded at close
/// ([`JournalStore`]'s `Drop`), which takes the lock itself — under the
/// lock it couldn't, and would leave staged lines unwritten and the
/// journal unfolded (PR #141 R2-M2). Kept alive meanwhile, the store
/// also stays in the registry, so a ledger opened in between shares it
/// rather than opening a second handle on the journal.
fn release_after_unlock<T: 'static>(v: T) {
    if HOLDS_FILE_LOCK.with(std::cell::Cell::get) {
        RELEASE_AFTER_UNLOCK.with(|r| r.borrow_mut().push(Box::new(v)));
    }
}

/// [`OUTBOUND_FILE_LOCK`], held.
struct FileLock(Option<std::sync::MutexGuard<'static, ()>>);

impl Drop for FileLock {
    fn drop(&mut self) {
        HOLDS_FILE_LOCK.with(|h| h.set(false));
        drop(self.0.take());
        // Each may take the lock again (and queue more, released by that
        // lock's own drop).
        let released = RELEASE_AFTER_UNLOCK.with(|r| std::mem::take(&mut *r.borrow_mut()));
        drop(released);
    }
}

fn lock_file() -> FileLock {
    let guard = OUTBOUND_FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    HOLDS_FILE_LOCK.with(|h| h.set(true));
    FileLock(Some(guard))
}

/// The outbound ledger files at `path` (the ledger, its journals and
/// its lost marker), held still for a caller about to move them away —
/// an account switch parking the data dir (`ant-ffi`'s
/// `bind_account_state`) — until dropped. See [`hold_ledger_files`].
#[must_use = "the files are only held while this is alive"]
pub struct LedgerFilesHeld {
    _file: FileLock,
}

/// Take the files of the outbound ledger at `path` away from this
/// process's ledgers before moving them (PR #141 R2-F1). Holds
/// [`OUTBOUND_FILE_LOCK`] until the returned guard drops, so a
/// compaction or a close-time fold still running (on a thread of its
/// own, which can outlive the node's shutdown) finishes before the
/// files move and none starts while they do; and retires every journal
/// store on the path ([`JournalIo::retired`]), so one that runs after
/// writes nothing at all — not over the next account's files adopted
/// at the same path. Ledgers still open on the path fail their cheques
/// from now on, and a ledger opened on it later starts afresh from
/// whatever files are there then.
pub fn hold_ledger_files(path: &Path) -> LedgerFilesHeld {
    let file = lock_file();
    let stores: Vec<Arc<JournalStore>> = {
        let mut reg = JOURNALS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stores = Vec::new();
        reg.retain(|(p, w)| {
            if p != path {
                return w.strong_count() > 0;
            }
            stores.extend(w.upgrade());
            false
        });
        stores
    };
    for store in &stores {
        store
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retire();
    }
    let ledgers: Vec<Arc<OutboundShared>> = {
        let mut reg = OUTBOUND_LEDGERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ledgers = Vec::new();
        reg.retain(|((p, _), w)| {
            if p != path {
                return w.strong_count() > 0;
            }
            ledgers.extend(w.upgrade());
            false
        });
        ledgers
    };
    // The marker moves too: don't answer from the old one's cache.
    if let Some(cache) = LOST_MARKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        cache.remove(&lost_marker_path(path));
    }
    release_after_unlock((stores, ledgers));
    LedgerFilesHeld { _file: file }
}

impl OutboundLedger {
    /// Open `chequebook`'s cumulatives from `persist_path` (or start
    /// empty without one). See the type docs for the file layout. A
    /// file that exists but can't be read leaves the ledger refusing to
    /// issue until it can ([`Self::ensure_readable`]).
    pub fn open(persist_path: Option<PathBuf>, chequebook: [u8; 20]) -> Self {
        let key = hex::encode(chequebook);
        let shared = match &persist_path {
            None => Arc::new(OutboundShared::default()),
            Some(p) => {
                // The file lock is held throughout, so nothing else opens
                // or registers a ledger between the lookup and the push;
                // the registry itself is released while the file is read,
                // since a move aside flags the live ledgers in it.
                let _file = lock_file();
                let id = (p.clone(), chequebook);
                let live = {
                    let mut reg = OUTBOUND_LEDGERS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    reg.retain(|(_, w)| w.strong_count() > 0);
                    reg.iter()
                        .find(|(k, _)| *k == id)
                        .and_then(|(_, w)| w.upgrade())
                };
                // A live state whose journal was retired (its files moved
                // away under it, an account switch) can't write any more:
                // reusing it would leave this ledger unable to pay for the
                // rest of the process (PR #141 R2-M1). Start afresh from
                // the files at the path instead; the old one stays with
                // whoever still holds it, and drops out of the registry.
                let live = match live {
                    Some(shared) if shared.store.as_ref().is_some_and(|s| s.retire_if_moved()) => {
                        OUTBOUND_LEDGERS
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .retain(|(k, w)| {
                                *k != id || !std::ptr::eq(w.as_ptr(), Arc::as_ptr(&shared))
                            });
                        release_after_unlock(shared);
                        None
                    }
                    live => live,
                };
                if let Some(shared) = live {
                    shared
                } else {
                    let store = JournalStore::for_path(p);
                    let mut st = OutboundState::default();
                    let loaded = match load_outbound_section(p, &key, &mut st) {
                        Ok(entries) => {
                            store
                                .snapshot_entries
                                .fetch_max(entries as u64, Ordering::SeqCst);
                            true
                        }
                        Err(e) => {
                            warn!(
                                target: "ant_p2p::swap",
                                chequebook = %key,
                                "outbound ledger unreadable: {e}; no cheques until it can be read",
                            );
                            st.unread = Some(e.to_string());
                            false
                        }
                    };
                    if let Some(why) = lost_figures_at(p, &chequebook) {
                        warn!(target: "ant_p2p::swap", "{why}");
                    }
                    let shared = Arc::new(OutboundShared {
                        state: Mutex::new(st),
                        loaded: AtomicBool::new(loaded),
                        store: Some(store),
                        ..OutboundShared::default()
                    });
                    OUTBOUND_LEDGERS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((id, Arc::downgrade(&shared)));
                    shared
                }
            }
        };
        Self {
            chequebook,
            shared,
            persist_path,
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, OutboundState> {
        self.shared.state.lock().expect("outbound ledger poisoned")
    }

    /// Lock to hold from reading `beneficiary`'s last cumulative to
    /// recording the next one, shared by every ledger on this chequebook
    /// and file, so two cheques to one beneficiary can't build on the
    /// same previous cumulative.
    #[must_use]
    pub fn beneficiary_lock(&self, beneficiary: [u8; 20]) -> Arc<tokio::sync::Mutex<()>> {
        self.shared
            .issuing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(beneficiary)
            .or_default()
            .clone()
    }

    /// Gate to hold from checking the chequebook's funds left
    /// (deposit less [`Self::total_issued`]) to recording the cheque
    /// that spends them, shared like [`Self::beneficiary_lock`].
    pub fn funds_gate(&self) -> std::sync::MutexGuard<'_, ()> {
        self.shared
            .funds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Chequebook whose cheques this ledger tracks.
    #[must_use]
    pub fn chequebook(&self) -> [u8; 20] {
        self.chequebook
    }

    /// `Ok` once the chequebook's recorded cumulatives are known: the
    /// file was read (or is missing). If the read at open failed, try it
    /// again now. Call before signing a cheque — while it errs,
    /// [`Self::cumulative_for`] and [`Self::total_issued`] may be short.
    /// The state lock isn't held while the file is read.
    ///
    /// It also retries a fresh record of this chequebook that failed at
    /// deploy, at most every [`FRESH_RETRY_INTERVAL`] ([`note_fresh_chequebook`]):
    /// once the ledger is live no load runs again to retry it, and the
    /// loss gate standing in for it would hold until a restart made it
    /// permanent (PR #156 R5-M1).
    pub fn ensure_readable(&self) -> std::io::Result<()> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let key = hex::encode(self.chequebook);
        if fresh_record_pending(path, &key) {
            let _file = lock_file();
            if !self.shared.store.as_ref().is_some_and(|s| s.is_retired()) {
                retry_fresh_record(path, &key, Some(FRESH_RETRY_INTERVAL));
            }
        }
        if self.lock_state().unread.is_none() {
            return Ok(());
        }
        let _file = lock_file();
        // Its files moved away (account switch): what is at the path now
        // is someone else's, and must not be read, migrated or moved
        // aside on this ledger's behalf.
        if self.shared.store.as_ref().is_some_and(|s| s.is_retired()) {
            return Err(retired_error());
        }
        let mut read = OutboundState::default();
        let loaded = load_outbound_section(path, &key, &mut read);
        let mut st = self.lock_state();
        match loaded {
            Ok(_) => {
                for (k, v) in read.cumulatives {
                    st.raise(k, v);
                }
                if st.unread.take().is_some() {
                    self.shared.loaded.store(true, Ordering::SeqCst);
                    info!(
                        target: "ant_p2p::swap",
                        chequebook = %hex::encode(self.chequebook),
                        "outbound ledger readable again; cheques resume",
                    );
                }
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                if st.unread.as_deref() != Some(msg.as_str()) {
                    warn!(
                        target: "ant_p2p::swap",
                        chequebook = %hex::encode(self.chequebook),
                        "outbound ledger still unreadable: {e}; no cheques until it can be read",
                    );
                }
                st.unread = Some(msg);
                Err(e)
            }
        }
    }

    /// Why this chequebook's figures are unknown — the ledger file was
    /// unparseable and moved aside, or the pre-section figures may be
    /// its own (an unparsable fresh marker, a fresh deploy that couldn't
    /// be recorded), and no operator has confirmed the chequebook's
    /// outstanding liability since (see the type docs) —
    /// or `None` while they are known. No cheque, for downloads or
    /// uploads, is paid while this is `Some`. Checked against the marker on
    /// every call, so a loss or a confirmation shows at once in every
    /// ledger on the file — but without the file lock, and parsing the
    /// marker only when it changed, since this runs on the swarm loop
    /// (PR #126 R1-M1). A ledger whose figures were in memory when the
    /// file was lost isn't affected (see the type docs).
    #[must_use]
    pub fn lost_figures(&self) -> Option<String> {
        let path = self.persist_path.as_ref()?;
        if self.shared.survived_loss.load(Ordering::SeqCst) {
            return None;
        }
        lost_figures_at(path, &self.chequebook)
    }

    /// Last cumulative we issued to `beneficiary` (zero if none).
    #[must_use]
    pub fn cumulative_for(&self, beneficiary: &[u8; 20]) -> U256 {
        self.recorded_for(beneficiary).unwrap_or(U256::zero())
    }

    /// Sum of every beneficiary's cumulative: all PLUR this chequebook
    /// has promised in cheques from this node (bee's `totalIssued`).
    /// O(1): the sum is kept as cheques are recorded.
    #[must_use]
    pub fn total_issued(&self) -> U256 {
        self.lock_state().total
    }

    /// Like [`Self::cumulative_for`] but distinguishes "no cheque ever
    /// issued" (`None`) from a recorded cumulative. The accounting
    /// snapshot needs the difference: bee's `/settlements/{peer}`
    /// 404s on a peer with no settlement record rather than reporting
    /// zero.
    #[must_use]
    pub fn recorded_for(&self, beneficiary: &[u8; 20]) -> Option<U256> {
        let key = hex::encode(beneficiary);
        self.lock_state().cumulatives.get(&key).copied()
    }

    /// Record `beneficiary` → `new_cumulative` as issued: in memory at
    /// once (so [`Self::total_issued`] counts it from now on), and staged
    /// for the journal. Nothing is written yet and no lock is held on
    /// return; the cheque may be sent only once the returned
    /// [`PendingWrite`] is durable. Cheques staged together are written
    /// and fsynced together.
    ///
    /// The journal line is written even while the file can't be read: it
    /// only ever raises a figure, so it can't erase one this ledger
    /// couldn't see. A ledger whose figures outlived a loss of the file
    /// ([`Self::lost_figures`]) journals all of them with this cheque, so
    /// a restart finds them again, and marks them known once they are on
    /// disk.
    pub fn stage_issued(&self, beneficiary: &[u8; 20], new_cumulative: U256) -> PendingWrite {
        let key = hex::encode(beneficiary);
        let mut st = self.lock_state();
        let now = st.raise(key.clone(), new_cumulative);
        let Some(store) = &self.shared.store else {
            return PendingWrite { pending: None };
        };
        let chequebook = hex::encode(self.chequebook);
        // Read before the rewrite is staged: a loss flagged after this
        // point isn't covered by it.
        let generation = self.shared.loss_gen.load(Ordering::SeqCst);
        let (seq, note_known) = if self.shared.survived_loss.load(Ordering::SeqCst) {
            let seq = store.stage(
                st.cumulatives
                    .iter()
                    .map(|(b, v)| (chequebook.as_str(), b.as_str(), *v)),
            );
            (seq, Some((chequebook, generation)))
        } else {
            (
                store.stage([(chequebook.as_str(), key.as_str(), now)]),
                None,
            )
        };
        drop(st);
        PendingWrite {
            pending: Some(Pending {
                store: Arc::clone(store),
                seq,
                shared: Arc::clone(&self.shared),
                note_known,
            }),
        }
    }

    /// [`Self::stage_issued`], then block until it is on disk. On error
    /// the in-memory record still holds the cheque (and the line stays
    /// staged, for the next write to retry).
    pub fn record_issued(
        &self,
        beneficiary: &[u8; 20],
        new_cumulative: U256,
    ) -> std::io::Result<()> {
        self.stage_issued(beneficiary, new_cumulative).wait()
    }
}

fn write_outbound_file(path: &Path, file: &OutboundFile) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&file.to_flat()).map_err(std::io::Error::other)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// --- I/O helpers (length-delimited frames + bee headers preamble) ---

async fn write_empty_headers<W: AsyncWriteExt + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[0u8]).await?;
    w.flush().await?;
    Ok(())
}

async fn read_delimited<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    let len = read_varint_len(r).await?;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (cap {max})"),
        ));
    }
    // Grows with the bytes that arrive, not the declared `len`, so a peer
    // can't pin the cap per stream by declaring a frame and stalling (#203).
    ant_retrieval::frame::read_frame_body(r, len).await
}

async fn read_varint_len<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<usize> {
    let mut byte = [0u8; 1];
    let mut acc: Vec<u8> = Vec::with_capacity(10);
    loop {
        r.read_exact(&mut byte).await?;
        acc.push(byte[0]);
        match unsigned_varint::decode::u64(&acc) {
            Ok((v, [])) => {
                return usize::try_from(v).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "varint overflow")
                });
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid varint framing",
                ));
            }
            Err(unsigned_varint::decode::Error::Insufficient) => {
                if acc.len() > 10 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint too long",
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varint: {e}"),
                ));
            }
        }
    }
}

async fn write_delimited<W, M>(w: &mut W, msg: &M) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    M: Message,
{
    let mut buf = Vec::with_capacity(msg.encoded_len() + 10);
    msg.encode_length_delimited(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Drain the inbound stream without touching any ledger. Used when
/// the operator hasn't configured a chequebook beneficiary yet — we
/// still want to accept the protocol negotiation so bee doesn't
/// disconnect us, but we have nothing meaningful to do with the
/// cheque. Logs at trace.
pub async fn drain_inbound_unconfigured(mut incoming: IncomingStreams) {
    while let Some((peer, mut stream)) = incoming.next().await {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(STREAM_TIMEOUT, async move {
                let _ = read_delimited(&mut stream, HEADERS_MAX).await;
                let _ = write_empty_headers(&mut stream).await;
                let _ = read_delimited(&mut stream, EMIT_CHEQUE_MAX).await;
                let _ = stream.close().await;
            })
            .await;
            trace!(
                target: "ant_p2p::swap",
                %peer,
                "drained inbound cheque (no chequebook configured; ignored)",
            );
        });
    }
}

// --- listener ---

/// Outcome surfaced by the inbound listener for each accepted cheque.
///
/// Currently advisory — operators can subscribe to log a one-line
/// "credited X PLUR from peer Y" event without re-parsing the
/// ledger snapshot.
#[derive(Debug, Clone)]
pub struct InboundCheque {
    pub peer: PeerId,
    pub chequebook: [u8; 20],
    pub issuer_eoa: [u8; 20],
    pub cumulative_payout: U256,
    pub previous_cumulative: U256,
}

/// Spawn the long-lived inbound listener. For each accepted stream
/// it: drains the bee headers preamble, reads the `EmitCheque` frame,
/// parses the JSON cheque, and applies it to the ledger. Successful
/// accepts publish to `events_tx` (best-effort: drops on backpressure).
///
/// Stays compatible with bee's `s.handler`: bee's listener reads the
/// dialer's headers FIRST, then writes back its own. We're the
/// listener here, so we mirror that — read first, then ack with
/// empty headers, then read the payload.
pub async fn run_inbound(
    mut incoming: IncomingStreams,
    ledger: Arc<CreditLedger>,
    events_tx: Option<mpsc::Sender<InboundCheque>>,
) {
    while let Some((peer, stream)) = incoming.next().await {
        let l = ledger.clone();
        let tx = events_tx.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(STREAM_TIMEOUT, handle_inbound_stream(peer, stream, l)).await
            {
                Ok(Ok(ev)) => {
                    info!(
                        target: "ant_p2p::swap",
                        %peer,
                        chequebook = %hex::encode(ev.chequebook),
                        cumulative = %ev.cumulative_payout,
                        delta = %(ev.cumulative_payout.saturating_sub(ev.previous_cumulative)),
                        "accepted cheque",
                    );
                    if let Some(tx) = tx {
                        let _ = tx.try_send(ev);
                    }
                }
                Ok(Err(e)) => debug!(
                    target: "ant_p2p::swap",
                    %peer,
                    "inbound cheque rejected: {e}",
                ),
                Err(_) => warn!(
                    target: "ant_p2p::swap",
                    %peer,
                    "inbound stream timed out after {}s",
                    STREAM_TIMEOUT.as_secs(),
                ),
            }
        });
    }
}

async fn handle_inbound_stream(
    peer: PeerId,
    mut stream: Stream,
    ledger: Arc<CreditLedger>,
) -> Result<InboundCheque, SwapError> {
    // Headers preamble: bee's dialer writes first, so we read first.
    let _their_headers = read_delimited(&mut stream, HEADERS_MAX).await?;
    write_empty_headers(&mut stream).await?;

    let body = read_delimited(&mut stream, EMIT_CHEQUE_MAX).await?;
    let msg = EmitChequePb::decode(body.as_slice())?;
    let signed = decode_signed_cheque_json(&msg.cheque)?;
    let prev = ledger.record_accepted(&signed)?;
    let issuer = recover_cheque_signer(&signed, ledger.chain_id)?;
    // Half-close so bee's `stream.FullClose()` returns promptly.
    let _ = stream.close().await;
    trace!(
        target: "ant_p2p::swap",
        %peer,
        "stream closed after accepted cheque",
    );
    Ok(InboundCheque {
        peer,
        chequebook: signed.cheque.chequebook,
        issuer_eoa: issuer,
        cumulative_payout: signed.cheque.cumulative_payout,
        previous_cumulative: prev,
    })
}

// --- dialer ---

/// Open a swap stream to `peer` and emit `signed`. Returns once bee
/// has read the message (we close our half; bee's `s.handler` does
/// the rest). On error the caller should NOT update the outbound
/// ledger — the cheque hasn't actually been delivered.
pub async fn emit_cheque(
    control: &mut Control,
    peer: PeerId,
    signed: &SignedCheque,
) -> Result<(), SwapError> {
    let proto = StreamProtocol::new(PROTOCOL_SWAP);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| std::io::Error::other(format!("open swap stream: {e}")))?;

    // Headers preamble — we're the dialer, so write first then read.
    write_empty_headers(&mut stream).await?;
    let _their_headers = read_delimited(&mut stream, HEADERS_MAX).await?;

    let body = encode_signed_cheque_json(signed);
    let msg = EmitChequePb { cheque: body };
    write_delimited(&mut stream, &msg).await?;
    let _ = stream.close().await;
    Ok(())
}

/// Bee's settlement response headers (`pkg/settlement/swap/headers`):
/// the cheque recipient's `exchange` rate (PLUR per accounting unit, from
/// the swap price oracle) and the one-off `deduction` (PLUR), both
/// big-endian unsigned integers. Bee's `swapprotocol.EmitCheque` reads
/// them before it signs and pays `amount × exchange + deduction`; the
/// recipient credits `(paid − deduction) / exchange` units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementRates {
    pub exchange_rate: U256,
    pub deduction: U256,
}

impl SettlementRates {
    /// PLUR a cheque must carry to clear `units` of accounting debt at
    /// these rates.
    #[must_use]
    pub fn cheque_amount(&self, units: u64) -> Option<U256> {
        U256::from(units)
            .checked_mul(self.exchange_rate)?
            .checked_add(self.deduction)
    }
}

/// Bee `internal/headers/pb::Header`.
#[derive(Clone, PartialEq, Eq, Message)]
struct HeaderPb {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

/// Bee `internal/headers/pb::Headers`.
#[derive(Clone, PartialEq, Eq, Message)]
struct HeadersPb {
    #[prost(message, repeated, tag = "1")]
    headers: Vec<HeaderPb>,
}

/// Decode the swap listener's response headers into [`SettlementRates`],
/// like bee's `ParseSettlementResponseHeaders`: `exchange` is required,
/// a missing `deduction` is zero (bee's `ErrNoDeductionHeader` path).
pub fn parse_settlement_headers(bytes: &[u8]) -> Result<SettlementRates, SwapError> {
    let headers = HeadersPb::decode(bytes)?;
    let field = |name: &str| {
        headers
            .headers
            .iter()
            .find(|h| h.key == name)
            .map(|h| h.value.as_slice())
    };
    let big = |v: &[u8]| -> Result<U256, SwapError> {
        if v.len() > 32 {
            return Err(SwapError::Rejected(format!(
                "settlement header of {} bytes",
                v.len()
            )));
        }
        Ok(U256::from_big_endian(v))
    };
    let exchange_rate =
        big(field("exchange").ok_or_else(|| SwapError::Rejected("no exchange header".into()))?)?;
    let deduction = match field("deduction") {
        Some(v) => big(v)?,
        None => U256::zero(),
    };
    Ok(SettlementRates {
        exchange_rate,
        deduction,
    })
}

/// Open a swap stream to `peer` and read the recipient's
/// [`SettlementRates`] from its response headers: the first half of bee's
/// `swapprotocol.EmitCheque`. Finish with [`write_cheque`] once the
/// cheque for those rates is signed, or drop the stream to abandon it.
pub async fn open_settlement(
    control: &mut Control,
    peer: PeerId,
) -> Result<(Stream, SettlementRates), SwapError> {
    let proto = StreamProtocol::new(PROTOCOL_SWAP);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| std::io::Error::other(format!("open swap stream: {e}")))?;
    write_empty_headers(&mut stream).await?;
    let headers = read_delimited(&mut stream, HEADERS_MAX).await?;
    let rates = parse_settlement_headers(&headers)?;
    Ok((stream, rates))
}

/// Write `signed` on a stream from [`open_settlement`]. Our side stays
/// open until [`await_processed`] has read the recipient's verdict (see
/// there). The recipient may hold the cheque from here on (and even if
/// this fails halfway), so the caller counts it as issued before calling
/// this.
pub async fn write_cheque(stream: &mut Stream, signed: &SignedCheque) -> Result<(), SwapError> {
    let body = encode_signed_cheque_json(signed);
    write_delimited(stream, &EmitChequePb { cheque: body }).await?;
    stream.flush().await?;
    Ok(())
}

/// Wait for the recipient of a cheque from [`write_cheque`] to finish
/// with the stream, and learn whether it accepted the cheque.
///
/// Bee's swap handler runs `ReceiveCheque` (signature, chequebook and
/// balance checks, then `NotifyPaymentReceived`) before it closes the
/// stream, so once the stream has ended bee has credited an accepted
/// cheque. Only then may the payer lower its own view of the debt:
/// lowering it as soon as the cheque is written lets new requests
/// through while the recipient still counts the old debt, which takes the
/// recipient past its disconnect limit, and bee blocklists the payer
/// (`debitAction.Apply`).
///
/// Bee ends the stream with `FullClose` (a `FIN`, then it waits for ours)
/// only after `ReceiveCheque` succeeded, and with `Reset` on any failure
/// (`swapprotocol.handler`). rust-yamux 0.13 reads both as a clean end of
/// stream (`Ok(0)`), so the read alone can't tell an accepted cheque from
/// a refused one. Their states differ, though, as long as *our* side is
/// still open: a `FIN` only closes the recipient's half (we can still
/// write), a `RST` or a dropped connection closes the stream entirely
/// (every write fails with `WriteZero`). So [`write_cheque`] leaves our
/// half open, and once the recipient's end is read a zero-length write
/// asks which it was: it fails on a refused or lost cheque. On an
/// accepted one we then close our half, which completes bee's
/// `FullClose`. The payer still watches the connection for a moment
/// after (`crate::PushsyncSwap`, `DELIVERY_GRACE`).
pub async fn await_processed(mut stream: Stream) -> Result<(), SwapError> {
    await_verdict(&mut stream).await
}

/// [`await_processed`] on any stream.
async fn await_verdict<S>(stream: &mut S) -> Result<(), SwapError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .map_err(|e| SwapError::Rejected(format!("cheque stream failed: {e}")))?;
    if let Err(e) = stream.write(&[]).await {
        return Err(SwapError::Rejected(format!(
            "the recipient reset the cheque stream (refused or lost): {e}"
        )));
    }
    let _ = stream.close().await;
    Ok(())
}

#[cfg(test)]
mod verdict_tests {
    use super::await_verdict;
    use futures::future::poll_fn;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// A yamux connection pair over an in-memory pipe: the dialer's side
    /// of one stream, and the listener's side of it.
    async fn stream_pair() -> (yamux::Stream, yamux::Stream) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client =
            yamux::Connection::new(a.compat(), yamux::Config::default(), yamux::Mode::Client);
        let mut server =
            yamux::Connection::new(b.compat(), yamux::Config::default(), yamux::Mode::Server);
        let (out_tx, out_rx) = tokio::sync::oneshot::channel();
        let (in_tx, in_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let s = poll_fn(|cx| client.poll_new_outbound(cx)).await.unwrap();
            let _ = out_tx.send(s);
            // Keep driving the connection.
            while poll_fn(|cx| client.poll_next_inbound(cx)).await.is_some() {}
        });
        tokio::spawn(async move {
            let mut in_tx = Some(in_tx);
            while let Some(Ok(s)) = poll_fn(|cx| server.poll_next_inbound(cx)).await {
                if let Some(tx) = in_tx.take() {
                    let _ = tx.send(s);
                }
            }
        });
        let mut ours = out_rx.await.unwrap();
        // A yamux stream reaches the listener with its first frame.
        ours.write_all(b"cheque").await.unwrap();
        ours.flush().await.unwrap();
        let theirs = in_rx.await.unwrap();
        (ours, theirs)
    }

    /// Read the cheque bytes on the recipient's side.
    async fn read_cheque(theirs: &mut yamux::Stream) {
        let mut buf = [0u8; 6];
        theirs.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"cheque");
    }

    #[tokio::test]
    async fn an_accepted_cheque_reads_as_delivered() {
        let (mut ours, mut theirs) = stream_pair().await;
        let recipient = tokio::spawn(async move {
            read_cheque(&mut theirs).await;
            // Bee's FullClose: our FIN, then wait for theirs.
            theirs.close().await.unwrap();
            let mut rest = Vec::new();
            theirs.read_to_end(&mut rest).await.unwrap();
        });
        await_verdict(&mut ours)
            .await
            .expect("a FIN-closed cheque stream is accepted");
        tokio::time::timeout(std::time::Duration::from_secs(5), recipient)
            .await
            .expect("bee's FullClose completes once we close our half")
            .unwrap();
    }

    #[tokio::test]
    async fn a_refused_cheque_reads_as_not_delivered() {
        let (mut ours, mut theirs) = stream_pair().await;
        tokio::spawn(async move {
            read_cheque(&mut theirs).await;
            // Bee's Reset on a refused cheque; the connection stays up.
            drop(theirs);
        });
        let verdict = await_verdict(&mut ours).await;
        assert!(
            verdict.is_err(),
            "a reset cheque stream must not count as delivered"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_chain::chequebook::sign_cheque;
    use ant_crypto::{
        ethereum_address_from_public_key, random_secp256k1_secret, SECP256K1_SECRET_LEN,
    };
    use k256::ecdsa::SigningKey;

    fn make_secret() -> [u8; SECP256K1_SECRET_LEN] {
        random_secp256k1_secret()
    }

    fn eoa(secret: &[u8; SECP256K1_SECRET_LEN]) -> [u8; 20] {
        let sk = SigningKey::from_bytes(secret.into()).unwrap();
        ethereum_address_from_public_key(sk.verifying_key())
    }

    /// Bee's settlement response headers decode to the rates the
    /// cheque amount is computed from; a missing deduction is zero, a
    /// missing exchange rate is refused.
    #[test]
    fn settlement_headers_decode_like_bee() {
        let enc = |h: Vec<(&str, Vec<u8>)>| {
            HeadersPb {
                headers: h
                    .into_iter()
                    .map(|(k, v)| HeaderPb {
                        key: k.into(),
                        value: v,
                    })
                    .collect(),
            }
            .encode_to_vec()
        };
        // Mainnet oracle at the time of writing: 100 000 PLUR/unit, 100 PLUR.
        let rates = parse_settlement_headers(&enc(vec![
            ("exchange", vec![0x01, 0x86, 0xa0]),
            ("deduction", vec![0x64]),
        ]))
        .unwrap();
        assert_eq!(rates.exchange_rate, U256::from(100_000u64));
        assert_eq!(rates.deduction, U256::from(100u64));
        assert_eq!(
            rates.cheque_amount(675_000),
            Some(U256::from(67_500_000_100u64))
        );
        let no_deduction =
            parse_settlement_headers(&enc(vec![("exchange", vec![0x01, 0x86, 0xa0])])).unwrap();
        assert_eq!(no_deduction.deduction, U256::zero());
        assert!(parse_settlement_headers(&enc(vec![])).is_err());
        assert!(parse_settlement_headers(&[0u8; 0]).is_err());
    }

    /// JSON encoder / decoder round-trip.
    #[test]
    fn json_round_trip() {
        let secret = make_secret();
        let cheque = Cheque {
            chequebook: [0x11u8; 20],
            beneficiary: [0x22u8; 20],
            cumulative_payout: U256::from(123_456_789u64),
        };
        let signed = sign_cheque(&secret, &cheque, 100).unwrap();
        let bytes = encode_signed_cheque_json(&signed);
        let back = decode_signed_cheque_json(&bytes).unwrap();
        assert_eq!(back, signed);
    }

    /// Bee-shape JSON sanity: hex prefix, decimal cumulative, base64 sig.
    #[test]
    fn json_layout_matches_bee_shape() {
        let signed = SignedCheque {
            cheque: Cheque {
                chequebook: hex::decode("11111111111111111111111111111111111111aa")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                beneficiary: hex::decode("22222222222222222222222222222222222222bb")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                cumulative_payout: U256::from(987_654u64),
            },
            signature: [0xcdu8; 65],
        };
        let bytes = encode_signed_cheque_json(&signed);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""Chequebook":"0x11111111111111111111111111111111111111aa""#));
        assert!(s.contains(r#""Beneficiary":"0x22222222222222222222222222222222222222bb""#));
        // A bare number, as go's `json.Marshal(*big.Int)` writes it: bee's
        // `UnmarshalJSON` refuses the quoted form (issue #121).
        assert!(s.contains(r#""CumulativePayout":987654,"#));
        // base64 of 65 bytes 0xcd = "zc3N…" repeated.
        assert!(s.contains(r#""Signature":"#));
        // Round-trip back, ensuring even the high-bit byte parses.
        let back = decode_signed_cheque_json(&bytes).unwrap();
        assert_eq!(back, signed);
    }

    /// Decoding takes the bare number bee sends, a payout past `u64`
    /// without losing digits, and the quoted form older Ant versions
    /// sent; it refuses a payout that isn't a decimal integer.
    #[test]
    fn cumulative_payout_decodes_bare_and_quoted() {
        let body = |payout: &str| {
            format!(
                r#"{{"Chequebook":"0x11111111111111111111111111111111111111aa","Beneficiary":"0x22222222222222222222222222222222222222bb","CumulativePayout":{payout},"Signature":"{}"}}"#,
                BASE64.encode([0xcdu8; 65])
            )
        };
        let big = "123456789012345678901234567890";
        for payout in [big.to_string(), format!("\"{big}\"")] {
            let decoded = decode_signed_cheque_json(body(&payout).as_bytes()).unwrap();
            assert_eq!(
                decoded.cheque.cumulative_payout,
                U256::from_dec_str(big).unwrap()
            );
        }
        for bad in ["-1", "1.5", "1e3", "\"0x10\"", "null"] {
            assert!(
                decode_signed_cheque_json(body(bad).as_bytes()).is_err(),
                "{bad} must be refused"
            );
        }
    }

    /// Ledger accepts a valid first cheque, then a strictly-larger
    /// follow-up. Rejects: smaller / equal cumulative, wrong
    /// beneficiary, swapped-issuer attack.
    #[test]
    fn ledger_monotonicity_and_pinning() {
        let issuer_secret = make_secret();
        let issuer_eoa = eoa(&issuer_secret);
        let our_eoa = [0xaau8; 20];
        let cheque1 = Cheque {
            chequebook: [0x77u8; 20],
            beneficiary: our_eoa,
            cumulative_payout: U256::from(100u64),
        };
        let signed1 = sign_cheque(&issuer_secret, &cheque1, 100).unwrap();
        let ledger = CreditLedger::open(None, 100, our_eoa);
        let prev = ledger.record_accepted(&signed1).unwrap();
        assert_eq!(prev, U256::zero());
        assert_eq!(ledger.cumulative_for(&[0x77u8; 20]), U256::from(100u64));

        // Strictly-larger follow-up accepted.
        let mut cheque2 = cheque1;
        cheque2.cumulative_payout = U256::from(150u64);
        let signed2 = sign_cheque(&issuer_secret, &cheque2, 100).unwrap();
        let prev2 = ledger.record_accepted(&signed2).unwrap();
        assert_eq!(prev2, U256::from(100u64));
        assert_eq!(ledger.cumulative_for(&[0x77u8; 20]), U256::from(150u64));

        // Equal cumulative rejected.
        let mut cheque_dup = cheque2.clone();
        cheque_dup.cumulative_payout = U256::from(150u64);
        let signed_dup = sign_cheque(&issuer_secret, &cheque_dup, 100).unwrap();
        assert!(matches!(
            ledger.record_accepted(&signed_dup).unwrap_err(),
            SwapError::Rejected(_),
        ));

        // Smaller cumulative rejected.
        let mut cheque_back = cheque2.clone();
        cheque_back.cumulative_payout = U256::from(120u64);
        let signed_back = sign_cheque(&issuer_secret, &cheque_back, 100).unwrap();
        assert!(matches!(
            ledger.record_accepted(&signed_back).unwrap_err(),
            SwapError::Rejected(_),
        ));

        // Wrong beneficiary rejected.
        let mut cheque_wrong_ben = cheque2.clone();
        cheque_wrong_ben.beneficiary = [0xffu8; 20];
        cheque_wrong_ben.cumulative_payout = U256::from(160u64);
        let signed_wrong_ben = sign_cheque(&issuer_secret, &cheque_wrong_ben, 100).unwrap();
        assert!(matches!(
            ledger.record_accepted(&signed_wrong_ben).unwrap_err(),
            SwapError::Rejected(_),
        ));

        // Swapped issuer (attacker mints a cheque under same chequebook):
        // signature recovers to a different EOA → rejected by sticky binding.
        let attacker_secret = make_secret();
        let mut cheque_attack = cheque2.clone();
        cheque_attack.cumulative_payout = U256::from(200u64);
        let signed_attack = sign_cheque(&attacker_secret, &cheque_attack, 100).unwrap();
        let err = ledger.record_accepted(&signed_attack).unwrap_err();
        match err {
            SwapError::Rejected(msg) => assert!(
                msg.contains("issuer for chequebook"),
                "expected pinning rejection, got: {msg}",
            ),
            other => panic!("expected Rejected, got {other:?}"),
        }

        // The legit issuer can still issue a strictly-larger cheque.
        let mut cheque3 = cheque2;
        cheque3.cumulative_payout = U256::from(300u64);
        let signed3 = sign_cheque(&issuer_secret, &cheque3, 100).unwrap();
        let prev3 = ledger.record_accepted(&signed3).unwrap();
        assert_eq!(prev3, U256::from(150u64));
        assert_eq!(ledger.cumulative_for(&[0x77u8; 20]), U256::from(300u64));

        let _ = issuer_eoa; // silence unused — recovery already validates it
    }

    /// Persist + reload across "process restarts" preserves
    /// monotonicity. A replay of the highest cheque after restart
    /// must still be rejected.
    #[test]
    fn ledger_persistence_replay_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credits.json");
        let issuer_secret = make_secret();
        let our_eoa = [0xaau8; 20];

        let cheque = Cheque {
            chequebook: [0x77u8; 20],
            beneficiary: our_eoa,
            cumulative_payout: U256::from(500u64),
        };
        let signed = sign_cheque(&issuer_secret, &cheque, 100).unwrap();

        {
            let ledger = CreditLedger::open(Some(path.clone()), 100, our_eoa);
            ledger.record_accepted(&signed).unwrap();
        }

        // "Restart" — new ledger reads the snapshot.
        let ledger2 = CreditLedger::open(Some(path), 100, our_eoa);
        assert_eq!(
            ledger2.cumulative_for(&[0x77u8; 20]),
            U256::from(500u64),
            "snapshot must round-trip across restarts",
        );

        // Replay of the same cheque must be rejected as non-monotonic.
        let err = ledger2.record_accepted(&signed).unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)));
    }

    /// A damaged stored cumulative (bee#5656) is neither zero nor a
    /// permanent refusal: the next cheque becomes the baseline and credits
    /// nothing, so the re-sent old cheque isn't credited again in full,
    /// and later cheques credit their increase. The issuer pin still holds.
    #[test]
    fn a_damaged_inbound_cumulative_rebaselines_instead_of_reading_zero() {
        let issuer_secret = make_secret();
        let our_eoa = [0xaau8; 20];
        let cb = [0x77u8; 20];
        let cheque = |cum: u64, secret: &[u8; SECP256K1_SECRET_LEN]| {
            let c = Cheque {
                chequebook: cb,
                beneficiary: our_eoa,
                cumulative_payout: U256::from(cum),
            };
            sign_cheque(secret, &c, 100).unwrap()
        };
        for bad in ["", "abc", "-5", "1e3", " 7", &"9".repeat(80)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credits.json");
            CreditLedger::open(Some(path.clone()), 100, our_eoa)
                .record_accepted(&cheque(1_000, &issuer_secret))
                .unwrap();
            let mut snap: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            snap["cheques"][hex::encode(cb)]["cumulative_payout_dec"] = bad.into();
            std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();

            let ledger = CreditLedger::open(Some(path.clone()), 100, our_eoa);
            // Another key can't take the chequebook over while it's damaged.
            let attacker = make_secret();
            assert!(
                matches!(
                    ledger.record_accepted(&cheque(2_000, &attacker)),
                    Err(SwapError::Rejected(_))
                ),
                "{bad:?}: issuer pin lost",
            );
            // The old cheque, re-sent: accepted as the baseline, credits 0.
            let old = cheque(1_000, &issuer_secret);
            assert_eq!(
                ledger.would_accept(&old).unwrap(),
                U256::from(1_000u64),
                "{bad:?}"
            );
            assert_eq!(
                ledger.record_accepted(&old).unwrap(),
                U256::from(1_000u64),
                "{bad:?}: re-sent cheque credited again"
            );
            // Replayed again: now refused as non-monotonic.
            assert!(matches!(
                ledger.record_accepted(&old),
                Err(SwapError::Rejected(_))
            ));
            // A higher cheque credits only its increase, and survives a reopen.
            assert_eq!(
                ledger
                    .record_accepted(&cheque(1_200, &issuer_secret))
                    .unwrap(),
                U256::from(1_000u64),
                "{bad:?}"
            );
            let reopened = CreditLedger::open(Some(path), 100, our_eoa);
            assert_eq!(reopened.cumulative_for(&cb), U256::from(1_200u64));
        }
    }

    /// What [`rebaseline`]'s doc admits: after a damaged figure, a peer
    /// re-sending its older cheques in ascending order is credited the
    /// increases above the replayed baseline a second time, bounded by
    /// the lost figure, and the stored figure follows the replay down.
    /// Pinned so the doc and the behaviour can't drift apart again.
    #[test]
    fn a_replay_after_a_damaged_inbound_cumulative_is_bounded_by_the_lost_figure() {
        let issuer_secret = make_secret();
        let our_eoa = [0xaau8; 20];
        let cb = [0x78u8; 20];
        let cheque = |cum: u64| {
            let c = Cheque {
                chequebook: cb,
                beneficiary: our_eoa,
                cumulative_payout: U256::from(cum),
            };
            sign_cheque(&issuer_secret, &c, 100).unwrap()
        };
        let credit =
            |l: &CreditLedger, cum: u64| U256::from(cum) - l.record_accepted(&cheque(cum)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credits.json");
        let ledger = CreditLedger::open(Some(path.clone()), 100, our_eoa);
        let mut first = U256::zero();
        for cum in [1_000, 1_200, 1_500] {
            first += credit(&ledger, cum);
        }
        assert_eq!(first, U256::from(1_500u64));
        drop(ledger);
        let mut snap: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        snap["cheques"][hex::encode(cb)]["cumulative_payout_dec"] = "".into();
        std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();

        let ledger = CreditLedger::open(Some(path), 100, our_eoa);
        let mut replayed = U256::zero();
        for cum in [1_000, 1_200, 1_500] {
            replayed += credit(&ledger, cum);
        }
        // 1000 is the baseline (0); 1200 and 1500 credit 500 again.
        assert_eq!(replayed, U256::from(500u64));
        assert!(replayed <= U256::from(1_500u64 - 1_000));
        assert_eq!(ledger.cumulative_for(&cb), U256::from(1_500u64));
        // Past the lost figure, cheques credit only their real increase.
        assert_eq!(credit(&ledger, 1_700), U256::from(200u64));
    }

    /// Outbound ledger persists across restarts and rejects
    /// going-backwards mistakes by surfacing the previous value.
    #[test]
    fn outbound_ledger_persists_cumulative() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbound.json");
        let beneficiary = [0xbbu8; 20];

        {
            let ob = OutboundLedger::open(Some(path.clone()), [0xc1; 20]);
            assert_eq!(ob.cumulative_for(&beneficiary), U256::zero());
            ob.record_issued(&beneficiary, U256::from(42u64)).unwrap();
        }
        let ob2 = OutboundLedger::open(Some(path), [0xc1; 20]);
        assert_eq!(ob2.cumulative_for(&beneficiary), U256::from(42u64));
    }

    /// Cumulatives belong to the chequebook that issued them (PR #126
    /// R1-F1): another chequebook on the same file starts from zero and
    /// owes nothing, the first one's survive its writes, and a file from
    /// before the sections is adopted by exactly one chequebook.
    #[test]
    fn outbound_ledger_is_scoped_to_its_chequebook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (a, b) = ([0xa0u8; 20], [0xb0u8; 20]);
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"1500"}"#,
        )
        .unwrap();

        let ledger_a = OutboundLedger::open(Some(path.clone()), a);
        assert_eq!(ledger_a.cumulative_for(&peer), U256::from(1_500u64));
        let ledger_b = OutboundLedger::open(Some(path.clone()), b);
        assert_eq!(ledger_b.cumulative_for(&peer), U256::zero());
        assert_eq!(ledger_b.total_issued(), U256::zero());

        ledger_b.record_issued(&peer, U256::from(200u64)).unwrap();
        ledger_a.record_issued(&peer, U256::from(1_600u64)).unwrap();
        let reopened_b = OutboundLedger::open(Some(path.clone()), b);
        assert_eq!(reopened_b.cumulative_for(&peer), U256::from(200u64));
        let reopened_a = OutboundLedger::open(Some(path), a);
        assert_eq!(reopened_a.cumulative_for(&peer), U256::from(1_600u64));
        assert_eq!(reopened_a.total_issued(), U256::from(1_600u64));
    }

    /// A fresh marker that can't be parsed is neither read as "none fresh"
    /// (which would adopt the pre-section ledger into a fresh chequebook)
    /// nor left to stop every ledger on the file for good: it is kept
    /// aside and replaced by "adopt into none", and the pre-section
    /// figures count as lost until an operator confirms (PR #156 R2-M2).
    #[test]
    fn an_unparsable_fresh_marker_adopts_into_none_and_records_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (old, a, b) = ([0x01u8; 20], [0xa0u8; 20], [0xb0u8; 20]);
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"5543284090100"}"#,
        )
        .unwrap();
        note_fresh_chequebook(&path, a).unwrap();
        let marker = fresh_marker_path(&path);
        std::fs::write(&marker, b"{ not json").unwrap();

        // The load meets it first: replaced, and nobody adopts.
        let ledger = OutboundLedger::open(Some(path.clone()), a);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.cumulative_for(&peer), U256::zero(), "not adopted");
        assert!(ledger.lost_figures().is_some(), "gated until confirmed");
        let kept: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().into_string().unwrap();
                name.contains(".fresh.corrupt-").then_some(name)
            })
            .collect();
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(
            std::fs::read(dir.path().join(&kept[0])).unwrap(),
            b"{ not json",
            "the unparsable marker is kept"
        );
        drop(ledger);

        // A later deploy is recorded on the replaced marker, and isn't gated.
        note_fresh_chequebook(&path, b).unwrap();
        assert!(lost_figures_at(&path, &b).is_none());
        let fresh: Vec<String> = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        assert!(listed_fresh(&fresh, &hex::encode(b)));

        // The chequebook that wrote the pre-section figures doesn't get them
        // back either (it is gated, like after any loss), and the operator
        // path clears it — no file needs deleting by hand.
        let legacy = OutboundLedger::open(Some(path.clone()), old);
        assert_eq!(legacy.cumulative_for(&peer), U256::zero());
        assert!(legacy.lost_figures().is_some());
        assert!(confirm_cheque_liability(&path, a).unwrap());
        drop(legacy);
        let ledger = OutboundLedger::open(Some(path), a);
        assert!(ledger.lost_figures().is_none());
        assert_eq!(ledger.cumulative_for(&peer), U256::zero());
        ledger.record_issued(&peer, U256::from(7u64)).unwrap();
    }

    /// Without a pre-section ledger an unparsable fresh marker costs
    /// nothing: replaced, no loss recorded.
    #[test]
    fn an_unparsable_fresh_marker_without_a_legacy_ledger_records_no_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let a = [0xa0u8; 20];
        let ledger = OutboundLedger::open(Some(path.clone()), a);
        ledger
            .record_issued(&[0x11u8; 20], U256::from(9u64))
            .unwrap();
        drop(ledger);
        std::fs::write(fresh_marker_path(&path), b"{ not json").unwrap();

        note_fresh_chequebook(&path, [0xb0u8; 20]).unwrap();
        assert!(!lost_marker_path(&path).exists());
        let ledger = OutboundLedger::open(Some(path), a);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.cumulative_for(&[0x11u8; 20]), U256::from(9u64));
    }

    /// A fresh record that fails while a pre-section ledger is on the
    /// file doesn't clear the loss gate either: cleared, the chequebook
    /// would pay from those adopted cumulatives (PR #156 R2-M1).
    #[test]
    fn a_failed_fresh_record_with_a_legacy_ledger_keeps_the_loss_gate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"5543284090100"}"#,
        )
        .unwrap();
        // A loss on record (from some earlier move aside).
        mark_figures_lost(&path, &dir.path().join("earlier.corrupt")).unwrap();
        let cb = [0xc0u8; 20];
        // The fresh marker can't be written (a directory is in its way).
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();

        let err = note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(err.to_string().contains("fresh"), "{err}");
        assert!(err.to_string().contains("free tier"), "{err}");
        assert!(lost_figures_at(&path, &cb).is_some(), "still gated");
    }

    /// With no loss on record, a fresh record that fails while a
    /// pre-section ledger is on the file puts one on record for the new
    /// chequebook, sparing chequebooks with sections of their own; and
    /// until a restart this process doesn't adopt the ledger into it,
    /// retrying the record at each load (PR #156 R3-M1).
    #[test]
    fn a_failed_fresh_record_without_a_loss_on_record_gates_the_chequebook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (cb, other) = ([0xc0u8; 20], [0xd0u8; 20]);
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(
                r#"{{"{p}":"5543284090100","{o}:{p}":"3"}}"#,
                p = hex::encode(peer),
                o = hex::encode(other),
            ),
        )
        .unwrap();
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();

        let err = note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(err.to_string().contains("free tier"), "{err}");
        let why = lost_figures_at(&path, &cb).expect("gated");
        // Says what was lost, not that a ledger was moved aside (R4-M2).
        assert!(
            why.contains("deployed fresh but couldn't be recorded"),
            "{why}"
        );
        assert!(!why.contains("moved aside"), "{why}");
        assert!(
            lost_figures_at(&path, &other).is_none(),
            "own section, spared"
        );
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.cumulative_for(&peer), U256::zero(), "not adopted");
        drop(ledger);

        // Once the record can be written, the next load writes it.
        std::fs::remove_dir(fresh_marker_path(&path)).unwrap();
        drop(OutboundLedger::open(Some(path.clone()), cb));
        let fresh: Vec<String> =
            serde_json::from_slice(&std::fs::read(fresh_marker_path(&path)).unwrap()).unwrap();
        assert!(listed_fresh(&fresh, &hex::encode(cb)));
        // And the gate that stood in for the record is lifted (R4-M1).
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        assert!(
            ledger.lost_figures().is_none(),
            "{:?}",
            ledger.lost_figures()
        );
        assert_eq!(
            ledger.cumulative_for(&peer),
            U256::zero(),
            "still not adopted"
        );
    }

    /// The retried fresh record lifts the gate only while no loss came
    /// in after the deploy: once one did, the chequebook may have paid
    /// in between (after an operator confirmed it), so its figures may
    /// be lost and it stays gated (PR #156 R4-M1).
    #[test]
    fn a_retried_fresh_record_keeps_a_later_loss_gate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc2u8; 20];
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(r#"{{"{}":"5543284090100"}}"#, hex::encode(peer)),
        )
        .unwrap();
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();
        note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(lost_figures_at(&path, &cb).is_some(), "gated");
        // A later loss, after the operator confirmed it.
        assert!(confirm_cheque_liability(&path, cb).unwrap());
        mark_figures_lost(&path, &dir.path().join("later.corrupt")).unwrap();

        std::fs::remove_dir(fresh_marker_path(&path)).unwrap();
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        ledger.ensure_readable().unwrap();
        let why = ledger.lost_figures().expect("still gated");
        assert!(why.contains("moved aside to"), "{why}");
        assert!(why.contains("later.corrupt"), "{why}");
    }

    /// Make the next [`OutboundLedger::ensure_readable`] retry `cb`'s
    /// failed fresh record without waiting out [`FRESH_RETRY_INTERVAL`].
    fn rewind_fresh_retry(path: &Path, cb: [u8; 20]) {
        let key = hex::encode(cb);
        for u in unrecorded_fresh_set()
            .iter_mut()
            .filter(|u| u.path == path && u.key == key)
        {
            u.last_try = std::time::Instant::now()
                .checked_sub(FRESH_RETRY_INTERVAL)
                .unwrap_or(u.last_try);
        }
    }

    /// The fresh record is retried on a live ledger too, not only at a
    /// load: one opened while the record still failed has no later load
    /// to retry it, so without this the gate stood until a restart made
    /// it permanent (PR #156 R5-M1).
    #[test]
    fn a_live_ledger_retries_a_failed_fresh_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc4u8; 20];
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(r#"{{"{}":"5543284090100"}}"#, hex::encode(peer)),
        )
        .unwrap();
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();
        note_fresh_chequebook(&path, cb).unwrap_err();
        // The ledger goes live while the record still fails.
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        ledger.ensure_readable().unwrap();
        assert!(ledger.lost_figures().is_some(), "gated");

        // The fault clears; the next retry is spaced out...
        std::fs::remove_dir(fresh_marker_path(&path)).unwrap();
        ledger.ensure_readable().unwrap();
        assert!(!fresh_marker_path(&path).exists(), "not retried yet");
        // ...and once due, the live ledger writes it and lifts the gate.
        rewind_fresh_retry(&path, cb);
        ledger.ensure_readable().unwrap();
        let fresh: Vec<String> =
            serde_json::from_slice(&std::fs::read(fresh_marker_path(&path)).unwrap()).unwrap();
        assert!(listed_fresh(&fresh, &hex::encode(cb)));
        assert!(
            ledger.lost_figures().is_none(),
            "{:?}",
            ledger.lost_figures()
        );
        assert_eq!(ledger.cumulative_for(&peer), U256::zero(), "not adopted");
    }

    /// A later loss hidden by a marker replaced when unparsable (its
    /// loss list starts over at one entry) still keeps the gate: the
    /// retried record lifts it only if the losses on record are exactly
    /// those at the deploy (PR #156 R5-M2).
    #[test]
    fn a_retried_fresh_record_keeps_a_loss_hidden_by_a_replaced_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (cb, other) = ([0xc5u8; 20], [0xd5u8; 20]);
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"5543284090100"}"#,
        )
        .unwrap();
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();
        note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(lost_figures_at(&path, &cb).is_some(), "gated");
        // Confirmed, then a later loss; then the marker is corrupted and a
        // confirm of another chequebook replaces it with one loss again.
        assert!(confirm_cheque_liability(&path, cb).unwrap());
        mark_figures_lost(&path, &dir.path().join("later.corrupt")).unwrap();
        std::fs::write(lost_marker_path(&path), b"{ not json").unwrap();
        assert!(confirm_cheque_liability(&path, other).unwrap());
        assert_eq!(
            read_lost_marker(&path).unwrap().unwrap().moved_aside.len(),
            1
        );

        std::fs::remove_dir(fresh_marker_path(&path)).unwrap();
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        ledger.ensure_readable().unwrap();
        let fresh: Vec<String> =
            serde_json::from_slice(&std::fs::read(fresh_marker_path(&path)).unwrap()).unwrap();
        assert!(listed_fresh(&fresh, &hex::encode(cb)), "recorded");
        let why = ledger.lost_figures().expect("still gated");
        assert!(why.contains("unreadable"), "{why}");
    }

    /// A loss already on record when the fresh record fails predates the
    /// deploy, so the retried record lifts the gate on it too (R4-M1).
    #[test]
    fn a_retried_fresh_record_lifts_an_earlier_loss_gate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"5543284090100"}"#,
        )
        .unwrap();
        mark_figures_lost(&path, &dir.path().join("earlier.corrupt")).unwrap();
        let cb = [0xc3u8; 20];
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();
        note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(lost_figures_at(&path, &cb).is_some(), "gated");

        std::fs::remove_dir(fresh_marker_path(&path)).unwrap();
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        ledger.ensure_readable().unwrap();
        assert!(
            ledger.lost_figures().is_none(),
            "{:?}",
            ledger.lost_figures()
        );
    }

    /// Nothing can be written at all (a read-only data dir): the deploy
    /// still adopts nothing in this process.
    #[cfg(unix)]
    #[test]
    fn a_fresh_record_on_a_read_only_dir_still_adopts_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(r#"{{"{}":"5543284090100"}}"#, hex::encode(peer)),
        )
        .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.path().join("probe"), b"").is_ok() {
            // Running as root: permissions don't stop writes.
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let err = note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(err.to_string().contains("after a restart"), "{err}");
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(ledger.cumulative_for(&peer), U256::zero(), "not adopted");
        drop(ledger);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// An unparsable fresh marker's loss gates only the chequebook that may
    /// own the pre-section figures: one with a section of its own didn't
    /// adopt them, so it stays known — unless it was already lost (PR #156
    /// R3-M2).
    #[test]
    fn an_unparsable_fresh_marker_spares_chequebooks_with_their_own_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (old, a, lost) = ([0x01u8; 20], [0xa0u8; 20], [0xe0u8; 20]);
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(
                r#"{{"{p}":"5543284090100","{a}:{p}":"4","{l}:{p}":"6"}}"#,
                p = hex::encode(peer),
                a = hex::encode(a),
                l = hex::encode(lost),
            ),
        )
        .unwrap();
        // `lost` is lost to an earlier loss, `a` was deployed after it.
        mark_figures_lost(&path, &dir.path().join("earlier.corrupt")).unwrap();
        note_fresh_chequebook(&path, a).unwrap();
        std::fs::write(fresh_marker_path(&path), b"{ not json").unwrap();

        let ledger = OutboundLedger::open(Some(path.clone()), a);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.cumulative_for(&peer), U256::from(4u64));
        assert!(ledger.lost_figures().is_none(), "own section: spared");
        assert!(lost_figures_at(&path, &lost).is_some(), "still lost");
        assert!(
            lost_figures_at(&path, &old).is_some(),
            "may own them: gated"
        );
    }

    /// A deploy whose fresh record fails is still recorded as known in
    /// the lost-ledger marker, so it isn't held behind the loss gate.
    #[test]
    fn a_failed_fresh_record_still_clears_the_loss_gate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let old = OutboundLedger::open(Some(path.clone()), [0xa1u8; 20]);
        old.record_issued(&[0x22u8; 20], U256::from(5u64)).unwrap();
        drop(old);
        // Lose the ledger.
        std::fs::write(&path, b"{ not json").unwrap();
        drop(OutboundLedger::open(Some(path.clone()), [0xa2; 20]));
        let cb = [0xc0u8; 20];
        assert!(lost_figures_at(&path, &cb).is_some(), "lost before deploy");
        // The fresh marker can't be written (a directory is in its way).
        std::fs::create_dir(fresh_marker_path(&path)).unwrap();

        let err = note_fresh_chequebook(&path, cb).unwrap_err();
        assert!(err.to_string().contains("fresh"), "{err}");
        assert!(
            lost_figures_at(&path, &cb).is_none(),
            "still recorded as known"
        );
    }

    /// A chequebook deployed fresh never adopts a ledger written before
    /// per-chequebook sections: those cumulatives came from an earlier
    /// chequebook, and as the new one's first cheques they would claim
    /// totals it never paid (and drain its deposit in our own funds
    /// check). A chequebook that was not deployed fresh still adopts it.
    #[test]
    fn a_fresh_chequebook_never_adopts_the_pre_section_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (old, fresh) = ([0xa0u8; 20], [0xf0u8; 20]);
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            br#"{"1111111111111111111111111111111111111111":"5543284090100"}"#,
        )
        .unwrap();

        note_fresh_chequebook(&path, fresh).unwrap();
        let ledger = OutboundLedger::open(Some(path.clone()), fresh);
        assert_eq!(ledger.cumulative_for(&peer), U256::zero());
        assert_eq!(ledger.total_issued(), U256::zero());
        ledger.record_issued(&peer, U256::from(250_000u64)).unwrap();
        drop(ledger);

        // Across a restart it still starts from what it really issued.
        let reopened = OutboundLedger::open(Some(path.clone()), fresh);
        assert_eq!(reopened.cumulative_for(&peer), U256::from(250_000u64));
        assert_eq!(reopened.total_issued(), U256::from(250_000u64));
        drop(reopened);

        // The pre-section figures are still there for the chequebook that
        // wrote them.
        let legacy = OutboundLedger::open(Some(path), old);
        assert_eq!(
            legacy.cumulative_for(&peer),
            U256::from(5_543_284_090_100u64)
        );
    }

    /// A file that exists but can't be read is not an empty ledger (PR
    /// #126 R2-F1): the ledger opened on it refuses to issue, and nothing
    /// writes over it — another chequebook's cheques go to the journal
    /// (issue #140), and a compaction, which would rewrite the file,
    /// fails instead. Once readable, every figure is where it was.
    #[cfg(unix)]
    #[test]
    fn outbound_ledger_never_overwrites_a_file_it_could_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (a, b) = ([0xa0u8; 20], [0xb0u8; 20]);
        let peer = [0x11u8; 20];
        {
            let ledger_a = OutboundLedger::open(Some(path.clone()), a);
            ledger_a.record_issued(&peer, U256::from(1_500u64)).unwrap();
        }
        let ledger_b = OutboundLedger::open(Some(path.clone()), b);
        ledger_b.record_issued(&peer, U256::from(200u64)).unwrap();

        let set_mode = |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m));
        set_mode(0o000).unwrap();
        if std::fs::read(&path).is_ok() {
            // Running as root: permissions don't fake a failed read.
            set_mode(0o600).unwrap();
            return;
        }
        // A's ledger opened on the unreadable file can't issue.
        let ledger_a = OutboundLedger::open(Some(path.clone()), a);
        assert!(ledger_a.ensure_readable().is_err());
        // B's cheque is journaled; the file isn't touched.
        ledger_b.record_issued(&peer, U256::from(300u64)).unwrap();
        let store = ledger_b.shared.store.clone().unwrap();
        assert!(
            {
                let _file = lock_file();
                store.compact_locked()
            }
            .is_err(),
            "a compaction can't rewrite a file it can't read"
        );
        set_mode(0o600).unwrap();

        let on_disk = read_outbound_file(&path).unwrap().unwrap();
        assert_eq!(
            on_disk.chequebooks[&hex::encode(a)][&hex::encode(peer)],
            "1500"
        );
        assert!(!on_disk.chequebooks.contains_key(&hex::encode(b)));
        // Readable again: A sees its cumulatives, B's next cheque lands.
        ledger_a.ensure_readable().unwrap();
        assert_eq!(ledger_a.cumulative_for(&peer), U256::from(1_500u64));
        ledger_b.record_issued(&peer, U256::from(400u64)).unwrap();
        drop((ledger_a, ledger_b, store));
        let on_disk = read_outbound_file(&path).unwrap().unwrap();
        assert_eq!(
            on_disk.chequebooks[&hex::encode(b)][&hex::encode(peer)],
            "400",
            "the last ledger closing folds the journal into the file"
        );
        let reopened_a = OutboundLedger::open(Some(path.clone()), a);
        assert_eq!(reopened_a.total_issued(), U256::from(1_500u64));
        let reopened_b = OutboundLedger::open(Some(path), b);
        assert_eq!(reopened_b.cumulative_for(&peer), U256::from(400u64));
    }

    /// Two ledgers on the same chequebook and file (settlement disabled
    /// and re-enabled while the old service finishes a cheque) share
    /// one state (PR #126 R2-M2): each sees the other's latest
    /// cumulative, and neither writes back a stale one.
    #[test]
    fn outbound_ledgers_on_one_chequebook_share_their_cumulatives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let (p, q) = ([0x11u8; 20], [0x22u8; 20]);
        let old = OutboundLedger::open(Some(path.clone()), cb);
        let new = OutboundLedger::open(Some(path.clone()), cb);
        new.record_issued(&p, U256::from(100u64)).unwrap();
        old.record_issued(&p, U256::from(250u64)).unwrap();
        assert_eq!(new.cumulative_for(&p), U256::from(250u64));
        new.record_issued(&q, U256::from(10u64)).unwrap();
        assert_eq!(new.total_issued(), U256::from(260u64));
        drop((old, new));
        let reopened = OutboundLedger::open(Some(path), cb);
        assert_eq!(reopened.cumulative_for(&p), U256::from(250u64));
        assert_eq!(reopened.cumulative_for(&q), U256::from(10u64));
    }

    /// Ledgers on one chequebook share the locks that serialise issuing,
    /// not just the figures (PR #126 R3-M1): an old service's cheque and
    /// a new service's to the same beneficiary queue on one lock, and
    /// both services' funds checks on one gate.
    #[test]
    fn outbound_ledgers_on_one_chequebook_share_their_issue_locks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let peer = [0x11u8; 20];
        let old = OutboundLedger::open(Some(path.clone()), [0xc1; 20]);
        let new = OutboundLedger::open(Some(path.clone()), [0xc1; 20]);
        let other = OutboundLedger::open(Some(path), [0xc2; 20]);

        let held = old.beneficiary_lock(peer);
        let _issuing = held.try_lock().unwrap();
        assert!(new.beneficiary_lock(peer).try_lock().is_err());
        assert!(new.beneficiary_lock([0x22; 20]).try_lock().is_ok());
        assert!(other.beneficiary_lock(peer).try_lock().is_ok());

        let _gate = old.funds_gate();
        assert!(new.shared.funds.try_lock().is_err());
        assert!(other.shared.funds.try_lock().is_ok());
    }

    /// A ledger file that isn't JSON (PR #126 R3-M2) is moved aside, not
    /// left blocking every cheque until it is repaired by hand: the
    /// ledger opens readable, starts from zero and writes a fresh file,
    /// and the broken bytes are kept next to it.
    #[test]
    fn an_unparseable_outbound_ledger_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let peer = [0x11u8; 20];
        std::fs::write(&path, b"{ not json").unwrap();

        let ledger = OutboundLedger::open(Some(path.clone()), [0xc1; 20]);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.total_issued(), U256::zero());
        ledger.record_issued(&peer, U256::from(70u64)).unwrap();

        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("pushsync_outbound.json.corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(
            std::fs::read(dir.path().join(&aside[0])).unwrap(),
            b"{ not json"
        );
        drop(ledger);
        let reopened = OutboundLedger::open(Some(path), [0xc1; 20]);
        assert_eq!(reopened.cumulative_for(&peer), U256::from(70u64));
    }

    /// A stored cumulative that isn't a decimal number (bee#5656) is a
    /// loss, not an absent entry: read as absent, the next cheque would
    /// restart from zero and a write would replace the real figure. Both
    /// on-disk shapes are checked; the file is moved aside and the
    /// chequebook's figures count as lost until confirmed.
    #[test]
    fn a_non_numeric_cumulative_is_a_loss_not_zero() {
        let cb = [0xc1u8; 20];
        let peer = [0x11u8; 20];
        let good = format!("{}:{}", hex::encode(cb), hex::encode([0x22u8; 20]));
        let bad_key = format!("{}:{}", hex::encode(cb), hex::encode(peer));
        for bad in ["", "abc", "-5", "1e3", " 7", &"9".repeat(80)] {
            for nested in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("pushsync_outbound.json");
                let body = if nested {
                    serde_json::json!({"chequebooks": {hex::encode(cb): {
                        hex::encode([0x22u8; 20]): "40",
                        hex::encode(peer): bad,
                    }}})
                } else {
                    serde_json::json!({ good.clone(): "40", bad_key.clone(): bad })
                };
                let bytes = serde_json::to_vec(&body).unwrap();
                std::fs::write(&path, &bytes).unwrap();

                let ledger = OutboundLedger::open(Some(path.clone()), cb);
                ledger.ensure_readable().unwrap();
                let why = ledger.lost_figures();
                assert!(why.is_some(), "{bad:?} nested={nested}: not a loss");
                assert!(!path.exists(), "{bad:?} nested={nested}: not moved");
                let aside: Vec<_> = std::fs::read_dir(dir.path())
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .filter(|n| n.starts_with("pushsync_outbound.json.corrupt-"))
                    .collect();
                assert_eq!(aside.len(), 1, "{bad:?} nested={nested}: {aside:?}");
                assert_eq!(std::fs::read(dir.path().join(&aside[0])).unwrap(), bytes);
            }
        }
    }

    /// A journal line whose cumulative isn't a decimal number is a damaged
    /// journal: moved aside, the figures lost, like an unparseable line.
    #[test]
    fn a_journal_line_with_a_non_numeric_cumulative_is_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(10u64)).unwrap();
        crash(&path, [l]);
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        let line = format!(
            "{{\"{}:{}\":\"abc\"}}\n",
            hex::encode(cb),
            hex::encode(beneficiary(1))
        );
        std::io::Write::write_all(&mut j, line.as_bytes()).unwrap();
        drop(j);

        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.ensure_readable().unwrap();
        assert!(l.lost_figures().is_some());
        assert!(!journal_path(&path).exists(), "journal not moved aside");
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert!(std::fs::read_to_string(dir.path().join(&aside[0]))
            .unwrap()
            .contains("\"abc\""));
    }

    /// Moving a ledger aside loses its chequebooks' figures (PR #126
    /// R4-M1): every chequebook on the file reports them lost — across a
    /// restart, since only an operator clears it — until its liability is
    /// confirmed, one chequebook at a time; a later loss makes every
    /// chequebook unknown again. Ledgers on other files are untouched.
    #[test]
    fn a_lost_ledger_stays_lost_until_the_operator_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (a, b) = ([0xa0u8; 20], [0xb0u8; 20]);
        let peer = [0x11u8; 20];
        let fresh = OutboundLedger::open(Some(path.clone()), a);
        assert!(fresh.lost_figures().is_none(), "no loss without a move");
        fresh.record_issued(&peer, U256::from(500u64)).unwrap();
        drop(fresh);

        std::fs::write(&path, b"{ not json").unwrap();
        let la = OutboundLedger::open(Some(path.clone()), a);
        let why = la.lost_figures().expect("a's figures are lost");
        assert!(why.contains(&hex::encode(a)), "{why}");
        assert!(why.contains("--confirm-cheque-liability"), "{why}");
        let lb = OutboundLedger::open(Some(path.clone()), b);
        assert!(lb.lost_figures().is_some(), "so are b's");
        // Pushsync still works on the restarted figures.
        la.record_issued(&peer, U256::from(10u64)).unwrap();
        assert!(la.lost_figures().is_some(), "a write doesn't clear it");
        drop((la, lb));
        let la = OutboundLedger::open(Some(path.clone()), a);
        assert!(la.lost_figures().is_some(), "a restart doesn't clear it");

        assert!(confirm_cheque_liability(&path, a).unwrap());
        assert!(la.lost_figures().is_none());
        assert!(
            !confirm_cheque_liability(&path, a).unwrap(),
            "already confirmed"
        );
        let lb = OutboundLedger::open(Some(path.clone()), b);
        assert!(lb.lost_figures().is_some(), "only the confirmed chequebook");

        let other = dir.path().join("other.json");
        assert!(
            !confirm_cheque_liability(&other, a).unwrap(),
            "nothing lost there"
        );
        assert!(OutboundLedger::open(Some(other), a)
            .lost_figures()
            .is_none());

        // A second loss makes the confirmed chequebook unknown again.
        drop((la, lb));
        std::fs::write(&path, b"{ broken again").unwrap();
        let la = OutboundLedger::open(Some(path.clone()), a);
        assert!(la.lost_figures().is_some());
        let marker: LostMarker =
            serde_json::from_slice(&std::fs::read(lost_marker_path(&path)).unwrap()).unwrap();
        assert_eq!(marker.moved_aside.len(), 2, "both copies are named");

        // A marker that can't be parsed counts as a loss, for every
        // chequebook (PR #126 R1-M2)...
        std::fs::write(lost_marker_path(&path), b"garbage").unwrap();
        let why = la.lost_figures().expect("unparseable marker is a loss");
        assert!(why.contains("--confirm-cheque-liability"), "{why}");
        // ...and confirming replaces it, clearing only that chequebook.
        assert!(confirm_cheque_liability(&path, a).unwrap());
        assert!(la.lost_figures().is_none());
        let lb = OutboundLedger::open(Some(path.clone()), b);
        assert!(lb.lost_figures().is_some(), "b stays lost");
        let marker: LostMarker =
            serde_json::from_slice(&std::fs::read(lost_marker_path(&path)).unwrap()).unwrap();
        assert!(
            marker.moved_aside[0].contains("unreadable"),
            "{:?}",
            marker.moved_aside
        );
        // A loss on top of an unparseable marker still records itself.
        drop((la, lb));
        std::fs::write(lost_marker_path(&path), b"garbage").unwrap();
        std::fs::write(&path, b"{ broken a third time").unwrap();
        let la = OutboundLedger::open(Some(path.clone()), a);
        assert!(la.lost_figures().is_some());
        let marker: LostMarker =
            serde_json::from_slice(&std::fs::read(lost_marker_path(&path)).unwrap()).unwrap();
        assert_eq!(marker.moved_aside.len(), 2, "{:?}", marker.moved_aside);
    }

    /// A loss only applies to chequebooks whose figures it took (PR #126
    /// R1-M3): one deployed afterwards has issued nothing, and one whose
    /// ledger was open keeps its figures in memory — at once for this
    /// run, and across a restart once it has rewritten them. A ledger
    /// opened only after the loss is still lost.
    #[test]
    fn a_loss_spares_chequebooks_whose_figures_are_known() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (live, closed, fresh) = ([0xa1u8; 20], [0xa2u8; 20], [0xa3u8; 20]);
        let peer = [0x11u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), live);
        l.record_issued(&peer, U256::from(500u64)).unwrap();
        let c = OutboundLedger::open(Some(path.clone()), closed);
        c.record_issued(&peer, U256::from(70u64)).unwrap();
        drop(c);

        // The file is lost under the running ledger; another open reads it.
        std::fs::write(&path, b"{ not json").unwrap();
        let c = OutboundLedger::open(Some(path.clone()), closed);
        assert!(
            c.lost_figures().is_some(),
            "closed chequebook's figures are gone"
        );
        assert!(
            l.lost_figures().is_none(),
            "live figures survived in memory"
        );
        assert_eq!(l.cumulative_for(&peer), U256::from(500u64));

        // Not yet on disk: a restart before the next cheque counts it lost.
        let marker: LostMarker =
            serde_json::from_slice(&std::fs::read(lost_marker_path(&path)).unwrap()).unwrap();
        assert!(marker.known.is_empty(), "{:?}", marker.known);
        l.record_issued(&peer, U256::from(600u64)).unwrap();
        drop(l);
        let l = OutboundLedger::open(Some(path.clone()), live);
        assert_eq!(l.cumulative_for(&peer), U256::from(600u64));
        assert!(
            l.lost_figures().is_none(),
            "rewritten, so known across a restart"
        );
        assert!(c.lost_figures().is_some());

        // A chequebook deployed after the loss.
        note_fresh_chequebook(&path, fresh).unwrap();
        assert!(OutboundLedger::open(Some(path.clone()), fresh)
            .lost_figures()
            .is_none());
        // Nothing to note without a loss on record.
        let other = dir.path().join("other.json");
        note_fresh_chequebook(&other, fresh).unwrap();
        assert!(!lost_marker_path(&other).exists());

        // A later loss makes them all unknown again.
        drop((l, c));
        std::fs::write(&path, b"{ broken again").unwrap();
        for cb in [live, closed, fresh] {
            assert!(OutboundLedger::open(Some(path.clone()), cb)
                .lost_figures()
                .is_some());
        }
    }

    /// A ledger still lost to an earlier loss holds only what it issued
    /// since, so a second loss under it must not count it as a survivor
    /// (PR #126 R2-F1): retrieval would then pay its peers from a
    /// restarted cumulative they refuse.
    #[test]
    fn a_second_loss_does_not_exempt_a_still_lost_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xb1u8; 20];
        let peer = [0x22u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&peer, U256::from(900u64)).unwrap();
        drop(l);

        // Loss 1, then a restart: lost, and pushsync issues from zero.
        std::fs::write(&path, b"{ not json").unwrap();
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some());
        l.record_issued(&peer, U256::from(100u64)).unwrap();
        assert!(l.lost_figures().is_some());

        // Loss 2 while it runs: still lost, now and after its next write.
        std::fs::write(&path, b"{ broken again").unwrap();
        let other = OutboundLedger::open(Some(path.clone()), [0xb2u8; 20]);
        assert!(other.lost_figures().is_some());
        assert!(l.lost_figures().is_some(), "not a survivor of loss 2");
        l.record_issued(&peer, U256::from(200u64)).unwrap();
        assert!(l.lost_figures().is_some());
        let marker: LostMarker =
            serde_json::from_slice(&std::fs::read(lost_marker_path(&path)).unwrap()).unwrap();
        assert!(marker.known.is_empty(), "{:?}", marker.known);
        drop((l, other));
        assert!(OutboundLedger::open(Some(path.clone()), cb)
            .lost_figures()
            .is_some());

        // Once confirmed, its figures are known again and survive a loss.
        confirm_cheque_liability(&path, cb).unwrap();
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_none());
        std::fs::write(&path, b"{ broken a third time").unwrap();
        drop(OutboundLedger::open(Some(path.clone()), [0xb3u8; 20]));
        assert!(l.lost_figures().is_none(), "known figures survive");
    }

    /// The marker is re-read when it changes, including by hand, though
    /// [`OutboundLedger::lost_figures`] caches it (PR #126 R1-M1).
    #[test]
    fn lost_figures_follows_marker_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xd1u8; 20];
        std::fs::write(&path, b"{ not json").unwrap();
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some());
        assert!(l.lost_figures().is_some(), "cached read agrees");
        std::fs::remove_file(lost_marker_path(&path)).unwrap();
        assert!(l.lost_figures().is_none(), "a deleted marker is seen");
        std::fs::write(lost_marker_path(&path), b"x").unwrap();
        assert!(l.lost_figures().is_some(), "so is a new one");
    }

    /// `lost_figures` doesn't wait for the outbound file lock, which a
    /// cheque's rewrite + fsync holds (PR #126 R1-M1).
    #[test]
    fn lost_figures_does_not_take_the_file_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let l = OutboundLedger::open(Some(path), [0xd2u8; 20]);
        let (tx, rx) = std::sync::mpsc::channel();
        let held = lock_file();
        std::thread::spawn(move || {
            let _ = tx.send(l.lost_figures());
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5));
        drop(held);
        assert!(matches!(got, Ok(None)), "{got:?}");
    }

    /// Moving a broken ledger aside never replaces an earlier copy (PR
    /// #126 R4-M2): a name already taken for this second gets a suffix.
    #[test]
    fn moving_a_ledger_aside_keeps_every_earlier_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Earlier copies under this second's and the next second's names.
        for s in [secs, secs + 1] {
            std::fs::write(
                dir.path()
                    .join(format!("pushsync_outbound.json.corrupt-{s}")),
                format!("earlier {s}"),
            )
            .unwrap();
        }
        for (cb, junk) in [([0xc1u8; 20], "{ first"), ([0xc2u8; 20], "{ second")] {
            std::fs::write(&path, junk).unwrap();
            OutboundLedger::open(Some(path.clone()), cb)
                .ensure_readable()
                .unwrap();
        }
        let mut kept: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p != &path && *p != lost_marker_path(&path))
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                "earlier ".to_string() + &secs.to_string(),
                "earlier ".to_string() + &(secs + 1).to_string(),
                "{ first".into(),
                "{ second".into(),
            ]
        );
    }

    /// A release from before the sections still parses the file and
    /// keeps every chequebook's figures when it rewrites it (PR #126
    /// R4-M3); whatever it adds is adopted again after the upgrade.
    #[test]
    fn a_downgraded_release_keeps_every_chequebooks_cumulatives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (a, b) = ([0xa0u8; 20], [0xb0u8; 20]);
        let (p, q) = ([0x11u8; 20], [0x22u8; 20]);
        {
            let la = OutboundLedger::open(Some(path.clone()), a);
            la.record_issued(&p, U256::from(1_500u64)).unwrap();
            la.record_issued(&q, U256::from(40u64)).unwrap();
            OutboundLedger::open(Some(path.clone()), b)
                .record_issued(&p, U256::from(200u64))
                .unwrap();
        }

        // The pre-PR release's open + record_issued, verbatim in effect:
        // parse a flat string map, keep every decimal entry, insert its
        // own bare-beneficiary cumulative and write the map back.
        let mut old: HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(&path).unwrap())
                .expect("a pre-section release must parse the file");
        old.retain(|_, v| U256::from_dec_str(v).is_ok());
        assert_eq!(old.len(), 3, "{old:?}");
        old.insert(hex::encode(q), "90".into());
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();

        let la = OutboundLedger::open(Some(path.clone()), a);
        assert_eq!(la.cumulative_for(&p), U256::from(1_500u64));
        // The downgraded release's larger figure for q wins.
        assert_eq!(la.cumulative_for(&q), U256::from(90u64));
        let lb = OutboundLedger::open(Some(path.clone()), b);
        assert_eq!(lb.cumulative_for(&p), U256::from(200u64));
        assert_eq!(lb.cumulative_for(&q), U256::zero());
        drop((la, lb));
        let flat: HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(flat.keys().all(|k| k.contains(':')), "{flat:?}");
    }

    /// What a process crash leaves of `ledgers` on `path`: whatever is on
    /// disk. Nothing is closed (no compaction at close), and the
    /// process-wide state on the file is forgotten, so the next open reads
    /// the disk like a restarted process would.
    fn crash(path: &Path, ledgers: impl IntoIterator<Item = OutboundLedger>) {
        for l in ledgers {
            // A crash runs no destructors.
            #[allow(clippy::mem_forget)]
            std::mem::forget(l);
        }
        OUTBOUND_LEDGERS
            .lock()
            .unwrap()
            .retain(|((p, _), _)| p != path);
        JOURNALS.lock().unwrap().retain(|(p, _)| p != path);
    }

    fn flat_ledger(chequebook: [u8; 20], entries: u32) -> Vec<u8> {
        let map: HashMap<String, String> = (0..entries)
            .map(|i| {
                let mut b = [0u8; 20];
                b[..4].copy_from_slice(&i.to_be_bytes());
                (
                    format!("{}:{}", hex::encode(chequebook), hex::encode(b)),
                    (1_000_000_000u64 + u64::from(i)).to_string(),
                )
            })
            .collect();
        serde_json::to_vec_pretty(&map).unwrap()
    }

    fn beneficiary(i: u32) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    /// A cheque costs one journal line, whatever the ledger's size (issue
    /// #140): the file isn't read or rewritten, and the line is on disk
    /// when `record_issued` returns.
    #[test]
    fn a_cheque_appends_one_line_and_leaves_the_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let snapshot = flat_ledger(cb, 2_000);
        std::fs::write(&path, &snapshot).unwrap();
        let ledger = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(
            ledger.cumulative_for(&beneficiary(7)),
            U256::from(1_000_000_007u64)
        );
        for i in 0..3u32 {
            ledger
                .record_issued(&beneficiary(i), U256::from(2_000_000_000u64 + u64::from(i)))
                .unwrap();
        }
        ledger
            .record_issued(&beneficiary(5_000), U256::from(9u64))
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), snapshot, "file untouched");
        let journal = std::fs::read_to_string(journal_path(&path)).unwrap();
        assert_eq!(
            journal
                .lines()
                .filter(|l| commit_mark(l.as_bytes()).is_none())
                .count(),
            4,
            "{journal}"
        );
        assert!(journal.ends_with(&format!(
            "{{\"{}:{}\":\"9\"}}\n#4\n",
            hex::encode(cb),
            hex::encode(beneficiary(5_000))
        )));
        let expected = (0..2_000u64)
            .map(|i| 1_000_000_000 + i)
            .chain([1_000_000_000, 1_000_000_000, 1_000_000_000])
            .sum::<u64>()
            + 9;
        assert_eq!(ledger.total_issued(), U256::from(expected));
    }

    /// Child half of [`a_cheque_on_disk_survives_a_crash`]: issue cheques
    /// from several threads, print each one once it may be sent, and
    /// abort mid-stream.
    #[test]
    #[ignore = "run by a_cheque_on_disk_survives_a_crash in a child process"]
    fn crash_child_issues_then_aborts() {
        use std::io::Write as _;
        let Ok(path) = std::env::var("ANT_LEDGER_CRASH_PATH") else {
            return;
        };
        let ledger = OutboundLedger::open(Some(PathBuf::from(path)), [0xc1; 20]);
        let acked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for t in 0..8u32 {
            let ledger = ledger.clone();
            let acked = acked.clone();
            std::thread::spawn(move || {
                for i in 1..=10_000u64 {
                    let b = beneficiary(t * 1_000 + u32::try_from(i % 50).unwrap());
                    let cum = U256::from(i * 1_000 + u64::from(t));
                    ledger.stage_issued(&b, cum).wait().unwrap();
                    let mut out = std::io::stdout().lock();
                    writeln!(out, "ACK {} {cum}", hex::encode(b)).unwrap();
                    out.flush().unwrap();
                    acked.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        while acked.load(Ordering::SeqCst) < 400 {
            std::thread::yield_now();
        }
        std::process::abort();
    }

    /// Crash safety: a cheque cleared to go out (its record durable) is
    /// on disk after the process dies — a real `abort()` in a child
    /// process, with 8 threads issuing concurrently and lines in flight.
    #[test]
    fn a_cheque_on_disk_survives_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        std::fs::write(&path, flat_ledger([0xc1; 20], 500)).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "swap::tests::crash_child_issues_then_aborts",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ANT_LEDGER_CRASH_PATH", &path)
            .output()
            .unwrap();
        assert!(!out.status.success(), "the child must have aborted");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut acked: HashMap<String, U256> = HashMap::new();
        for line in stdout.lines().filter_map(|l| l.strip_prefix("ACK ")) {
            let (b, cum) = line.split_once(' ').unwrap();
            let cum = U256::from_dec_str(cum).unwrap();
            let e = acked.entry(b.to_string()).or_default();
            *e = (*e).max(cum);
        }
        assert!(acked.len() >= 50, "{} acked", acked.len());
        let ledger = OutboundLedger::open(Some(path), [0xc1; 20]);
        ledger.ensure_readable().unwrap();
        for (b, cum) in &acked {
            let b: [u8; 20] = hex::decode(b).unwrap().try_into().unwrap();
            assert!(ledger.cumulative_for(&b) >= *cum, "lost a sent cheque");
        }
        assert_eq!(
            ledger.cumulative_for(&beneficiary(499)),
            U256::from(1_000_000_499u64),
            "the file's figures are still there"
        );
    }

    /// Concurrent issuers on two ledgers of one chequebook and a second
    /// chequebook on the same file lose nothing — not to each other, not
    /// to a compaction running meanwhile, not to a crash right after.
    #[test]
    fn concurrent_issuers_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let (a, b) = ([0xa0u8; 20], [0xb0u8; 20]);
        std::fs::write(&path, flat_ledger(a, 300)).unwrap();
        let a1 = OutboundLedger::open(Some(path.clone()), a);
        let a2 = OutboundLedger::open(Some(path.clone()), a);
        let lb = OutboundLedger::open(Some(path.clone()), b);
        let store = a1.shared.store.clone().unwrap();
        std::thread::scope(|s| {
            for t in 0..12u32 {
                let l = [&a1, &a2, &lb][t as usize % 3].clone();
                s.spawn(move || {
                    for i in 1..=40u64 {
                        // Each thread has its own beneficiaries, so the
                        // last figure it wrote is the one to find.
                        let ben = beneficiary(10_000 + t * 10 + u32::try_from(i % 10).unwrap());
                        l.record_issued(&ben, U256::from(i)).unwrap();
                    }
                });
            }
            s.spawn(|| {
                for _ in 0..5 {
                    let _file = lock_file();
                    store.compact_locked().unwrap();
                }
            });
        });
        let issued_a: u64 =
            (0..300u64).map(|i| 1_000_000_000 + i).sum::<u64>() + 8 * (31..=40u64).sum::<u64>();
        assert_eq!(a1.total_issued(), U256::from(issued_a));
        assert_eq!(lb.total_issued(), U256::from(4 * (31..=40u64).sum::<u64>()));
        drop(store);
        crash(&path, [a1, a2, lb]);
        let a1 = OutboundLedger::open(Some(path.clone()), a);
        let lb = OutboundLedger::open(Some(path), b);
        assert_eq!(a1.total_issued(), U256::from(issued_a));
        assert_eq!(lb.total_issued(), U256::from(4 * (31..=40u64).sum::<u64>()));
        for t in 0..12u32 {
            let l = if t % 3 == 2 { &lb } else { &a1 };
            for i in 31..=40u64 {
                let ben = beneficiary(10_000 + t * 10 + u32::try_from(i % 10).unwrap());
                assert_eq!(l.cumulative_for(&ben), U256::from(i));
            }
        }
    }

    /// A compaction cut short at any step — the journal renamed aside,
    /// the file rewritten but the old journal not yet deleted, a temp file
    /// left over — loses nothing across a crash, and the next open
    /// finishes it.
    #[test]
    fn an_interrupted_compaction_loses_nothing() {
        for step in [1u8, 2] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pushsync_outbound.json");
            let cb = [0xc1u8; 20];
            std::fs::write(&path, flat_ledger(cb, 100)).unwrap();
            let l = OutboundLedger::open(Some(path.clone()), cb);
            l.record_issued(&beneficiary(1), U256::from(5_000_000_000u64))
                .unwrap();
            l.record_issued(&beneficiary(200), U256::from(7u64))
                .unwrap();
            let store = l.shared.store.clone().unwrap();
            COMPACT_STOP_AFTER.with(|c| c.set(step));
            let stopped = {
                let _file = lock_file();
                store.compact_locked()
            };
            COMPACT_STOP_AFTER.with(|c| c.set(0));
            assert!(stopped.is_err(), "step {step}");
            assert!(journal_old_path(&path).exists(), "step {step}");
            // Cheques go on into a fresh journal meanwhile.
            l.record_issued(&beneficiary(2), U256::from(6_000_000_000u64))
                .unwrap();
            l.record_issued(&beneficiary(200), U256::from(8u64))
                .unwrap();
            // A temp file from a rewrite cut off before its rename.
            std::fs::write(path.with_extension("json.tmp"), b"{ half").unwrap();
            drop(store);
            crash(&path, [l]);

            let l = OutboundLedger::open(Some(path.clone()), cb);
            l.ensure_readable().unwrap();
            assert!(l.lost_figures().is_none(), "step {step}");
            assert_eq!(
                l.cumulative_for(&beneficiary(1)),
                U256::from(5_000_000_000u64)
            );
            assert_eq!(
                l.cumulative_for(&beneficiary(2)),
                U256::from(6_000_000_000u64)
            );
            assert_eq!(l.cumulative_for(&beneficiary(200)), U256::from(8u64));
            assert_eq!(
                l.cumulative_for(&beneficiary(99)),
                U256::from(1_000_000_099u64)
            );
            // The open folded both journals into the file.
            assert!(!journal_old_path(&path).exists(), "step {step}");
            assert!(!journal_path(&path).exists(), "step {step}");
            let on_disk = read_outbound_file(&path).unwrap().unwrap();
            assert_eq!(on_disk.chequebooks[&hex::encode(cb)].len(), 101);
            assert_eq!(
                on_disk.chequebooks[&hex::encode(cb)][&hex::encode(beneficiary(200))],
                "8"
            );
        }
    }

    /// A journal line cut off by a crash mid-write was never confirmed,
    /// so it is skipped, and the next append starts on a clean line. A
    /// damaged line anywhere else is a damaged journal: moved aside, and
    /// the figures count as lost, like an unparseable file (PR #126).
    #[test]
    fn a_torn_journal_line_is_skipped_and_a_damaged_one_is_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(10u64)).unwrap();
        crash(&path, [l]);
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, br#"{"c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1:00"#)
            .unwrap();
        drop(j);
        // The open folds the journal; the torn line is dropped.
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.cumulative_for(&beneficiary(1)), U256::from(10u64));
        assert!(l.lost_figures().is_none());
        drop(l);

        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(20u64)).unwrap();
        crash(&path, [l]);
        // A torn tail, then an append: the append cuts the tail off.
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, br#"{"c1c1"#).unwrap();
        drop(j);
        let store = Arc::new(JournalStore {
            path: path.clone(),
            queue: Mutex::default(),
            io: Mutex::default(),
            durable: AtomicU64::new(0),
            snapshot_entries: AtomicU64::new(0),
            compacting: AtomicBool::new(false),
            compact_failed: Mutex::new(None),
        });
        let seq = store.stage([(
            hex::encode(cb).as_str(),
            hex::encode(beneficiary(2)).as_str(),
            U256::from(3u64),
        )]);
        store.commit(seq).unwrap();
        #[allow(clippy::mem_forget)] // crashed: no compaction at close
        std::mem::forget(store);
        let lines = std::fs::read_to_string(journal_path(&path)).unwrap();
        assert_eq!(
            lines
                .lines()
                .filter(|l| commit_mark(l.as_bytes()).is_none())
                .count(),
            2,
            "{lines}"
        );
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.cumulative_for(&beneficiary(1)), U256::from(20u64));
        assert_eq!(l.cumulative_for(&beneficiary(2)), U256::from(3u64));
        drop(l);

        // A damaged line in the middle.
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(30u64)).unwrap();
        crash(&path, [l]);
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, b"garbage\n{}\n").unwrap();
        drop(j);
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some(), "a damaged journal is a loss");
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".journal.old.corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert!(std::fs::read_to_string(dir.path().join(&aside[0]))
            .unwrap()
            .contains("garbage"));
        // The file's figures from before the journal are still there.
        assert_eq!(l.cumulative_for(&beneficiary(2)), U256::from(3u64));
    }

    /// A cheque whose line can't be written isn't durable — the caller
    /// must not send it — but stays issued in memory, and its line stays
    /// staged: the next write that succeeds puts it on disk too.
    #[cfg(unix)]
    #[test]
    fn a_failed_journal_write_is_retried_with_the_next_cheque() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("data");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        let set_mode = |m| std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(m));
        set_mode(0o500).unwrap();
        if std::fs::write(sub.join("probe"), b"").is_ok() {
            // Running as root: permissions don't fake a failed write.
            set_mode(0o700).unwrap();
            return;
        }
        assert!(l.record_issued(&beneficiary(1), U256::from(40u64)).is_err());
        assert_eq!(l.total_issued(), U256::from(40u64), "issued in memory");
        set_mode(0o700).unwrap();
        l.record_issued(&beneficiary(2), U256::from(2u64)).unwrap();
        crash(&path, [l]);
        let l = OutboundLedger::open(Some(path), cb);
        assert_eq!(l.cumulative_for(&beneficiary(1)), U256::from(40u64));
        assert_eq!(l.total_issued(), U256::from(42u64));
    }

    /// A ledger whose figures outlived a loss of the file journals all
    /// of them with its next cheque, not just that cheque's, so a crash
    /// right after finds every one (PR #126 R1-M3 with the journal).
    #[test]
    fn a_survivor_journals_all_its_figures_after_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xa1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(500u64))
            .unwrap();
        l.record_issued(&beneficiary(2), U256::from(70u64)).unwrap();
        let store = l.shared.store.clone().unwrap();
        {
            let _file = lock_file();
            store.compact_locked().unwrap();
        }
        drop(store);
        std::fs::write(&path, b"{ not json").unwrap();
        drop(OutboundLedger::open(Some(path.clone()), [0xa2; 20]));
        assert!(l.lost_figures().is_none(), "survived in memory");
        l.record_issued(&beneficiary(3), U256::from(9u64)).unwrap();
        crash(&path, [l]);
        let l = OutboundLedger::open(Some(path), cb);
        assert!(l.lost_figures().is_none(), "known across the crash");
        assert_eq!(l.cumulative_for(&beneficiary(1)), U256::from(500u64));
        assert_eq!(l.cumulative_for(&beneficiary(2)), U256::from(70u64));
        assert_eq!(l.total_issued(), U256::from(579u64));
    }

    /// A survivor's rewrite that is on disk but loses its journal to a
    /// second loss before the waiter takes the file lock must not mark
    /// the chequebook known: the rewrite went aside with the journal
    /// (PR #141 R1-F1). It stays flagged and its next cheque rewrites
    /// all of its figures again.
    #[test]
    fn a_loss_between_commit_and_wait_keeps_the_survivor_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xa1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(500u64))
            .unwrap();
        l.record_issued(&beneficiary(2), U256::from(70u64)).unwrap();
        let store = l.shared.store.clone().unwrap();
        {
            let _file = lock_file();
            store.compact_locked().unwrap();
        }
        // Loss 1: the file is damaged; `l` survives it in memory.
        std::fs::write(&path, b"{ not json").unwrap();
        drop(OutboundLedger::open(Some(path.clone()), [0xa2; 20]));
        assert!(l.lost_figures().is_none(), "survived in memory");

        // The next cheque stages the full rewrite and it reaches disk...
        let w = l.stage_issued(&beneficiary(3), U256::from(9u64));
        let seq = w.pending.as_ref().unwrap().seq;
        store.commit(seq).unwrap();
        // ...then, before the waiter takes the file lock, loss 2: a
        // damaged journal line moves the journal (rewrite and all) aside.
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, b"garbage\n").unwrap();
        drop(j);
        drop(OutboundLedger::open(Some(path.clone()), [0xa3; 20]));
        w.wait().unwrap();
        assert!(
            lost_figures_at(&path, &cb).is_some(),
            "the rewrite was moved aside: the chequebook is still lost on disk"
        );
        assert!(l.shared.survived_loss.load(Ordering::SeqCst));

        // Its next cheque rewrites everything again and marks it known.
        l.record_issued(&beneficiary(4), U256::from(1u64)).unwrap();
        drop(store);
        crash(&path, [l]);
        let l = OutboundLedger::open(Some(path), cb);
        assert!(l.lost_figures().is_none(), "known once rewritten again");
        assert_eq!(l.total_issued(), U256::from(580u64));
    }

    /// A ledger still alive when its data dir is parked (an account
    /// switch while a blocking cheque write outlived the shutdown) writes
    /// nothing more, neither to the parked journal nor at the path; the
    /// next ledger on the path gets a journal of its own instead of
    /// appending to the parked one (PR #141 R1-M1), and a ledger reopened
    /// on the old chequebook once its files are back pays again (R2-M1).
    #[cfg(unix)]
    #[test]
    fn a_journal_moved_away_is_not_reused_by_the_next_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let parked = dir.path().join("parked");
        std::fs::create_dir(&parked).unwrap();
        let (a, b) = ([0xa1u8; 20], [0xb1u8; 20]);
        let old = OutboundLedger::open(Some(path.clone()), a);
        old.record_issued(&beneficiary(1), U256::from(11u64))
            .unwrap();
        // The account switch parks the ledger's files.
        std::fs::rename(journal_path(&path), parked.join("j")).unwrap();

        let new = OutboundLedger::open(Some(path.clone()), b);
        assert!(!Arc::ptr_eq(
            old.shared.store.as_ref().unwrap(),
            new.shared.store.as_ref().unwrap()
        ));
        new.record_issued(&beneficiary(2), U256::from(22u64))
            .unwrap();
        old.record_issued(&beneficiary(3), U256::from(33u64))
            .expect_err("a retired ledger writes nothing");
        let parked_lines = std::fs::read_to_string(parked.join("j")).unwrap();
        assert!(parked_lines.contains(&hex::encode(a)), "{parked_lines}");
        assert!(!parked_lines.contains(&hex::encode(b)), "{parked_lines}");
        assert!(!parked_lines.contains(&hex::encode(beneficiary(3))));
        let live = std::fs::read_to_string(journal_path(&path)).unwrap();
        assert!(!live.contains(&hex::encode(a)), "{live}");

        // Switch back: B's files go, A's come back, while `old` (leaked)
        // still holds A's retired state.
        drop(new);
        let parked_b = dir.path().join("parked-b");
        std::fs::create_dir(&parked_b).unwrap();
        std::fs::rename(&path, parked_b.join("f")).unwrap();
        std::fs::rename(parked.join("j"), journal_path(&path)).unwrap();
        let again = OutboundLedger::open(Some(path.clone()), a);
        assert!(!Arc::ptr_eq(&again.shared, &old.shared), "fresh state");
        assert_eq!(again.cumulative_for(&beneficiary(1)), U256::from(11u64));
        again
            .record_issued(&beneficiary(4), U256::from(44u64))
            .expect("A pays again");
        old.record_issued(&beneficiary(5), U256::from(55u64))
            .expect_err("still retired");
        // The old ledger closes after all that: nothing of its is folded
        // anywhere.
        drop(old);
        crash(&path, [again]);
        let again = OutboundLedger::open(Some(path), a);
        assert_eq!(again.cumulative_for(&beneficiary(4)), U256::from(44u64));
        assert_eq!(again.total_issued(), U256::from(55u64));
    }

    /// An account switch holds the ledger files while it moves them
    /// (PR #141 R2-F1): a compaction of the previous account's ledger
    /// that was already waiting for the file lock, and the close-time
    /// fold when the last of its ledgers drops after the switch, write
    /// nothing over the next account's files adopted at the same path.
    #[test]
    fn a_compaction_outliving_an_account_switch_leaves_the_next_accounts_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let parked = dir.path().join("parked");
        std::fs::create_dir(&parked).unwrap();
        let (a, b) = ([0xa2u8; 20], [0xb2u8; 20]);
        let old = OutboundLedger::open(Some(path.clone()), a);
        old.record_issued(&beneficiary(1), U256::from(11u64))
            .unwrap();
        old.record_issued(&beneficiary(2), U256::from(12u64))
            .unwrap();
        let store = old.shared.store.clone().unwrap();
        // A compaction that ran before the switch left the journal handle
        // closed (the one at the path is reopened by name on demand).
        {
            let _file = lock_file();
            store.compact_locked().unwrap();
        }
        old.record_issued(&beneficiary(1), U256::from(13u64))
            .unwrap();

        let held = hold_ledger_files(&path);
        // A's compaction starts on its own thread and waits for the lock.
        let compaction = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let _file = lock_file();
                store.compact_locked()
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Park A's files, adopt B's.
        std::fs::rename(&path, parked.join("f")).unwrap();
        std::fs::rename(journal_path(&path), parked.join("j")).unwrap();
        let b_file = format!(
            r#"{{"{}:{}":"777"}}"#,
            hex::encode(b),
            hex::encode(beneficiary(9))
        );
        std::fs::write(&path, &b_file).unwrap();
        drop(held);
        compaction.join().unwrap().unwrap();
        // A cheque the old ledger was still finishing goes nowhere.
        old.record_issued(&beneficiary(2), U256::from(14u64))
            .expect_err("the old account's ledger writes nothing after the switch");
        drop(store);
        drop(old);

        assert_eq!(std::fs::read_to_string(&path).unwrap(), b_file);
        assert!(!journal_path(&path).exists());
        assert!(!journal_old_path(&path).exists());
        assert!(std::fs::read_to_string(parked.join("j"))
            .unwrap()
            .contains(&hex::encode(a)));
        let ledger_b = OutboundLedger::open(Some(path.clone()), b);
        assert_eq!(ledger_b.cumulative_for(&beneficiary(9)), U256::from(777u64));
        assert!(ledger_b.lost_figures().is_none());
        crash(&path, [ledger_b]);
    }

    /// A journal store whose last reference goes on a thread holding the
    /// file lock still writes its staged lines and folds the journal at
    /// close, once the lock is released (PR #141 R2-M2).
    #[test]
    fn the_last_ledger_closing_under_the_file_lock_still_folds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc3u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(5u64)).unwrap();
        // Staged, never committed.
        drop(l.stage_issued(&beneficiary(2), U256::from(6u64)));
        {
            let _file = lock_file();
            // A temporary upgrade, as `for_path` and the quarantine take.
            let live = live_journal(&path).unwrap();
            drop(l);
            release_after_unlock(live);
            assert!(journal_path(&path).exists(), "not under the lock");
        }
        assert!(!journal_path(&path).exists(), "folded at close");
        let on_disk = read_outbound_file(&path).unwrap().unwrap().to_flat();
        let key = |i| format!("{}:{}", hex::encode(cb), hex::encode(beneficiary(i)));
        assert_eq!(on_disk.get(&key(1)).map(String::as_str), Some("5"));
        assert_eq!(on_disk.get(&key(2)).map(String::as_str), Some("6"));
    }

    /// A NUL-filled range a crash left in the journal's last, never
    /// synced group commit is a torn write, not damage: dropped without
    /// a loss, and cut off by the next append (PR #141 R2-M3).
    #[test]
    fn a_zero_filled_journal_tail_is_torn_not_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc4u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(10u64)).unwrap();
        crash(&path, [l]);
        // The unsynced group commit: lines zeroed, one survived after them.
        let mut tail = vec![0u8; 300];
        tail.push(b'\n');
        tail.extend_from_slice(
            format!(
                "{{\"{}:{}\":\"99\"}}\n",
                hex::encode(cb),
                hex::encode(beneficiary(2))
            )
            .as_bytes(),
        );
        tail.extend_from_slice(&[0u8; 40]);
        tail.push(b'\n');
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, &tail).unwrap();
        drop(j);
        assert_eq!(
            journal_intact_len(&std::fs::read(journal_path(&path)).unwrap()),
            std::fs::read(journal_path(&path)).unwrap().len() - tail.len()
        );

        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.cumulative_for(&beneficiary(1)), U256::from(10u64));
        assert_eq!(l.cumulative_for(&beneficiary(2)), U256::zero());
        assert!(l.lost_figures().is_none(), "no loss");
        assert!(!lost_marker_path(&path).exists());
        // An append after one cuts the tail off first.
        crash(&path, [l]);
        let mut j = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        std::io::Write::write_all(&mut j, &tail).unwrap();
        drop(j);
        let mut io = JournalIo::default();
        io.append(
            &path,
            format!(
                "{{\"{}:{}\":\"3\"}}\n",
                hex::encode(cb),
                hex::encode(beneficiary(3))
            )
            .as_bytes(),
        )
        .unwrap();
        drop(io);
        let bytes = std::fs::read(journal_path(&path)).unwrap();
        assert!(!bytes.contains(&0), "the zeroed tail was cut off");
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.cumulative_for(&beneficiary(3)), U256::from(3u64));
        assert!(l.lost_figures().is_none());
        crash(&path, [l]);
    }

    /// A NUL-filled range in lines a later group commit came after was
    /// synced and acknowledged — cheques went out on it — so it is
    /// damage, not a torn write: the journal is moved aside and the
    /// figures count as lost, never silently dropped (PR #141 R3-F1).
    #[test]
    fn a_zeroed_range_before_a_later_commit_is_a_loss_not_torn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc5u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        for (i, v) in [10u64, 20, 30].into_iter().enumerate() {
            let i = u32::try_from(i).unwrap();
            l.record_issued(&beneficiary(i), U256::from(v)).unwrap();
        }
        crash(&path, [l]);
        let jp = journal_path(&path);
        let mut bytes = std::fs::read(&jp).unwrap();
        // Zero part of the first, synced line.
        bytes[2..12].fill(0);
        std::fs::write(&jp, &bytes).unwrap();
        assert_eq!(journal_intact_len(&bytes), bytes.len());

        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some(), "acked cheques were lost");
        assert!(lost_marker_path(&path).exists());
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".journal.old.corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(
            std::fs::read(dir.path().join(&aside[0])).unwrap(),
            bytes,
            "the damaged journal is kept whole"
        );
        // An append doesn't cut synced lines off either.
        let mut io = JournalIo::default();
        std::fs::write(&jp, &bytes).unwrap();
        io.append(&path, b"{}\n").unwrap();
        drop(io);
        let after = std::fs::read(&jp).unwrap();
        assert!(after.starts_with(&bytes), "nothing cut");
        crash(&path, [l]);
    }

    /// A group commit whose fsync failed is cut off before the retry is
    /// appended: its bytes read back fine now but may be zeros after a
    /// crash, and an acknowledged retry behind such a range must never
    /// read as a torn tail (PR #141 R4-F1). Even laid out that way, the
    /// retry's commit mark comes after a gap, so the range reads as
    /// damage — a loss, with the journal kept — not as torn.
    #[test]
    fn a_failed_commit_is_cut_off_before_its_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc6u8; 20];
        let jp = journal_path(&path);
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(10u64)).unwrap();
        let c1 = std::fs::read(&jp).unwrap();
        FAIL_NEXT_SYNC.with(|f| f.set(true));
        assert!(l.record_issued(&beneficiary(2), U256::from(20u64)).is_err());
        let failed = std::fs::read(&jp).unwrap()[c1.len()..].to_vec();
        assert!(
            !failed.is_empty(),
            "the failed write's bytes are in the file"
        );
        l.record_issued(&beneficiary(3), U256::from(5u64)).unwrap();
        let after = std::fs::read(&jp).unwrap();
        assert!(after.starts_with(&c1));
        let retry = after[c1.len()..].to_vec();
        assert!(!retry.starts_with(&failed), "the failed write was cut off");
        assert!(failed.ends_with(b"#2\n"));
        assert!(
            retry.ends_with(b"#2\n"),
            "the retry takes the cut-off write's number: no gap (PR #141 R5-M1)"
        );
        let b2 = hex::encode(beneficiary(2));
        assert_eq!(
            String::from_utf8_lossy(&after).matches(b2.as_str()).count(),
            1,
            "the retried line is in the file once"
        );
        crash(&path, [l]);

        // As journaled: everything is there.
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.total_issued(), U256::from(35u64));
        assert!(l.lost_figures().is_none());
        crash(&path, [l]);

        // The layout an uncut retry would have left (the fallback when
        // the failed handle's metadata was unreadable: the failed write's
        // mark stays in the file and the retry numbers past it), with the
        // failed write zeroed by a crash: never a silent drop.
        let mut disk = c1.clone();
        disk.extend(std::iter::repeat_n(0u8, failed.len()));
        disk.extend_from_slice(&retry[..retry.len() - 3]);
        disk.extend_from_slice(b"#3\n");
        std::fs::remove_file(&path).ok();
        std::fs::write(&jp, &disk).unwrap();
        assert_eq!(journal_intact_len(&disk), disk.len(), "damage, not torn");
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some(), "acked cheques may be lost");
        assert!(lost_marker_path(&path).exists());
        crash(&path, [l]);
    }

    /// A crash that tears the retry of a failed commit — its lines
    /// zeroed, its trailing mark surviving — reads as a torn tail, the
    /// same as the same tear without a failure before it: the retry was
    /// never acknowledged, so nothing is lost and no marker gates the
    /// chequebook. The cut-off write's number isn't burned, so the
    /// retry's mark follows the last durable one (PR #141 R5-M1).
    #[test]
    fn a_torn_retry_after_a_failed_commit_is_torn_not_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc8u8; 20];
        let jp = journal_path(&path);
        let l = OutboundLedger::open(Some(path.clone()), cb);
        l.record_issued(&beneficiary(1), U256::from(10u64)).unwrap();
        let c1 = std::fs::read(&jp).unwrap();
        FAIL_NEXT_SYNC.with(|f| f.set(true));
        assert!(l.record_issued(&beneficiary(2), U256::from(20u64)).is_err());
        l.record_issued(&beneficiary(3), U256::from(5u64)).unwrap();
        crash(&path, [l]);
        let after = std::fs::read(&jp).unwrap();
        assert!(after.starts_with(&c1));
        assert!(
            after.ends_with(b"#2\n"),
            "{}",
            String::from_utf8_lossy(&after)
        );

        // The crash zero-fills the retry's lines, its mark survives.
        let mut torn = after.clone();
        let len = torn.len();
        torn[c1.len()..len - 3].fill(0);
        assert_eq!(journal_intact_len(&torn), c1.len(), "torn, not damage");
        std::fs::remove_file(&path).ok();
        std::fs::write(&jp, &torn).unwrap();
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert_eq!(l.total_issued(), U256::from(10u64));
        assert!(l.lost_figures().is_none(), "nothing acknowledged was lost");
        assert!(!lost_marker_path(&path).exists());
        crash(&path, [l]);
    }

    /// A zeroed range that starts in the second-to-last group commit and
    /// swallows its commit mark is damage, not the last commit's torn
    /// tail: the last commit's mark comes after a gap (PR #141 R4-M1).
    /// One running to the end of the file, marks and all, can't be told
    /// from a torn write and is dropped — but a copy is kept first.
    #[test]
    fn a_zeroed_range_across_two_commits_is_a_loss_and_a_dropped_one_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc7u8; 20];
        let jp = journal_path(&path);
        let l = OutboundLedger::open(Some(path.clone()), cb);
        let mut ends = Vec::new();
        for i in 1..=3u32 {
            l.record_issued(&beneficiary(i), U256::from(u64::from(i)))
                .unwrap();
            ends.push(std::fs::read(&jp).unwrap().len());
        }
        crash(&path, [l]);
        let bytes = std::fs::read(&jp).unwrap();
        assert!(bytes.ends_with(b"#3\n"));

        // From the middle of commit 2 through its mark into commit 3.
        let mut damaged = bytes.clone();
        damaged[ends[0] + 5..ends[1] + 5].fill(0);
        assert_eq!(journal_intact_len(&damaged), damaged.len());
        std::fs::write(&jp, &damaged).unwrap();
        let l = OutboundLedger::open(Some(path.clone()), cb);
        assert!(l.lost_figures().is_some(), "commit 2 was acknowledged");
        crash(&path, [l]);

        // From the middle of commit 2 to the end of the file: dropped as
        // torn, but kept in a copy.
        let dir2 = tempfile::tempdir().unwrap();
        let path2 = dir2.path().join("pushsync_outbound.json");
        let jp2 = journal_path(&path2);
        let mut tail = bytes.clone();
        let len = tail.len();
        tail[ends[0] + 5..len - 1].fill(0);
        assert_eq!(journal_intact_len(&tail), ends[0]);
        std::fs::write(&jp2, &tail).unwrap();
        let l = OutboundLedger::open(Some(path2.clone()), cb);
        assert!(l.lost_figures().is_none());
        assert_eq!(l.total_issued(), U256::from(1u64));
        let copies: Vec<_> = std::fs::read_dir(dir2.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains(".journal.old.torn-"))
            .collect();
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(std::fs::read(&copies[0]).unwrap(), tail);
        crash(&path2, [l]);

        // The same through an append: kept before it is cut off.
        std::fs::remove_file(&path2).ok();
        std::fs::write(&jp2, &tail).unwrap();
        let mut io = JournalIo::default();
        io.append(&path2, b"{}\n").unwrap();
        assert_eq!(&std::fs::read(&jp2).unwrap()[..ends[0]], &bytes[..ends[0]]);
        let copies = std::fs::read_dir(dir2.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".journal.torn-")
            })
            .count();
        assert_eq!(copies, 1);
    }

    /// Once the journal holds as many lines as the threshold, it is folded
    /// into the file in the background, without a cheque waiting for it.
    #[test]
    fn a_long_journal_is_compacted_in_the_background() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let l = OutboundLedger::open(Some(path.clone()), cb);
        let n = u32::try_from(COMPACT_MIN_LINES).unwrap();
        let mut last = None;
        for i in 0..n {
            last = Some(l.stage_issued(&beneficiary(i), U256::from(u64::from(i) + 1)));
        }
        last.unwrap().wait().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while journal_path(&path).exists() || journal_old_path(&path).exists() {
            assert!(std::time::Instant::now() < deadline, "never compacted");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let on_disk = read_outbound_file(&path).unwrap().unwrap();
        assert_eq!(on_disk.entries(), n as usize);
        l.record_issued(&beneficiary(0), U256::from(99u64)).unwrap();
        crash(&path, [l]);
        let l = OutboundLedger::open(Some(path), cb);
        assert_eq!(l.cumulative_for(&beneficiary(0)), U256::from(99u64));
        assert_eq!(
            l.cumulative_for(&beneficiary(n - 1)),
            U256::from(u64::from(n))
        );
    }

    /// Micro-benchmark for issue #140: what recording one cheque costs as
    /// the ledger grows (500 / 4k / 50k entries), one issuer at a time and
    /// 16 at once. `cargo test -p ant-p2p --release --lib
    /// record_cost_vs_ledger_size -- --ignored --nocapture`.
    #[test]
    #[ignore = "micro-benchmark"]
    fn record_cost_vs_ledger_size() {
        let cb = [0xc1u8; 20];
        println!("entries | serial us/cheque (p50, mean) | 16 issuers cheques/s");
        for entries in [500u32, 4_000, 50_000] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pushsync_outbound.json");
            std::fs::write(&path, flat_ledger(cb, entries)).unwrap();
            let l = OutboundLedger::open(Some(path.clone()), cb);
            let mut took = Vec::new();
            for i in 0..300u32 {
                let t = std::time::Instant::now();
                l.record_issued(
                    &beneficiary(i % entries),
                    U256::from(2_000_000_000u64 + u64::from(i)),
                )
                .unwrap();
                took.push(t.elapsed().as_secs_f64() * 1e6);
            }
            let mean = took.iter().sum::<f64>() / took.len() as f64;
            took.sort_by(f64::total_cmp);
            let t = std::time::Instant::now();
            std::thread::scope(|s| {
                for th in 0..16u32 {
                    let l = l.clone();
                    s.spawn(move || {
                        for i in 0..100u32 {
                            l.record_issued(
                                &beneficiary((th * 100 + i) % entries),
                                U256::from(3_000_000_000u64 + u64::from(i)),
                            )
                            .unwrap();
                        }
                    });
                }
            });
            let rate = 1_600.0 / t.elapsed().as_secs_f64();
            println!(
                "{entries:>7} | {:>8.0} {:>8.0} | {rate:>8.0}",
                took[took.len() / 2],
                mean
            );
        }
    }

    /// The nested layout unreleased builds of this PR wrote still reads.
    #[test]
    fn the_nested_ledger_layout_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pushsync_outbound.json");
        let cb = [0xc1u8; 20];
        let peer = [0x11u8; 20];
        std::fs::write(
            &path,
            format!(
                r#"{{"chequebooks":{{"{}":{{"{}":"77"}}}}}}"#,
                hex::encode(cb),
                hex::encode(peer)
            ),
        )
        .unwrap();
        let ledger = OutboundLedger::open(Some(path), cb);
        ledger.ensure_readable().unwrap();
        assert_eq!(ledger.cumulative_for(&peer), U256::from(77u64));
    }

    /// `EmitChequePb` round-trips through prost, so any future change
    /// to the protobuf shape is caught by tests instead of by bee.
    #[test]
    fn emit_cheque_pb_round_trip() {
        let signed = SignedCheque {
            cheque: Cheque {
                chequebook: [0x11u8; 20],
                beneficiary: [0x22u8; 20],
                cumulative_payout: U256::from(7u64),
            },
            signature: [0xeeu8; 65],
        };
        let json = encode_signed_cheque_json(&signed);
        let msg = EmitChequePb { cheque: json };
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let back = EmitChequePb::decode(buf.as_slice()).unwrap();
        let back_signed = decode_signed_cheque_json(&back.cheque).unwrap();
        assert_eq!(back_signed, signed);
    }

    /// `issue_cheque` binds the new cumulative correctly and the
    /// signature recovers to the issuer's own EOA.
    #[test]
    fn issue_cheque_round_trip() {
        let secret = make_secret();
        let want_eoa = eoa(&secret);
        let signed =
            issue_cheque(&secret, [0x99u8; 20], [0x88u8; 20], U256::from(999u64), 100).unwrap();
        assert_eq!(signed.cheque.cumulative_payout, U256::from(999u64));
        let recovered = recover_cheque_signer(&signed, 100).unwrap();
        assert_eq!(recovered, want_eoa);
    }
}
