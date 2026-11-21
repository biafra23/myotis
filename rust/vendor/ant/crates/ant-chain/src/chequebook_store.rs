//! Shared chequebook bootstrap: the on-disk association record plus the
//! "resolve / deploy a node-owned chequebook" mechanics that both
//! `antd` (at startup) and `ant-ffi` (on the first storage buy) need
//! for outbound SWAP settlement.
//!
//! The cheque *protocol* lives in [`crate::chequebook`] (EIP-712
//! signing, calldata) and the *wire* lives in `ant-p2p`. This module is
//! the thin orchestration layer in between: where a chequebook comes
//! from and how its address is persisted across restarts, so a node
//! deploys once and reuses forever. Building the actual
//! `ant_p2p::PushsyncSwapConfig` from the resolved address stays with
//! each caller, since that type belongs to a higher layer.
//!
//! `load_persisted_chequebook_for` / `persist_chequebook` / [`ChequebookFile`]
//! are pure file I/O and compile everywhere; the deploy / factory-check
//! helpers drive a JSON-RPC node and are gated on `chain-rpc`.

use std::path::Path;

/// Target xBZZ deposit behind a node's chequebook, in PLUR (1 xBZZ =
/// 1e16 PLUR): **0.001 xBZZ**. It is `antd`'s default
/// (`--chequebook-deposit-plur`), `ant-ffi`'s target while the account
/// has no storage plan, and the floor of [`deposit_target_for_depth`].
/// It is grounded in the #67 benchmark, where that deposit backed 65 K+
/// cheques with a wide margin (~300× one soak's measured settlement
/// demand). That is small enough not to compete with the postage the
/// user came to buy, and it isn't spent money: an unspent deposit stays
/// withdrawable by the issuer. A fresh deploy is funded up to it, and
/// an adopted chequebook is topped back up to it
/// ([`top_up_chequebook`]).
pub const DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR: u128 = 10_000_000_000_000;

/// The batch depth [`deposit_target_for_depth`] is anchored at.
const PLAN_DEPOSIT_BASE_DEPTH: u8 = 21;

/// [`deposit_target_for_depth`] at [`PLAN_DEPOSIT_BASE_DEPTH`]: 0.1 xBZZ.
const PLAN_DEPOSIT_AT_BASE_PLUR: u128 = 1_000_000_000_000_000;

/// The most [`deposit_target_for_depth`] asks for: 1 xBZZ.
const PLAN_DEPOSIT_MAX_PLUR: u128 = 10_000_000_000_000_000;

/// The chequebook deposit to keep behind a storage plan of batch depth
/// `depth`, in PLUR: **0.1 xBZZ at depth 21**, doubling per extra depth
/// level and halving per level below (depth 22 → 0.2 xBZZ, 20 → 0.05
/// xBZZ), never below [`DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR`] and never above
/// 1 xBZZ.
///
/// The deposit backs the cheques that pay peers for upload bandwidth.
/// Mainnet streaming measured that at ~0.03 xBZZ/GB (360p) to ~0.17
/// xBZZ/GB (720p); the flat 0.001 xBZZ covered ~6 MB of 720p before
/// uploads fell back to the slow free tier. A plan's depth is what it
/// can hold, so the deposit grows with it, and the user pays it with the
/// plan. The cap keeps a huge batch from locking up an absurd deposit.
///
/// The app library (`ant-ffi`) prices it into a plan quote, funds it on
/// a buy and tops up against it. `antd` keeps an operator-chosen flat
/// deposit (`--chequebook-deposit-plur`) instead.
#[must_use]
pub fn deposit_target_for_depth(depth: u8) -> u128 {
    let target = if depth >= PLAN_DEPOSIT_BASE_DEPTH {
        1u128
            .checked_shl(u32::from(depth - PLAN_DEPOSIT_BASE_DEPTH))
            .and_then(|factor| PLAN_DEPOSIT_AT_BASE_PLUR.checked_mul(factor))
            .unwrap_or(u128::MAX)
    } else {
        PLAN_DEPOSIT_AT_BASE_PLUR >> (PLAN_DEPOSIT_BASE_DEPTH - depth)
    };
    target.clamp(DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR, PLAN_DEPOSIT_MAX_PLUR)
}

/// On-disk record of the chequebook a node auto-deployed (or
/// rediscovered) for outbound settlement, persisted at
/// `<data-dir>/chequebook.json`. Written once on first deploy and
/// reloaded on every subsequent start (deploy-once, reuse-forever —
/// the equivalent of the chequebook record bee keeps in its
/// statestore, which we can't read). The issuer baked into the
/// chequebook is the node EOA, so the node signing key is the cheque
/// signer; the remaining fields are pure provenance for operator
/// debugging / on-chain cross-referencing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChequebookFile {
    /// Deployed `SimpleSwap` contract address (`0x` + 40 hex).
    pub chequebook: String,
    /// Issuer EOA baked into the chequebook (the node's own address).
    pub issuer: String,
    /// CREATE2 salt used for the deploy (hex). Empty for a
    /// rediscovered chequebook whose salt we never learned.
    #[serde(default)]
    pub salt: String,
    /// Deploy tx hash (hex). Empty for a rediscovered chequebook.
    #[serde(default)]
    pub deploy_tx: String,
}

impl ChequebookFile {
    /// Build a record for `chequebook` issued by `issuer`, with no
    /// known salt / deploy tx (the rediscovered-chequebook case).
    #[must_use]
    pub fn rediscovered(chequebook: &[u8; 20], issuer: &[u8; 20]) -> Self {
        Self {
            chequebook: format!("0x{}", hex::encode(chequebook)),
            issuer: format!("0x{}", hex::encode(issuer)),
            salt: String::new(),
            deploy_tx: String::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChequebookError {
    #[error("read chequebook association {0}: {1}")]
    Read(String, std::io::Error),
    #[error("parse chequebook association {0}: {1}")]
    Parse(String, serde_json::Error),
    #[error("decode persisted chequebook address '{0}'")]
    Decode(String),
    #[error("write {0}: {1}")]
    Write(String, std::io::Error),
    #[error("serialize chequebook association: {0}")]
    Serialize(serde_json::Error),
    /// Any JSON-RPC / transaction failure during deploy or factory
    /// verification, flattened to a string so the error type stays
    /// feature-agnostic for callers.
    #[cfg(feature = "chain-rpc")]
    #[error("{0}")]
    Chain(String),
    /// The node wallet can't afford the one-time deploy. Callers that
    /// treat auto-deploy as best-effort (e.g. `ant-ffi`) match this to
    /// skip softly; `antd` logs it and starts without settlement.
    #[cfg(feature = "chain-rpc")]
    #[error(
        "node wallet 0x{wallet} has {have} wei xDAI, needs ~{need} wei to deploy a chequebook"
    )]
    InsufficientGas {
        wallet: String,
        have: String,
        need: String,
    },
    #[cfg(feature = "chain-rpc")]
    #[error("deploy tx 0x{0} confirmed but emitted no SimpleSwapDeployed log")]
    NoDeployLog(String),
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Load the persisted chequebook address from `path`, if the file
/// exists **and** the `issuer` it names is `owner`. This is the only
/// loader: both `antd` and `ant-ffi` know their own EOA, and trusting
/// the path alone is exactly the drift the parity audit found
/// (`docs/ffi-parity-audit.md`).
///
/// A malformed file is an error rather than "none": silently ignoring
/// it could re-trigger a deploy on every start, so callers decide.
/// `antd` treats it as fatal; `ant-ffi` rediscovers on-chain first and
/// only deploys (overwriting the file) when the chain has none.
///
/// A chequebook's issuer is baked into the contract on-chain: bee only
/// accepts a cheque whose signature recovers to `chequebook.issuer()`,
/// so a node that signs with a different key emits cheques every peer
/// silently drops while its own settlement status reads "ready". A
/// record can outlive the account that wrote it whenever the node key
/// changes under a fixed data dir (a restore-from-backup-key flow), and
/// the file already carries the owner, so the path alone is never
/// trusted. A foreign record
/// reads as `Ok(None)` — "no chequebook for this account" — which is
/// exactly what a fresh account is, so callers rediscover or deploy
/// their own instead of failing.
pub fn load_persisted_chequebook_for(
    path: &Path,
    owner: &[u8; 20],
) -> Result<Option<[u8; 20]>, ChequebookError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ChequebookError::Read(path.display().to_string(), e))?;
    let file: ChequebookFile = serde_json::from_str(&raw)
        .map_err(|e| ChequebookError::Parse(path.display().to_string(), e))?;
    let mut issuer = [0u8; 20];
    hex::decode_to_slice(strip_0x(file.issuer.trim()), &mut issuer)
        .map_err(|_| ChequebookError::Decode(file.issuer.clone()))?;
    if issuer != *owner {
        tracing::warn!(
            path = %path.display(),
            issuer = %format!("0x{}", hex::encode(issuer)),
            owner = %format!("0x{}", hex::encode(owner)),
            "ignoring chequebook association issued by a different account",
        );
        return Ok(None);
    }
    let mut cb = [0u8; 20];
    hex::decode_to_slice(strip_0x(file.chequebook.trim()), &mut cb)
        .map_err(|_| ChequebookError::Decode(file.chequebook.clone()))?;
    Ok(Some(cb))
}

/// Atomically persist the chequebook association (write-tmp + rename),
/// so a crash mid-write can't leave a half-written file that a later
/// start would reject.
pub fn persist_chequebook(path: &Path, file: &ChequebookFile) -> Result<(), ChequebookError> {
    let json = serde_json::to_string_pretty(file).map_err(ChequebookError::Serialize)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|e| ChequebookError::Write(tmp.display().to_string(), e))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| ChequebookError::Write(path.display().to_string(), e))?;
    Ok(())
}

/// One `eth_call` to the Swarm chequebook factory's
/// `deployedContracts(address)` view. Returns `Ok(true)` iff the
/// factory has a record of having deployed `chequebook` itself — which
/// is exactly the predicate bee's `chequeStore.ReceiveCheque` uses to
/// decide whether to accept a cheque drawn on it. Cheques drawn on a
/// chequebook the factory doesn't know about are silently dropped by
/// bee, so emitting them just wastes bandwidth.
#[cfg(feature = "chain-rpc")]
pub async fn verify_chequebook_with_factory(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<bool, ChequebookError> {
    use crate::chequebook::{factory_deployed_contracts_calldata, GNOSIS_CHEQUEBOOK_FACTORY};

    let calldata = factory_deployed_contracts_calldata(chequebook);
    let v = client
        .eth_call(
            &format!("0x{}", hex::encode(GNOSIS_CHEQUEBOOK_FACTORY)),
            &format!("0x{}", hex::encode(&calldata)),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("factory.deployedContracts eth_call: {e}")))?;
    if v.len() < 32 {
        return Err(ChequebookError::Chain(format!(
            "factory.deployedContracts returned <32 bytes (got {} bytes)",
            v.len()
        )));
    }
    let last_word = &v[v.len() - 32..];
    Ok(last_word.iter().any(|&b| b != 0))
}

/// One `eth_call` to `chequebook.issuer()` returning the 20-byte EOA
/// the contract recognises as its issuer. Cheques are only accepted by
/// bee peers when signed by this exact key (bee recovers the signer in
/// `cashChequeBeneficiary` and the chequebook's `issuer()` must match),
/// so a node whose cheque-signing key differs from `issuer()` emits
/// cheques every peer silently drops. Callers compare the result to the
/// EOA derived from their signing key before enabling outbound SWAP.
#[cfg(feature = "chain-rpc")]
pub async fn read_chequebook_issuer(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<[u8; 20], ChequebookError> {
    use crate::chequebook::chequebook_issuer_selector;

    let v = client
        .eth_call(
            &format!("0x{}", hex::encode(chequebook)),
            &format!("0x{}", hex::encode(chequebook_issuer_selector())),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("chequebook.issuer eth_call: {e}")))?;
    if v.len() < 32 {
        return Err(ChequebookError::Chain(format!(
            "chequebook.issuer returned <32 bytes (got {} bytes)",
            v.len()
        )));
    }
    // Address is the low 20 bytes of the right-aligned 32-byte word.
    let word = &v[v.len() - 32..];
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..32]);
    Ok(out)
}

/// The two on-chain checks a chequebook must pass before a node signs
/// cheques on it (see [`check_chequebook`]). Each field keeps its own
/// read result so a caller can report them separately, as `antd` does.
#[cfg(feature = "chain-rpc")]
#[derive(Debug)]
pub struct ChequebookChecks {
    /// [`verify_chequebook_with_factory`]: `Ok(false)` means bee drops
    /// every cheque drawn on it.
    pub registered: Result<bool, ChequebookError>,
    /// [`read_chequebook_issuer`]: bee only accepts cheques signed by
    /// this EOA. `None` when [`check_chequebook`]'s [`IssuerRead`]
    /// policy skipped the read (nothing to compare against, or the
    /// factory check already disqualified the chequebook).
    pub issuer: Option<Result<[u8; 20], ChequebookError>>,
}

/// When [`check_chequebook`] reads `issuer()` — each read is an RPC
/// round-trip, so skip it when its answer can't change the outcome.
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerRead {
    /// Don't read it (e.g. no signing EOA to compare it with).
    Never,
    /// Read it unless the factory already answered "not registered",
    /// which disqualifies the chequebook on its own.
    UnlessUnregistered,
    /// Always read it (a caller that reports every check even when one
    /// has already failed, like `antd` under
    /// `--chequebook-allow-unverified`).
    Always,
}

/// Whether a node signing with a given key may use a chequebook, per
/// [`ChequebookChecks::verdict`].
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChequebookVerdict {
    /// Every check that could be read passed.
    Usable,
    /// The Swarm chequebook factory doesn't know it.
    NotRegistered,
    /// Its on-chain `issuer()` is this other EOA, not the signer.
    IssuerMismatch([u8; 20]),
}

#[cfg(feature = "chain-rpc")]
impl ChequebookChecks {
    /// The shared rule for `antd` and `ant-ffi`: a check that answered
    /// "no" disqualifies the chequebook, while a check whose read
    /// *failed* is skipped rather than failed. Unverified is not bad, and
    /// dropping settlement over an RPC hiccup stalls uploads. `antd`
    /// lets `--chequebook-allow-unverified` override a disqualification.
    #[must_use]
    pub fn verdict(&self, signer: &[u8; 20]) -> ChequebookVerdict {
        if matches!(self.registered, Ok(false)) {
            return ChequebookVerdict::NotRegistered;
        }
        match self.issuer {
            Some(Ok(issuer)) if issuer != *signer => ChequebookVerdict::IssuerMismatch(issuer),
            _ => ChequebookVerdict::Usable,
        }
    }
}

/// How long after our own deploy (the record's write time) a factory
/// "not registered" may still be a lagging backend. A load-balanced RPC
/// trails by seconds to a few minutes, not for good.
#[cfg(feature = "chain-rpc")]
pub const DEPLOY_LAG_GRACE: std::time::Duration = std::time::Duration::from_mins(10);

/// Whether a factory "not registered" answer for the persisted `cb` may
/// just be a backend that hasn't seen our deploy yet (a load-balanced
/// RPC trails by a few blocks; e.g. `ant-ffi`'s launch-time
/// `ant_deploy_chequebook` followed within seconds by the gateway
/// start's check, or `antd` topping up the chequebook it deployed at
/// startup on the first stamp buy). Only for a chequebook we deployed ourselves — the
/// record carries its deploy tx — and only within [`DEPLOY_LAG_GRACE`]
/// of the record being written: `true` then when that tx's receipt isn't
/// visible or can't be read (unconfirmed, not "no"), or shows the
/// factory deploying `cb` (registered by construction). A visible
/// receipt without that deploy lets the "not registered" stand, as does
/// a record without a deploy tx (a rediscovered chequebook) or one older
/// than the grace (a backend doesn't lag for that long; a record whose
/// deploy tx isn't on this chain would otherwise pass as "lag" forever).
#[cfg(feature = "chain-rpc")]
pub async fn not_registered_may_be_lag(
    client: &crate::ChainClient,
    persist_path: &std::path::Path,
    cb: &[u8; 20],
) -> bool {
    use crate::chequebook::{GNOSIS_CHEQUEBOOK_FACTORY, SIMPLE_SWAP_DEPLOYED_TOPIC};

    // An unreadable mtime, or one in the future (clock change), counts as
    // outside the grace: the factory's "no" is a real answer.
    let recent = std::fs::metadata(persist_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < DEPLOY_LAG_GRACE);
    if !recent {
        return false;
    }
    let Some(deploy_tx) = std::fs::read(persist_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<ChequebookFile>(&b).ok())
        .and_then(|f| {
            let mut tx = [0u8; 32];
            hex::decode_to_slice(f.deploy_tx.trim_start_matches("0x"), &mut tx).ok()?;
            Some(tx)
        })
    else {
        return false;
    };
    match client.eth_get_transaction_receipt(&deploy_tx).await {
        Ok(Some(receipt)) => receipt.logs.iter().any(|l| {
            l.address == GNOSIS_CHEQUEBOOK_FACTORY
                && l.topics.first() == Some(&SIMPLE_SWAP_DEPLOYED_TOPIC)
                && l.data.get(12..32) == Some(cb.as_slice())
        }),
        Ok(None) | Err(_) => true,
    }
}

/// What [`top_up_chequebook`] did.
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopUp {
    /// The chequebook already holds at least the target.
    NotNeeded,
    /// Moved `amount` PLUR from the wallet into the chequebook.
    Funded { amount: u128, tx: [u8; 32] },
    /// The chequebook is `shortfall` PLUR short, and the wallet holds no
    /// xBZZ to give.
    WalletEmpty { shortfall: u128 },
    /// The chain says no to this chequebook for `node_eth` (not
    /// factory-registered, or issued by someone else): nothing was
    /// sent. Peers drop its cheques, so a deposit would only strand
    /// xBZZ in it; the caller should switch settlement off for it.
    Refused(ChequebookVerdict),
}

/// Top `chequebook`'s xBZZ deposit up to `target_plur` from the node
/// wallet. The transfer is capped to what the wallet holds: a thin
/// wallet gives a partial deposit rather than a failed transfer (some
/// backing beats none). It never withdraws, so a chequebook at or above
/// the target is left alone.
///
/// Right before the transfer it runs [`check_chequebook`] and sends
/// only on a positive answer to both checks (registered with the
/// factory, `issuer()` is `node_eth`). Stricter than
/// [`ChequebookChecks::verdict`], which lets a failed read pass so an
/// RPC hiccup doesn't switch settlement off: a deposit can't be taken
/// back, so a failed read is an error here and a "no" is
/// [`TopUp::Refused`]. The check runs whatever the caller already
/// verified, so no path can fund a chequebook the chain rejects.
///
/// A chequebook that backs nothing only publishes until the peers'
/// payment tolerance runs out, then stalls (#73). Adopted chequebooks
/// (persisted, or rediscovered on-chain) can be sitting at zero, so both
/// `antd` and `ant-ffi` top them up with this before relying on them.
#[cfg(feature = "chain-rpc")]
pub async fn top_up_chequebook(
    client: &crate::ChainClient,
    wallet: &crate::tx::Wallet,
    node_eth: &[u8; 20],
    chequebook: &[u8; 20],
    target_plur: u128,
) -> Result<TopUp, ChequebookError> {
    use crate::chequebook::GNOSIS_BZZ_TOKEN_BYTES;
    use primitive_types::U256;

    let have = client
        .erc20_balance_of_lower128(crate::GNOSIS_BZZ_TOKEN, chequebook)
        .await
        .map_err(|e| ChequebookError::Chain(format!("read chequebook deposit: {e}")))?;
    let shortfall = target_plur.saturating_sub(have);
    if shortfall == 0 {
        return Ok(TopUp::NotNeeded);
    }
    let wallet_bzz = client
        .erc20_balance_of_lower128(crate::GNOSIS_BZZ_TOKEN, node_eth)
        .await
        .map_err(|e| ChequebookError::Chain(format!("read wallet xBZZ: {e}")))?;
    let amount = shortfall.min(wallet_bzz);
    if amount == 0 {
        return Ok(TopUp::WalletEmpty { shortfall });
    }
    let checks = check_chequebook(client, chequebook, IssuerRead::UnlessUnregistered).await;
    match checks.verdict(node_eth) {
        ChequebookVerdict::Usable => {}
        refused => return Ok(TopUp::Refused(refused)),
    }
    // Usable with a read that failed is unverified, not a "yes".
    let unread = [
        checks.registered.err(),
        checks.issuer.map_or_else(
            || Some(ChequebookError::Chain("issuer() not read".into())),
            Result::err,
        ),
    ];
    if let Some(e) = unread.into_iter().flatten().next() {
        return Err(ChequebookError::Chain(format!(
            "could not verify the chequebook before depositing into it: {e}"
        )));
    }
    let receipt = wallet
        .erc20_transfer(
            client,
            &GNOSIS_BZZ_TOKEN_BYTES,
            chequebook,
            U256::from(amount),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("deposit transfer: {e}")))?;
    note_deposit(chequebook, amount);
    Ok(TopUp::Funded {
        amount,
        tx: receipt.tx_hash,
    })
}

/// What a node's chequebook can put into SWAP cheques, and at which
/// rates: for downloads (issue #121) and uploads (issue #127) alike,
/// since both pay through the one shared payer. (The `Retrieval` in the
/// name predates #127.) Read with [`read_retrieval_funds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalFunds {
    /// xBZZ ever deposited and not withdrawn, in PLUR: the chequebook's
    /// balance plus what beneficiaries have already cashed
    /// (`totalPaidOut`), less any [`withdraw_from_chequebook`] in this
    /// process that is in flight or sent but not yet shown by the
    /// read (see [`WITHDRAWING`]). Bee's `AvailableBalance` is this minus every
    /// cheque issued so far, which only the issuing node knows.
    pub deposited_plur: u128,
    /// Bee's oracle exchange rate, PLUR per accounting unit.
    pub exchange_rate_plur: u128,
    /// Bee's oracle deduction, PLUR, added to the first cheque to a peer.
    pub deduction_plur: u128,
}

/// How often the entry points re-read [`RetrievalFunds`] while
/// settlement runs ([`watch_retrieval_funds`]), so a deposit made by any
/// path (a buy, a top-up, `POST /chequebook/deposit`, someone else's
/// transfer) starts paying for downloads and uploads (pushsync) within
/// this long.
#[cfg(feature = "chain-rpc")]
pub const RETRIEVAL_FUNDS_REFRESH: std::time::Duration = std::time::Duration::from_secs(60);

/// Read [`RetrievalFunds`] for `chequebook`: its xBZZ balance, its
/// `totalPaidOut()`, and bee's price oracle (`getPrice()`). Any failed
/// read is an error, never a zero: the caller keeps what it knew. While
/// [`withdraw_from_chequebook`] runs on `chequebook` in this process, and
/// for [`LANDED_WITHDRAWAL_TTL`] after it is sent, on any read that
/// doesn't show it, the deposit it reports is lowered by the amount
/// withdrawn. A read still unanswered after [`FUNDS_READ_TIMEOUT`] is an
/// error too.
#[cfg(feature = "chain-rpc")]
pub async fn read_retrieval_funds(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<RetrievalFunds, ChequebookError> {
    let raw = read_raw_retrieval_funds(client, chequebook).await?;
    Ok(with_withdrawals_applied(chequebook, raw))
}

/// `raw` (as [`read_raw_retrieval_funds`] returned it) less any
/// withdrawal in flight or landed but maybe not yet seen by the backend
/// that answered (see [`WITHDRAWING`]), so no read hands the node credit
/// a withdrawal is taking (or has taken) out. Evaluated against the
/// withdrawals known *now*, so a read taken a while ago is treated like
/// one from a backend that far behind, which [`Withdrawals::apply`]
/// already covers.
#[cfg(feature = "chain-rpc")]
fn with_withdrawals_applied(chequebook: &[u8; 20], raw: RetrievalFunds) -> RetrievalFunds {
    RetrievalFunds {
        deposited_plur: withdrawals_applied(chequebook, raw.deposited_plur),
        ..raw
    }
}

/// How long one [`RetrievalFunds`] read (all three calls) may take
/// before it fails. The reads are adjusted for this process's
/// withdrawals when they land, not when they were taken, and that only
/// covers a read taken while a withdrawal's [`Landed`] entry still
/// exists: a read stalled for longer than [`LANDED_WITHDRAWAL_TTL`]
/// could carry the pre-withdrawal deposit past the entry's expiry and
/// be published unadjusted. The RPC client has no timeout of its own,
/// so this bound is what keeps every read well inside the TTL.
#[cfg(feature = "chain-rpc")]
const FUNDS_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(feature = "chain-rpc")]
const _: () = assert!(FUNDS_READ_TIMEOUT.as_secs() * 2 <= LANDED_WITHDRAWAL_TTL.as_secs());

/// [`read_retrieval_funds`] as the chain answered it: the deposit is the
/// balance plus `totalPaidOut`, with no withdrawal of this process taken
/// off. Only for [`read_retrieval_funds`] and
/// [`read_and_publish_retrieval_funds`], which apply them. Fails after
/// [`FUNDS_READ_TIMEOUT`].
#[cfg(feature = "chain-rpc")]
async fn read_raw_retrieval_funds(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<RetrievalFunds, ChequebookError> {
    tokio::time::timeout(
        FUNDS_READ_TIMEOUT,
        read_raw_retrieval_funds_unbounded(client, chequebook),
    )
    .await
    .map_err(|_| {
        ChequebookError::Chain(format!(
            "chequebook funds read timed out after {}s",
            FUNDS_READ_TIMEOUT.as_secs()
        ))
    })?
}

#[cfg(feature = "chain-rpc")]
async fn read_raw_retrieval_funds_unbounded(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<RetrievalFunds, ChequebookError> {
    use crate::chequebook::{
        chequebook_total_paid_out_selector, price_oracle_get_price_selector,
        GNOSIS_SWAP_PRICE_ORACLE,
    };
    let word = |v: &[u8], at: usize, what: &str| -> Result<u128, ChequebookError> {
        let w = v
            .get(at..at + 32)
            .ok_or_else(|| ChequebookError::Chain(format!("{what} returned {} bytes", v.len())))?;
        if w[..16].iter().any(|&b| b != 0) {
            return Err(ChequebookError::Chain(format!("{what} overflows u128")));
        }
        Ok(u128::from_be_bytes(w[16..].try_into().expect("16 bytes")))
    };
    let balance = client
        .erc20_balance_of_lower128(crate::GNOSIS_BZZ_TOKEN, chequebook)
        .await
        .map_err(|e| ChequebookError::Chain(format!("read chequebook balance: {e}")))?;
    let paid_out = client
        .eth_call(
            &format!("0x{}", hex::encode(chequebook)),
            &format!("0x{}", hex::encode(chequebook_total_paid_out_selector())),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("chequebook.totalPaidOut eth_call: {e}")))?;
    let paid_out = word(&paid_out, 0, "chequebook.totalPaidOut")?;
    let price = client
        .eth_call(
            &format!("0x{}", hex::encode(GNOSIS_SWAP_PRICE_ORACLE)),
            &format!("0x{}", hex::encode(price_oracle_get_price_selector())),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("priceOracle.getPrice eth_call: {e}")))?;
    Ok(RetrievalFunds {
        deposited_plur: balance.saturating_add(paid_out),
        exchange_rate_plur: word(&price, 0, "priceOracle.getPrice")?,
        deduction_plur: word(&price, 32, "priceOracle.getPrice")?,
    })
}

/// Keep the node's view of `chequebook`'s [`RetrievalFunds`] current:
/// read them now and every [`RETRIEVAL_FUNDS_REFRESH`], handing each
/// successful read to `publish`. A failed read publishes nothing, so the
/// node keeps its last good value (a hiccup doesn't read as "empty").
/// Returns when `publish` returns `false` (the node is gone).
///
/// Both `antd` and `ant-ffi` run this for the chequebook settlement runs
/// on, publishing into `ControlCommand::SetRetrievalFunds`, so SWAP
/// payments for downloads (issue #121) and uploads (issue #127) spend at
/// most what the chequebook holds, on either entry point. Each keeps one
/// watch per node and aborts it when settlement moves to another
/// chequebook (or, in `antd`, is switched off): the node accepts funds
/// for any chequebook, so a stale watch would otherwise keep overwriting
/// the current one's.
///
/// A read that times out ([`FUNDS_READ_TIMEOUT`]) stops being waited
/// for, but a host chain transport call inside it can't be cancelled:
/// its blocking-pool thread stays in the host's `serve` until the host
/// returns. So while one of this watch's own host calls is still
/// outstanding, a tick starts no new read (the node keeps its last good
/// value, as for a failed read): a host that never answers holds one
/// thread for this watch, not one more per tick.
#[cfg(feature = "chain-rpc")]
pub async fn watch_retrieval_funds<F, Fut>(
    client: crate::ChainClient,
    chequebook: [u8; 20],
    mut publish: F,
) where
    F: FnMut(RetrievalFunds) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let client = client.with_own_host_call_count();
    loop {
        let parked = client.host_calls_in_flight();
        if parked > 0 {
            tracing::debug!(
                target: "ant_chain::chequebook_store",
                chequebook = %hex::encode(chequebook),
                parked,
                "retrieval funds not refreshed: an earlier read is still waiting on the host chain transport",
            );
            tokio::time::sleep(RETRIEVAL_FUNDS_REFRESH).await;
            continue;
        }
        match read_and_publish_retrieval_funds(&client, &chequebook, &mut publish).await {
            Ok((_, true)) => {}
            Ok((_, false)) => return,
            Err(e) => tracing::debug!(
                target: "ant_chain::chequebook_store",
                chequebook = %hex::encode(chequebook),
                "retrieval funds not refreshed: {e}",
            ),
        }
        tokio::time::sleep(RETRIEVAL_FUNDS_REFRESH).await;
    }
}

/// Read `chequebook`'s [`RetrievalFunds`] and hand them to `publish`
/// (which returns `false` once the node is gone). The chain read runs
/// unlocked; this process's withdrawals are taken off it, and the result
/// published, under [`FUNDS_PUBLISH`], so no read taken before a
/// [`withdraw_from_chequebook`] reserves its amount can reach the node
/// after the lowered funds it publishes: it gets the reservation taken
/// off when it is published, not when it was read. Every publisher of a
/// fresh read goes through this: [`watch_retrieval_funds`], the entry
/// points' refresh after a deposit, and the withdrawal's own re-read. A
/// failed read publishes nothing.
#[cfg(feature = "chain-rpc")]
pub async fn read_and_publish_retrieval_funds<F, Fut>(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
    publish: F,
) -> Result<(RetrievalFunds, bool), ChequebookError>
where
    F: FnOnce(RetrievalFunds) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let raw = read_raw_retrieval_funds(client, chequebook).await?;
    let _ordered = FUNDS_PUBLISH.lock().await;
    let funds = with_withdrawals_applied(chequebook, raw);
    Ok((funds, publish(funds).await))
}

/// Held while funds are adjusted for this process's withdrawals and
/// handed to the node ([`read_and_publish_retrieval_funds`]), and by
/// [`withdraw_from_chequebook`] from its reservation until the node has
/// the lowered funds (and, on a refusal, from releasing it until the
/// node has the funds back). Without it a read adjusted just before the
/// reservation (the full deposit) could land at the node after the
/// lowered figure and stand while the transaction confirms. Never held
/// across a chain read (bounded only by [`FUNDS_READ_TIMEOUT`]): only across
/// the in-memory adjustment and the hand-off to a local node, so one
/// node's stalled RPC can't hold up another's funds or a withdrawal. One
/// lock for every chequebook.
#[cfg(feature = "chain-rpc")]
static FUNDS_PUBLISH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Withdrawals in this process, per chequebook, that a chain read may
/// not show yet: PLUR a [`withdraw_from_chequebook`] may be taking out
/// right now, and withdrawals that have confirmed but that the backend
/// answering a read may not have caught up with (a lagging or
/// load-balanced RPC). [`read_retrieval_funds`] reports the deposit less
/// these (see [`Withdrawals::apply`]), so neither the per-minute
/// [`watch_retrieval_funds`], a refresh after a deposit, nor the re-read
/// right after the withdrawal hands the node credit that is leaving, or
/// has left, the chequebook.
#[cfg(feature = "chain-rpc")]
static WITHDRAWING: std::sync::Mutex<std::collections::BTreeMap<[u8; 20], Withdrawals>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// How long a confirmed withdrawal is still taken off reads that don't
/// show it (see [`Landed`]). Far past any RPC backend's lag. One read
/// that shows it proves nothing about the next: behind a load-balanced
/// RPC, a backend a block behind can still answer the pre-withdrawal
/// deposit after a caught-up one answered, so the entry stays the whole
/// TTL. A deposit this process makes meanwhile raises the ceiling with
/// it ([`note_deposit`]), so it counts in full at once; one made from
/// elsewhere (another process, a plain transfer) lifts the read above
/// the ceiling and is under-reported (the safe way) by up to the amount
/// withdrawn until the entry expires.
///
/// A withdrawal whose transaction was sent but not seen to confirm (the
/// receipt wait timed out, an RPC error after the send, the call was
/// cancelled) is kept the same way, from when the call gave up: if it
/// is still pending it may land at any moment. One still unmined
/// [`LANDED_WITHDRAWAL_TTL`] after that is no longer covered.
#[cfg(feature = "chain-rpc")]
const LANDED_WITHDRAWAL_TTL: std::time::Duration = std::time::Duration::from_mins(10);

/// One chequebook's entry in [`WITHDRAWING`].
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Default)]
struct Withdrawals {
    /// PLUR being withdrawn right now (see [`WithdrawReservation`]).
    in_flight: u128,
    /// Confirmed withdrawals, oldest first, younger than
    /// [`LANDED_WITHDRAWAL_TTL`].
    landed: Vec<Landed>,
}

/// A withdrawal of `amount` PLUR that confirmed (or may still: sent, but
/// the call gave up before its receipt). A read whose deposit is above
/// `ceiling` (the deposit right before it, less `amount`, plus every
/// deposit this process made since, see [`note_deposit`]) may come from
/// a backend that hasn't seen the transaction: the deposit only drops
/// through withdrawals, so it gets `amount` taken off. A read at or
/// below `ceiling` shows it and is left as is, but the entry stays
/// until `expires`: the next read may come from a backend that is still
/// behind. If a deposit from elsewhere lands meanwhile, the read stays
/// above `ceiling` and is under-reported (the safe way) until
/// `expires`.
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Landed {
    amount: u128,
    ceiling: u128,
    expires: std::time::Instant,
}

#[cfg(feature = "chain-rpc")]
impl Withdrawals {
    /// `raw` (a chequebook's balance plus `totalPaidOut`, as one read
    /// returned it) less what this process knows has left or is leaving:
    /// every withdrawal in flight, and every landed one `raw` doesn't
    /// show. Drops only expired landed entries: one read showing a
    /// withdrawal doesn't mean the next (maybe from a lagging backend)
    /// will.
    fn apply(&mut self, raw: u128, now: std::time::Instant) -> u128 {
        self.landed.retain(|l| now < l.expires);
        self.landed
            .iter()
            .filter(|l| raw > l.ceiling)
            .fold(raw.saturating_sub(self.in_flight), |d, l| {
                d.saturating_sub(l.amount)
            })
    }

    fn is_empty(&self) -> bool {
        self.in_flight == 0 && self.landed.is_empty()
    }
}

#[cfg(feature = "chain-rpc")]
fn withdrawing_map(
) -> std::sync::MutexGuard<'static, std::collections::BTreeMap<[u8; 20], Withdrawals>> {
    WITHDRAWING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `raw` deposit read for `chequebook`, less its [`Withdrawals`].
#[cfg(feature = "chain-rpc")]
fn withdrawals_applied(chequebook: &[u8; 20], raw: u128) -> u128 {
    let mut map = withdrawing_map();
    let Some(w) = map.get_mut(chequebook) else {
        return raw;
    };
    let deposited = w.apply(raw, std::time::Instant::now());
    if w.is_empty() {
        map.remove(chequebook);
    }
    deposited
}

/// `amount` PLUR were just deposited into `chequebook` by this process
/// (a confirmed transfer): raise the ceiling of every [`Landed`]
/// withdrawal on it by as much, so a read that shows both the
/// withdrawal and the deposit isn't taken for one that shows neither
/// and the deposit counts at once. Still safe on a lagging backend: one
/// that shows the deposit but not the withdrawal reads above the raised
/// ceiling and still has it taken off; one that shows neither reads at
/// most the pre-withdrawal deposit, which is then either taken off
/// (above the ceiling) or not more than what the chain now holds.
/// Called by [`top_up_chequebook`] and `ant-gateway`'s
/// `POST /chequebook/deposit`.
#[cfg(feature = "chain-rpc")]
pub fn note_deposit(chequebook: &[u8; 20], amount: u128) {
    if let Some(w) = withdrawing_map().get_mut(chequebook) {
        for l in &mut w.landed {
            l.ceiling = l.ceiling.saturating_add(amount);
        }
    }
}

/// PLUR being withdrawn from `chequebook` right now (see [`WITHDRAWING`]).
#[cfg(all(test, feature = "chain-rpc"))]
fn withdrawing(chequebook: &[u8; 20]) -> u128 {
    withdrawing_map().get(chequebook).map_or(0, |w| w.in_flight)
}

/// One withdrawal's in-flight PLUR in [`WITHDRAWING`], removed on drop:
/// on every way out of [`withdraw_from_chequebook`], including a
/// cancelled future. Once [`WithdrawReservation::sending`] was called
/// the transaction may be on its way, so the drop first adds a
/// [`Landed`] entry for it, unless [`WithdrawReservation::not_sent`]
/// says it can't have taken anything out. The landed entry goes in
/// before the in-flight amount comes out (one lock), so no read sees
/// neither.
#[cfg(feature = "chain-rpc")]
struct WithdrawReservation {
    chequebook: [u8; 20],
    amount: u128,
    /// The deposit right before the withdrawal.
    before: u128,
    sending: bool,
}

#[cfg(feature = "chain-rpc")]
impl WithdrawReservation {
    fn new(chequebook: [u8; 20], amount: u128, before: u128) -> Self {
        let mut map = withdrawing_map();
        let entry = map.entry(chequebook).or_default();
        entry.in_flight = entry.in_flight.saturating_add(amount);
        Self {
            chequebook,
            amount,
            before,
            sending: false,
        }
    }

    /// The transaction goes out now: from here on, however the call
    /// ends (confirmed, a receipt timeout, an RPC error, a cancelled
    /// future), the withdrawal is kept off reads that don't show it.
    fn sending(&mut self) {
        self.sending = true;
    }

    /// The transaction took nothing out (it reverted, or was never
    /// signed): just release the amount.
    fn not_sent(mut self) {
        self.sending = false;
    }
}

#[cfg(feature = "chain-rpc")]
impl Drop for WithdrawReservation {
    fn drop(&mut self) {
        let mut map = withdrawing_map();
        if self.sending {
            map.entry(self.chequebook).or_default().landed.push(Landed {
                amount: self.amount,
                ceiling: self.before.saturating_sub(self.amount),
                expires: std::time::Instant::now() + LANDED_WITHDRAWAL_TTL,
            });
        }
        if let Some(w) = map.get_mut(&self.chequebook) {
            w.in_flight = w.in_flight.saturating_sub(self.amount);
            if w.is_empty() {
                map.remove(&self.chequebook);
            }
        }
    }
}

/// What [`withdraw_from_chequebook`] took out of the chequebook.
#[cfg(feature = "chain-rpc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdrawal {
    /// PLUR moved back to the node wallet.
    pub amount_plur: u128,
    /// The `withdraw` transaction.
    pub tx: [u8; 32],
    /// The chequebook's funds read back afterwards and handed to the
    /// node; `None` when that read failed (the node then keeps the
    /// lowered figure it was given before the transaction, which is what
    /// the chain holds now, until the funds watch's next read).
    pub funds: Option<RetrievalFunds>,
}

/// Why [`withdraw_from_chequebook`] sent nothing, or what failed.
/// `Display` is the message the apps show.
#[cfg(feature = "chain-rpc")]
#[derive(Debug, thiserror::Error)]
pub enum WithdrawError {
    /// A zero amount.
    #[error("{0}")]
    Invalid(String),
    /// More than the chequebook can give back: what isn't backing an
    /// issued cheque (deposit less every cheque issued), and not more
    /// than its liquid balance. Nothing was sent.
    #[error(
        "can withdraw at most {} xBZZ now: the rest of the chequebook backs cheques already \
         issued to peers",
        format_plur_as_bzz(*available_plur)
    )]
    ExceedsAvailable {
        requested_plur: u128,
        available_plur: u128,
    },
    /// The node can't say what it has issued from this chequebook, so no
    /// amount is known to be free. Nothing was sent.
    #[error("not withdrawing: {0}")]
    IssuedUnknown(String),
    /// The chequebook's `issuer()` is another address; only the issuer
    /// may withdraw. Nothing was sent.
    #[error(
        "chequebook 0x{} is issued by 0x{}, not this node; only its issuer can withdraw",
        hex::encode(chequebook),
        hex::encode(issuer)
    )]
    NotIssuer {
        chequebook: [u8; 20],
        issuer: [u8; 20],
    },
    /// A chain read before the transaction failed, or the node is gone.
    /// Nothing was sent.
    #[error("{0}")]
    Chain(String),
    /// The `withdraw` transaction failed to send, reverted or timed out.
    #[error("withdraw transaction: {0}")]
    Tx(String),
}

/// PLUR as xBZZ (16 decimals), trailing zeros trimmed: `"0.0015"`.
#[cfg(feature = "chain-rpc")]
fn format_plur_as_bzz(plur: u128) -> String {
    const PLUR_PER_BZZ: u128 = 10_000_000_000_000_000;
    let frac = format!("{:016}", plur % PLUR_PER_BZZ);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{}", plur / PLUR_PER_BZZ)
    } else {
        format!("{}.{frac}", plur / PLUR_PER_BZZ)
    }
}

/// `chequebook.liquidBalance()`: xBZZ (PLUR) not held by hard deposits,
/// the most `withdraw` accepts.
#[cfg(feature = "chain-rpc")]
async fn read_liquid_balance(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
) -> Result<u128, ChequebookError> {
    let v = client
        .eth_call(
            &format!("0x{}", hex::encode(chequebook)),
            &format!(
                "0x{}",
                hex::encode(crate::chequebook::chequebook_liquid_balance_selector())
            ),
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("chequebook.liquidBalance eth_call: {e}")))?;
    let w = v.get(..32).ok_or_else(|| {
        ChequebookError::Chain(format!(
            "chequebook.liquidBalance returned {} bytes",
            v.len()
        ))
    })?;
    if w[..16].iter().any(|&b| b != 0) {
        // More than u128 holds is more than any withdrawal asks for.
        return Ok(u128::MAX);
    }
    Ok(u128::from_be_bytes(w[16..].try_into().expect("16 bytes")))
}

/// What a withdrawal may take: the deposit (`funds.deposited_plur`, all
/// xBZZ ever deposited and not withdrawn) less every cheque `issued`
/// from it, so the chequebook keeps backing each cheque peers hold (bee's
/// `availableBalance`), and no more than its `liquid` balance.
#[cfg(feature = "chain-rpc")]
fn withdrawable(funds: &RetrievalFunds, issued: u128, liquid: u128) -> u128 {
    funds.deposited_plur.saturating_sub(issued).min(liquid)
}

/// Withdraw `amount` PLUR from `chequebook` back to the node wallet
/// (`SimpleSwap.withdraw`, signed by `wallet`, which must be its
/// issuer), never touching xBZZ that backs a cheque already issued.
/// Shared by `antd`'s `POST /chequebook/withdraw` (the gateway's chain
/// writer) and `ant-ffi`'s `ant_storage_settlement_withdraw_amount`.
///
/// The node is told about it through two callbacks: `publish` hands it
/// the chequebook's funds (`ControlCommand::SetRetrievalFunds`; `false`
/// when the node is gone), and `issued` asks for the PLUR it has issued
/// from `chequebook` (an error when that total isn't fully known, see
/// `ant_control::AccountingSnapshotView::issued_from`; the withdrawal is
/// then refused, since no amount is known to be free).
///
/// Steps: check `issuer()` is the wallet; read the funds and
/// `liquidBalance()`; refuse an amount above [`withdrawable`]. Then, so
/// the node can't sign cheques against the xBZZ while the transaction
/// confirms, the amount is reserved (every [`read_retrieval_funds`] in
/// this process reports the deposit less it) and the lowered funds are
/// handed to the node; with them in place the issued total is read
/// again and checked once more, so a cheque issued in between still
/// counts. Only then is `withdraw` sent. Afterwards the funds are read
/// back and handed to the node, so its `paying`/`available_plur` follow
/// at once. Once the transaction is sent, the reservation becomes a
/// landed withdrawal that every read that doesn't show it keeps taking
/// off for [`LANDED_WITHDRAWAL_TTL`] (see [`Landed`]), so a lagging or
/// load-balanced RPC answering with the pre-withdrawal deposit, even
/// after another backend already showed it, doesn't hand the node xBZZ
/// that has left. The same holds when the call never sees the receipt
/// (a timeout, an RPC error, a cancelled future), since the transaction
/// may still land; only a revert, or a transaction never signed,
/// releases it.
///
/// A refusal before the transaction sends nothing and gives the node its
/// unlowered funds back. The caller holds its wallet tx lock around the
/// call, which also keeps two withdrawals (or a withdrawal and a deposit)
/// from racing each other's reads.
///
/// # Errors
///
/// See [`WithdrawError`]; everything but [`WithdrawError::Tx`] means
/// nothing was sent.
#[cfg(feature = "chain-rpc")]
pub async fn withdraw_from_chequebook<P, PF, I, IF>(
    client: &crate::ChainClient,
    wallet: &crate::tx::Wallet,
    chequebook: &[u8; 20],
    amount: u128,
    mut publish: P,
    mut issued: I,
) -> Result<Withdrawal, WithdrawError>
where
    P: FnMut(RetrievalFunds) -> PF,
    PF: std::future::Future<Output = bool>,
    I: FnMut() -> IF,
    IF: std::future::Future<Output = Result<u128, String>>,
{
    if amount == 0 {
        return Err(WithdrawError::Invalid(
            "a withdrawal must be more than 0 PLUR".into(),
        ));
    }
    let issuer = read_chequebook_issuer(client, chequebook)
        .await
        .map_err(|e| WithdrawError::Chain(e.to_string()))?;
    if issuer != *wallet.address() {
        return Err(WithdrawError::NotIssuer {
            chequebook: *chequebook,
            issuer,
        });
    }
    let funds = read_retrieval_funds(client, chequebook)
        .await
        .map_err(|e| WithdrawError::Chain(e.to_string()))?;
    let liquid = read_liquid_balance(client, chequebook)
        .await
        .map_err(|e| WithdrawError::Chain(e.to_string()))?;
    let free = withdrawable(
        &funds,
        issued().await.map_err(WithdrawError::IssuedUnknown)?,
        liquid,
    );
    if amount > free {
        return Err(WithdrawError::ExceedsAvailable {
            requested_plur: amount,
            available_plur: free,
        });
    }

    // Held until the node has the lowered funds: a funds read taken
    // before the reservation can't reach the node after them.
    let ordered = FUNDS_PUBLISH.lock().await;
    let mut reservation = WithdrawReservation::new(*chequebook, amount, funds.deposited_plur);
    let lowered = RetrievalFunds {
        deposited_plur: funds.deposited_plur.saturating_sub(amount),
        ..funds
    };
    if !publish(lowered).await {
        return Err(WithdrawError::Chain(
            "the node stopped; nothing was withdrawn".into(),
        ));
    }
    drop(ordered);
    // Cheques issued before the node had the lowered funds count now.
    let refused = match issued().await {
        Err(e) => Some(WithdrawError::IssuedUnknown(e)),
        Ok(now) => {
            let free = withdrawable(&funds, now, liquid);
            (amount > free).then_some(WithdrawError::ExceedsAvailable {
                requested_plur: amount,
                available_plur: free,
            })
        }
    };
    if let Some(e) = refused {
        let _ordered = FUNDS_PUBLISH.lock().await;
        drop(reservation);
        publish(funds).await;
        return Err(e);
    }

    // From here the transaction may be out: the reservation becomes a
    // landed withdrawal however this ends, a cancelled future included
    // (the gateway's client hanging up mid-wait), unless the chain says
    // it took nothing. The backend answering the next reads may not
    // have the block yet, or the transaction may still be pending: keep
    // the amount off every read that doesn't show it.
    reservation.sending();
    let sent = wallet
        .withdraw_from_chequebook(client, chequebook, primitive_types::U256::from(amount))
        .await;
    match &sent {
        Err(
            crate::tx::TxError::Reverted { .. }
            | crate::tx::TxError::Crypto(_)
            | crate::tx::TxError::Rlp(_),
        ) => reservation.not_sent(),
        // Confirmed, or maybe still pending (a receipt timeout, an RPC
        // error that may have come after the send).
        _ => drop(reservation),
    }
    let after = match read_and_publish_retrieval_funds(client, chequebook, &mut publish).await {
        Ok((after, _)) => Some(after),
        Err(e) => {
            tracing::debug!(
                target: "ant_chain::chequebook_store",
                chequebook = %hex::encode(chequebook),
                "funds not re-read after the withdrawal (the watch retries): {e}",
            );
            None
        }
    };
    let receipt = sent.map_err(|e| WithdrawError::Tx(e.to_string()))?;
    Ok(Withdrawal {
        amount_plur: amount,
        tx: receipt.tx_hash,
        funds: after,
    })
}

/// Run the chequebook checks against the chain: factory registration,
/// then `issuer()` as `issuer_read` allows. Shared by `antd` (every
/// chequebook it adopts at startup) and `ant-ffi` (a persisted
/// chequebook before enabling settlement), so the two can't disagree on
/// what makes a chequebook unusable.
#[cfg(feature = "chain-rpc")]
pub async fn check_chequebook(
    client: &crate::ChainClient,
    chequebook: &[u8; 20],
    issuer_read: IssuerRead,
) -> ChequebookChecks {
    let registered = verify_chequebook_with_factory(client, chequebook).await;
    let read_issuer = match issuer_read {
        IssuerRead::Never => false,
        IssuerRead::UnlessUnregistered => !matches!(registered, Ok(false)),
        IssuerRead::Always => true,
    };
    let issuer = if read_issuer {
        Some(read_chequebook_issuer(client, chequebook).await)
    } else {
        None
    };
    ChequebookChecks { registered, issuer }
}

/// Deploy a fresh factory-registered chequebook (issuer = `node_eth`,
/// gas paid by `wallet`), persist the association at `persist_path`,
/// then optionally fund it with up to `deposit_plur` xBZZ (capped to
/// the wallet's balance; `0` deploys it unfunded — bee still accepts
/// the cheques, cashing waits for a later deposit). Returns the
/// deployed chequebook address.
///
/// A gas pre-flight runs first: a deploy we can't pay for just burns a
/// failed-tx wait, so an underfunded wallet surfaces as
/// [`ChequebookError::InsufficientGas`] before anything is signed. The
/// reserve covers the funding transfer too when `deposit_plur > 0`.
#[cfg(feature = "chain-rpc")]
pub async fn auto_deploy_chequebook(
    client: &crate::ChainClient,
    wallet: &crate::tx::Wallet,
    node_eth: &[u8; 20],
    deposit_plur: u128,
    persist_path: &Path,
) -> Result<[u8; 20], ChequebookError> {
    use crate::chequebook::{
        extract_deployed_chequebook, random_chequebook_salt, DEFAULT_HARD_DEPOSIT_TIMEOUT_SECS,
        GNOSIS_BZZ_TOKEN_BYTES, GNOSIS_CHEQUEBOOK_FACTORY,
    };
    use crate::tx::{DEFAULT_GAS_PRICE_WEI, ERC20_TRANSFER_GAS, FACTORY_DEPLOY_CHEQUEBOOK_GAS};
    use primitive_types::U256;

    let gas_units = if deposit_plur > 0 {
        FACTORY_DEPLOY_CHEQUEBOOK_GAS + ERC20_TRANSFER_GAS
    } else {
        FACTORY_DEPLOY_CHEQUEBOOK_GAS
    };
    let need_gas_wei = U256::from(DEFAULT_GAS_PRICE_WEI).saturating_mul(U256::from(gas_units));
    let native = client
        .eth_get_balance_lower128(node_eth)
        .await
        .map_err(|e| ChequebookError::Chain(format!("read node xDAI balance: {e}")))?;
    if U256::from(native) < need_gas_wei {
        return Err(ChequebookError::InsufficientGas {
            wallet: hex::encode(node_eth),
            have: native.to_string(),
            need: need_gas_wei.to_string(),
        });
    }

    let salt = random_chequebook_salt();
    tracing::info!(
        target: "ant_chain::chequebook",
        factory = %format!("0x{}", hex::encode(GNOSIS_CHEQUEBOOK_FACTORY)),
        issuer = %format!("0x{}", hex::encode(node_eth)),
        "auto-deploying a factory-registered chequebook (issuer = node EOA)",
    );
    let receipt = wallet
        .deploy_chequebook(
            client,
            &GNOSIS_CHEQUEBOOK_FACTORY,
            node_eth,
            U256::from(DEFAULT_HARD_DEPOSIT_TIMEOUT_SECS),
            &salt,
        )
        .await
        .map_err(|e| ChequebookError::Chain(format!("factory.deploySimpleSwap: {e}")))?;
    let cb = extract_deployed_chequebook(&receipt)
        .ok_or_else(|| ChequebookError::NoDeployLog(hex::encode(receipt.tx_hash)))?;
    tracing::info!(
        target: "ant_chain::chequebook",
        chequebook = %format!("0x{}", hex::encode(cb)),
        tx = %format!("0x{}", hex::encode(receipt.tx_hash)),
        block = receipt.block_number,
        "auto-deployed chequebook",
    );

    // Persist before funding so a crash between the deploy and the
    // transfer still reuses this chequebook on the next start rather
    // than deploying a second one.
    persist_chequebook(
        persist_path,
        &ChequebookFile {
            chequebook: format!("0x{}", hex::encode(cb)),
            issuer: format!("0x{}", hex::encode(node_eth)),
            salt: format!("0x{}", hex::encode(salt)),
            deploy_tx: format!("0x{}", hex::encode(receipt.tx_hash)),
        },
    )?;

    if deposit_plur > 0 {
        match client
            .erc20_balance_of_lower128(crate::GNOSIS_BZZ_TOKEN, node_eth)
            .await
        {
            Ok(bzz_bal) => {
                let deposit = deposit_plur.min(bzz_bal);
                if deposit == 0 {
                    tracing::warn!(
                        target: "ant_chain::chequebook",
                        chequebook = %format!("0x{}", hex::encode(cb)),
                        "node wallet holds no xBZZ; deployed an unfunded chequebook (cheques are still accepted; deposit BZZ later)",
                    );
                } else {
                    match wallet
                        .erc20_transfer(client, &GNOSIS_BZZ_TOKEN_BYTES, &cb, U256::from(deposit))
                        .await
                    {
                        Ok(r) => tracing::info!(
                            target: "ant_chain::chequebook",
                            chequebook = %format!("0x{}", hex::encode(cb)),
                            deposit_plur = deposit,
                            tx = %format!("0x{}", hex::encode(r.tx_hash)),
                            "funded chequebook with xBZZ",
                        ),
                        Err(e) => tracing::warn!(
                            target: "ant_chain::chequebook",
                            chequebook = %format!("0x{}", hex::encode(cb)),
                            "chequebook funding transfer failed; chequebook is deployed and usable but unfunded: {e}",
                        ),
                    }
                }
            }
            Err(e) => tracing::warn!(
                target: "ant_chain::chequebook",
                "could not read node xBZZ balance; deployed chequebook left unfunded: {e}",
            ),
        }
    }

    Ok(cb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_target_scales_with_plan_depth() {
        const BZZ: u128 = 10_000_000_000_000_000;
        assert_eq!(deposit_target_for_depth(21), BZZ / 10);
        assert_eq!(deposit_target_for_depth(22), BZZ / 5);
        assert_eq!(deposit_target_for_depth(23), 2 * BZZ / 5);
        assert_eq!(deposit_target_for_depth(24), 4 * BZZ / 5);
        assert_eq!(deposit_target_for_depth(20), BZZ / 20);
        assert_eq!(deposit_target_for_depth(17), BZZ / 160);
    }

    #[test]
    fn deposit_target_is_floored_at_the_default() {
        // 0.1 xBZZ / 2^7 = 0.00078 xBZZ, under the 0.001 floor.
        assert_eq!(
            deposit_target_for_depth(14),
            DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR
        );
        assert_eq!(deposit_target_for_depth(0), DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR);
        // 0.1 xBZZ / 2^6 = 0.0016 xBZZ, still above it.
        assert!(deposit_target_for_depth(15) > DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR);
    }

    #[test]
    fn deposit_target_is_capped_at_one_bzz() {
        const BZZ: u128 = 10_000_000_000_000_000;
        assert_eq!(deposit_target_for_depth(25), BZZ, "1.6 xBZZ caps at 1");
        assert_eq!(deposit_target_for_depth(40), BZZ);
        // Shifts past u128's width don't wrap.
        assert_eq!(deposit_target_for_depth(149), BZZ);
        assert_eq!(deposit_target_for_depth(255), BZZ);
        assert!((0..=u8::MAX).all(|d| deposit_target_for_depth(d) <= BZZ));
    }

    #[test]
    fn persist_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("ant-cb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chequebook.json");
        let cb = [0x11u8; 20];
        persist_chequebook(&path, &ChequebookFile::rediscovered(&cb, &[0x22u8; 20])).unwrap();
        assert_eq!(
            load_persisted_chequebook_for(&path, &[0x22u8; 20]).unwrap(),
            Some(cb)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn owner_checked_load_skips_another_accounts_chequebook() {
        let dir = std::env::temp_dir().join(format!("ant-cb-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chequebook.json");
        let cb = [0x11u8; 20];
        let issuer = [0x22u8; 20];
        persist_chequebook(&path, &ChequebookFile::rediscovered(&cb, &issuer)).unwrap();

        // Its own issuer adopts it; anyone else sees "no chequebook" and
        // deploys their own rather than signing cheques bee will drop.
        assert_eq!(
            load_persisted_chequebook_for(&path, &issuer).unwrap(),
            Some(cb)
        );
        assert_eq!(
            load_persisted_chequebook_for(&path, &[0x33u8; 20]).unwrap(),
            None
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_none() {
        let path = std::env::temp_dir().join("definitely-not-a-chequebook-file-xyz.json");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            load_persisted_chequebook_for(&path, &[0x22u8; 20]).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_file_is_error() {
        let dir = std::env::temp_dir().join(format!("ant-cb-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chequebook.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_persisted_chequebook_for(&path, &[0x22u8; 20]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "chain-rpc")]
    #[test]
    fn chequebook_verdict_disqualifies_only_on_a_read_no() {
        let signer = [0x0au8; 20];
        let failed = || ChequebookError::Chain("backend unavailable".into());
        let checks = |registered, issuer| ChequebookChecks {
            registered,
            issuer: Some(issuer),
        };

        assert_eq!(
            checks(Ok(true), Ok(signer)).verdict(&signer),
            ChequebookVerdict::Usable
        );
        assert_eq!(
            checks(Ok(false), Ok(signer)).verdict(&signer),
            ChequebookVerdict::NotRegistered
        );
        assert_eq!(
            checks(Ok(true), Ok([0x5e; 20])).verdict(&signer),
            ChequebookVerdict::IssuerMismatch([0x5e; 20])
        );
        // Not registered wins over a mismatch: it's the first thing bee checks.
        assert_eq!(
            checks(Ok(false), Ok([0x5e; 20])).verdict(&signer),
            ChequebookVerdict::NotRegistered
        );
        // A read that failed is skipped, never a disqualification.
        assert_eq!(
            checks(Err(failed()), Ok(signer)).verdict(&signer),
            ChequebookVerdict::Usable
        );
        assert_eq!(
            checks(Ok(true), Err(failed())).verdict(&signer),
            ChequebookVerdict::Usable
        );
        assert_eq!(
            checks(Err(failed()), Err(failed())).verdict(&signer),
            ChequebookVerdict::Usable
        );
        // An issuer read that was skipped is not a mismatch.
        let skipped = |registered| ChequebookChecks {
            registered,
            issuer: None,
        };
        assert_eq!(
            skipped(Ok(true)).verdict(&signer),
            ChequebookVerdict::Usable
        );
        assert_eq!(
            skipped(Ok(false)).verdict(&signer),
            ChequebookVerdict::NotRegistered
        );
    }

    /// A scripted backend for the top-up decisions: xBZZ `balanceOf`,
    /// plus the two chequebook checks (`None` answers an RPC error).
    /// Anything else (a transfer) answers an error and is counted.
    #[cfg(feature = "chain-rpc")]
    struct Balances {
        of: std::collections::HashMap<[u8; 20], u128>,
        registered: Option<bool>,
        issuer: Option<[u8; 20]>,
        other_calls: std::sync::Mutex<usize>,
    }

    #[cfg(feature = "chain-rpc")]
    impl crate::transport::ChainTransport for Balances {
        fn serve(&self, request_json: &str) -> Option<String> {
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let data = req["params"][0]["data"].as_str().unwrap_or_default();
            let error = || {
                Some(
                    serde_json::json!({"jsonrpc": "2.0", "id": req["id"],
                        "error": {"code": -32603, "message": "backend unavailable"}})
                    .to_string(),
                )
            };
            let word = |w: String| {
                Some(
                    serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": w}).to_string(),
                )
            };
            if req["method"] == "eth_call" {
                let deployed_sel = hex::encode(
                    &crate::chequebook::factory_deployed_contracts_calldata(&CHEQUEBOOK)[..4],
                );
                let issuer_sel = hex::encode(crate::chequebook::chequebook_issuer_selector());
                if data.starts_with("0x70a08231") {
                    let mut owner = [0u8; 20];
                    hex::decode_to_slice(&data[34..74], &mut owner).unwrap();
                    return match self.of.get(&owner) {
                        Some(bal) => word(format!("0x{bal:064x}")),
                        None => error(),
                    };
                }
                if data[2..].starts_with(&deployed_sel) {
                    return match self.registered {
                        Some(r) => word(format!("0x{:064x}", u8::from(r))),
                        None => error(),
                    };
                }
                if data[2..].starts_with(&issuer_sel) {
                    return match self.issuer {
                        Some(i) => word(format!("0x{}{}", "00".repeat(12), hex::encode(i))),
                        None => error(),
                    };
                }
            }
            *self.other_calls.lock().unwrap() += 1;
            Some(
                serde_json::json!({"jsonrpc": "2.0", "id": req["id"],
                    "error": {"code": -32603, "message": "scripted: no transfer here"}})
                .to_string(),
            )
        }
    }

    #[cfg(feature = "chain-rpc")]
    async fn top_up_with(of: &[([u8; 20], u128)]) -> (Result<TopUp, ChequebookError>, usize) {
        top_up_checked(of, Some(true), Some(WALLET)).await
    }

    #[cfg(feature = "chain-rpc")]
    async fn top_up_checked(
        of: &[([u8; 20], u128)],
        registered: Option<bool>,
        issuer: Option<[u8; 20]>,
    ) -> (Result<TopUp, ChequebookError>, usize) {
        let script = std::sync::Arc::new(Balances {
            of: of.iter().copied().collect(),
            registered,
            issuer,
            other_calls: std::sync::Mutex::new(0),
        });
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(script.clone()));
        let wallet = crate::tx::Wallet::new([7u8; 32], crate::tx::GNOSIS_CHAIN_ID).unwrap();
        let result = top_up_chequebook(
            &client,
            &wallet,
            &WALLET,
            &CHEQUEBOOK,
            DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR,
        )
        .await;
        let others = *script.other_calls.lock().unwrap();
        (result, others)
    }

    /// A scripted chain for [`read_retrieval_funds`]: the chequebook's
    /// xBZZ balance, its `totalPaidOut()` and the price oracle. `None`
    /// answers an RPC error.
    #[cfg(feature = "chain-rpc")]
    struct FundsChain {
        balance: Option<u128>,
        paid_out: Option<u128>,
        price: Option<(u128, u128)>,
    }

    #[cfg(feature = "chain-rpc")]
    impl crate::transport::ChainTransport for FundsChain {
        fn serve(&self, request_json: &str) -> Option<String> {
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let to = req["params"][0]["to"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            let data = req["params"][0]["data"].as_str().unwrap_or_default();
            let answer = if data.starts_with("0x70a08231") {
                self.balance.map(|b| format!("0x{b:064x}"))
            } else if to == format!("0x{}", hex::encode(CHEQUEBOOK)) {
                assert_eq!(
                    &data[2..10],
                    hex::encode(crate::chequebook::chequebook_total_paid_out_selector())
                );
                self.paid_out.map(|p| format!("0x{p:064x}"))
            } else {
                assert_eq!(
                    to,
                    format!(
                        "0x{}",
                        hex::encode(crate::chequebook::GNOSIS_SWAP_PRICE_ORACLE)
                    )
                );
                self.price.map(|(r, d)| format!("0x{r:064x}{d:064x}"))
            };
            Some(
                match answer {
                    Some(w) => serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": w}),
                    None => serde_json::json!({"jsonrpc": "2.0", "id": req["id"],
                        "error": {"code": -32603, "message": "backend unavailable"}}),
                }
                .to_string(),
            )
        }
    }

    #[cfg(feature = "chain-rpc")]
    async fn funds_from(chain: FundsChain) -> Result<RetrievalFunds, ChequebookError> {
        let client = crate::ChainClient::new("http://127.0.0.1:1")
            .with_transport(Some(std::sync::Arc::new(chain)));
        read_retrieval_funds(&client, &CHEQUEBOOK).await
    }

    /// The funds are the deposit ever made (balance + cashed out), at the
    /// oracle's rates; any read that fails is an error, never a zero
    /// (issue #121).
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn retrieval_funds_add_cashed_out_to_the_balance() {
        let full = || FundsChain {
            balance: Some(15_000_000_000_000),
            paid_out: Some(5_000_000_000_000),
            price: Some((100_000, 100)),
        };
        assert_eq!(
            funds_from(full()).await.unwrap(),
            RetrievalFunds {
                deposited_plur: 20_000_000_000_000,
                exchange_rate_plur: 100_000,
                deduction_plur: 100,
            }
        );
        for broken in [
            FundsChain {
                balance: None,
                ..full()
            },
            FundsChain {
                paid_out: None,
                ..full()
            },
            FundsChain {
                price: None,
                ..full()
            },
        ] {
            assert!(funds_from(broken).await.is_err());
        }
    }

    /// A scripted chain for [`withdraw_from_chequebook`]: chequebook
    /// `cb`'s balance, `totalPaidOut`, `liquidBalance` and `issuer()`, the price
    /// oracle, and a `withdraw` transaction that mines at once and takes
    /// the amount out of the balance. Records each withdrawal's amount and
    /// the reservation [`read_retrieval_funds`] saw while it was sent.
    #[cfg(feature = "chain-rpc")]
    struct WithdrawChain {
        /// One per test: tests run in parallel and [`WITHDRAWING`] is
        /// process-wide, so none may share another's chequebook (nor
        /// [`CHEQUEBOOK`], whose funds other tests read).
        cb: [u8; 20],
        balance: std::sync::Mutex<u128>,
        paid_out: u128,
        liquid: Option<u128>,
        issuer: [u8; 20],
        /// `(amount, reserved while sending)`.
        withdrawn: std::sync::Mutex<Vec<(u128, u128)>>,
        /// How many `balanceOf` reads after a withdrawal still answer the
        /// balance from before it (a backend lagging behind the block).
        lagging_reads: std::sync::Mutex<u32>,
        /// The balance before the last withdrawal.
        before: std::sync::Mutex<Option<u128>>,
        /// The `withdraw` receipt's status: `Some("0x1")` mines it at
        /// once (the amount leaves the balance), `Some("0x0")` reverts
        /// it, `None` leaves it pending (no receipt, balance untouched).
        receipt: std::sync::Mutex<Option<&'static str>>,
    }

    #[cfg(feature = "chain-rpc")]
    impl crate::transport::ChainTransport for WithdrawChain {
        fn serve(&self, request_json: &str) -> Option<String> {
            use crate::chequebook::{
                chequebook_issuer_selector, chequebook_liquid_balance_selector,
                chequebook_total_paid_out_selector, GNOSIS_SWAP_PRICE_ORACLE,
            };
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let id = req["id"].clone();
            let word = |v: u128| format!("0x{v:064x}");
            let result = match req["method"].as_str().unwrap() {
                "eth_call" => {
                    let to = req["params"][0]["to"].as_str().unwrap().to_lowercase();
                    let data = req["params"][0]["data"].as_str().unwrap();
                    let sel = &data[2..10];
                    if data.starts_with("0x70a08231") {
                        assert_eq!(data[34..74], hex::encode(self.cb));
                        let mut lag = self.lagging_reads.lock().unwrap();
                        match *self.before.lock().unwrap() {
                            Some(before) if *lag > 0 => {
                                *lag -= 1;
                                word(before)
                            }
                            _ => word(*self.balance.lock().unwrap()),
                        }
                    } else if to == format!("0x{}", hex::encode(GNOSIS_SWAP_PRICE_ORACLE)) {
                        format!("0x{:064x}{:064x}", 100_000, 100)
                    } else if sel == hex::encode(chequebook_total_paid_out_selector()) {
                        word(self.paid_out)
                    } else if sel == hex::encode(chequebook_issuer_selector()) {
                        format!("0x{}{}", "00".repeat(12), hex::encode(self.issuer))
                    } else if sel == hex::encode(chequebook_liquid_balance_selector()) {
                        word(self.liquid.unwrap_or_else(|| *self.balance.lock().unwrap()))
                    } else {
                        panic!("unscripted eth_call {data}");
                    }
                }
                "eth_getTransactionCount" => "0x0".into(),
                "eth_sendRawTransaction" => {
                    let raw = hex::decode(&req["params"][0].as_str().unwrap()[2..]).unwrap();
                    let rlp = rlp::Rlp::new(&raw);
                    let to: Vec<u8> = rlp.at(3).unwrap().data().unwrap().to_vec();
                    let input: Vec<u8> = rlp.at(5).unwrap().data().unwrap().to_vec();
                    assert_eq!(to, self.cb);
                    assert_eq!(hex::encode(&input[..4]), "2e1a7d4d", "withdraw(uint256)");
                    let amount = u128::from_be_bytes(input[20..36].try_into().unwrap());
                    if *self.receipt.lock().unwrap() == Some("0x1") {
                        let mut balance = self.balance.lock().unwrap();
                        *self.before.lock().unwrap() = Some(*balance);
                        *balance -= amount;
                    }
                    self.withdrawn
                        .lock()
                        .unwrap()
                        .push((amount, withdrawing(&self.cb)));
                    word(1)
                }
                "eth_getTransactionReceipt" => {
                    let result = self.receipt.lock().unwrap().map(|status| {
                        serde_json::json!({"status": status, "blockNumber": "0x1", "logs": []})
                    });
                    return Some(
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
                            .to_string(),
                    );
                }
                other => panic!("unscripted method {other}"),
            };
            Some(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
        }
    }

    #[cfg(feature = "chain-rpc")]
    fn withdraw_wallet() -> crate::tx::Wallet {
        crate::tx::Wallet::new([9u8; 32], crate::tx::GNOSIS_CHAIN_ID).unwrap()
    }

    /// Balance 1000 + 200 cashed = 1200 deposited.
    #[cfg(feature = "chain-rpc")]
    fn withdraw_chain(cb: u8, liquid: Option<u128>) -> std::sync::Arc<WithdrawChain> {
        std::sync::Arc::new(WithdrawChain {
            cb: [cb; 20],
            balance: std::sync::Mutex::new(1000),
            paid_out: 200,
            liquid,
            issuer: *withdraw_wallet().address(),
            withdrawn: std::sync::Mutex::new(Vec::new()),
            lagging_reads: std::sync::Mutex::new(0),
            before: std::sync::Mutex::new(None),
            receipt: std::sync::Mutex::new(Some("0x1")),
        })
    }

    /// Run a withdrawal of `amount` with the node's issued total
    /// answering `issued` in turn. Returns the result and the deposits
    /// the node was handed.
    #[cfg(feature = "chain-rpc")]
    async fn withdraw_with(
        chain: &std::sync::Arc<WithdrawChain>,
        amount: u128,
        issued: &[Result<u128, String>],
    ) -> (Result<Withdrawal, WithdrawError>, Vec<u128>) {
        withdraw_waiting(chain, amount, issued, withdraw_wallet()).await
    }

    /// [`withdraw_with`], signing with `wallet` (its receipt wait).
    #[cfg(feature = "chain-rpc")]
    async fn withdraw_waiting(
        chain: &std::sync::Arc<WithdrawChain>,
        amount: u128,
        issued: &[Result<u128, String>],
        wallet: crate::tx::Wallet,
    ) -> (Result<Withdrawal, WithdrawError>, Vec<u128>) {
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let published = std::sync::Mutex::new(Vec::new());
        let answers = std::sync::Mutex::new(issued.iter().cloned());
        let result = withdraw_from_chequebook(
            &client,
            &wallet,
            &chain.cb,
            amount,
            |funds: RetrievalFunds| {
                published.lock().unwrap().push(funds.deposited_plur);
                async { true }
            },
            || {
                let next = answers
                    .lock()
                    .unwrap()
                    .next()
                    .expect("issued asked too often");
                async move { next }
            },
        )
        .await;
        assert_eq!(withdrawing(&chain.cb), 0, "the reservation is released");
        (result, published.into_inner().unwrap())
    }

    /// The cap: deposited 1200 less 500 issued leaves 700. One PLUR more
    /// is refused before anything is sent or the node is touched; 700
    /// goes through, with the node holding the lowered deposit while the
    /// transaction confirms and the chain's figure after it.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn withdraw_never_takes_what_issued_cheques_need() {
        let chain = withdraw_chain(0xc1, None);
        let (result, published) = withdraw_with(&chain, 701, &[Ok(500)]).await;
        assert!(
            matches!(
                result,
                Err(WithdrawError::ExceedsAvailable {
                    requested_plur: 701,
                    available_plur: 700
                })
            ),
            "{result:?}"
        );
        assert_eq!(published, [] as [u128; 0], "the node's funds untouched");
        assert!(chain.withdrawn.lock().unwrap().is_empty(), "nothing sent");

        let (result, published) = withdraw_with(&chain, 700, &[Ok(500), Ok(500)]).await;
        let done = result.unwrap();
        assert_eq!(done.amount_plur, 700);
        assert_eq!(done.funds.unwrap().deposited_plur, 500);
        assert_eq!(
            *chain.withdrawn.lock().unwrap(),
            [(700, 700)],
            "reserved while sent"
        );
        assert_eq!(*chain.balance.lock().unwrap(), 300);
        // Lowered before the transaction, the chain's figure after: the
        // 500 issued stay backed (300 balance + 200 cashed).
        assert_eq!(published, [500, 500]);
    }

    /// The first reads after the withdrawal come from a backend that
    /// hasn't seen its block and answer the old balance: neither the
    /// re-read handed to the node nor the next watch read gives back the
    /// 700 that left, nor does a lagging read after a caught-up one
    /// (a load-balanced RPC). Once the entry expires, reads are the
    /// chain's own figure again.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn withdraw_survives_a_lagging_backend() {
        let chain = withdraw_chain(0xc6, None);
        *chain.lagging_reads.lock().unwrap() = 2;
        let (result, published) = withdraw_with(&chain, 700, &[Ok(500), Ok(500)]).await;
        let done = result.unwrap();
        assert_eq!(*chain.balance.lock().unwrap(), 300);
        assert_eq!(
            done.funds.unwrap().deposited_plur,
            500,
            "not the stale 1200"
        );
        assert_eq!(published, [500, 500]);

        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let read = || async { read_retrieval_funds(&client, &chain.cb).await.unwrap() };
        // Still lagging: the watch's next read.
        assert_eq!(read().await.deposited_plur, 500);
        // Caught up: shows the withdrawal, taken as is.
        assert_eq!(read().await.deposited_plur, 500);
        // Another backend, still a block behind, answers next.
        *chain.lagging_reads.lock().unwrap() = 1;
        assert_eq!(read().await.deposited_plur, 500, "not the stale 1200");
        assert_eq!(read().await.deposited_plur, 500);
        // Once the entry expires, a later deposit counts in full.
        for w in &mut withdrawing_map().get_mut(&chain.cb).unwrap().landed {
            w.expires = std::time::Instant::now();
        }
        *chain.balance.lock().unwrap() += 1000;
        assert_eq!(read().await.deposited_plur, 1500);
        assert!(!withdrawing_map().contains_key(&chain.cb));
    }

    /// [`Withdrawals::apply`]: in-flight amounts always come off; a
    /// landed one only off reads above its ceiling, until it expires
    /// (a read that shows it doesn't end it: the next may lag).
    #[cfg(feature = "chain-rpc")]
    #[test]
    fn landed_withdrawals_come_off_until_seen() {
        let now = std::time::Instant::now();
        let landed = |amount, ceiling| Landed {
            amount,
            ceiling,
            expires: now + LANDED_WITHDRAWAL_TTL,
        };
        // 1200 → withdraw 100 → withdraw 50.
        let mut w = Withdrawals {
            in_flight: 0,
            landed: vec![landed(100, 1100), landed(50, 1050)],
        };
        assert_eq!(w.apply(1200, now), 1050, "sees neither");
        assert_eq!(w.landed.len(), 2);
        assert_eq!(w.apply(1100, now), 1050, "sees the first");
        assert_eq!(w.apply(1050, now), 1050, "sees both");
        assert_eq!(w.apply(1200, now), 1050, "a lagging read after both");
        assert_eq!(w.landed.len(), 2, "kept: the next read may lag");
        assert_eq!(w.apply(1200, now + LANDED_WITHDRAWAL_TTL), 1200, "expired");
        assert!(w.is_empty());

        // A deposit landing meanwhile keeps the read above the ceiling:
        // under-reported (never over) until the entry expires.
        let mut w = Withdrawals {
            in_flight: 30,
            landed: vec![landed(100, 1100)],
        };
        assert_eq!(w.apply(1400, now), 1270);
        assert_eq!(w.apply(1400, now + LANDED_WITHDRAWAL_TTL), 1370);
        assert_eq!(w.landed, []);
    }

    /// A withdrawal sent but not seen to confirm may still land: a
    /// receipt timeout, or the call cancelled mid-wait (the gateway's
    /// client hanging up), keeps the amount off every read that doesn't
    /// show it, as a confirmed one does. Only a revert releases it.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn an_unconfirmed_withdrawal_stays_off_the_funds() {
        // Receipt wait times out: 1200 deposited, 500 issued, 700 out.
        let chain = withdraw_chain(0xc7, None);
        *chain.receipt.lock().unwrap() = None;
        let impatient = withdraw_wallet().wait_for(std::time::Duration::ZERO);
        let (result, published) =
            withdraw_waiting(&chain, 700, &[Ok(500), Ok(500)], impatient).await;
        assert!(matches!(result, Err(WithdrawError::Tx(_))), "{result:?}");
        assert_eq!(*chain.balance.lock().unwrap(), 1000, "still pending");
        assert_eq!(published, [500, 500], "never the full 1200");
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let read = || async { read_retrieval_funds(&client, &chain.cb).await.unwrap() };
        assert_eq!(read().await.deposited_plur, 500, "pending");
        // It mines later: shown, taken as is.
        *chain.balance.lock().unwrap() = 300;
        assert_eq!(read().await.deposited_plur, 500, "mined");

        // Cancelled while waiting for the receipt.
        let chain = withdraw_chain(0xc8, None);
        *chain.receipt.lock().unwrap() = None;
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let issued = std::sync::Mutex::new([Ok(500), Ok(500)].into_iter());
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            withdraw_from_chequebook(
                &client,
                &withdraw_wallet(),
                &chain.cb,
                700,
                |_| async { true },
                || {
                    let next: Result<u128, String> = issued.lock().unwrap().next().unwrap();
                    async move { next }
                },
            ),
        )
        .await;
        assert!(cancelled.is_err(), "cancelled mid-wait");
        assert_eq!(withdrawing(&chain.cb), 0, "no longer in flight");
        let read = || async { read_retrieval_funds(&client, &chain.cb).await.unwrap() };
        assert_eq!(read().await.deposited_plur, 500, "not the full 1200");

        // Reverted: nothing left, nothing kept.
        let chain = withdraw_chain(0xc9, None);
        *chain.receipt.lock().unwrap() = Some("0x0");
        let (result, published) = withdraw_with(&chain, 700, &[Ok(500), Ok(500)]).await;
        assert!(matches!(result, Err(WithdrawError::Tx(_))), "{result:?}");
        assert_eq!(published, [500, 1200], "lowered, then the chain's figure");
        assert!(!withdrawing_map().contains_key(&chain.cb));
    }

    /// A funds read taken before the withdrawal reserved its amount (the
    /// full deposit) can't reach the node after the lowered funds: the
    /// withdrawal waits for it to be published first.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn a_stale_funds_read_never_lands_after_the_lowered_funds() {
        let chain = withdraw_chain(0xca, None);
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let published = std::sync::Mutex::new(Vec::new());
        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let watch = read_and_publish_retrieval_funds(&client, &chain.cb, |funds| {
            read_tx.send(()).unwrap();
            let published = &published;
            async move {
                // The node is slow to take this one.
                gate_rx.await.unwrap();
                published.lock().unwrap().push(funds.deposited_plur);
                true
            }
        });
        let issued = std::sync::Mutex::new([Ok(500), Ok(500)].into_iter());
        let withdraw = async {
            read_rx.await.unwrap();
            withdraw_from_chequebook(
                &client,
                &withdraw_wallet(),
                &chain.cb,
                700,
                |funds: RetrievalFunds| {
                    published.lock().unwrap().push(funds.deposited_plur);
                    async { true }
                },
                || {
                    let next: Result<u128, String> = issued.lock().unwrap().next().unwrap();
                    async move { next }
                },
            )
            .await
        };
        let release = async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert_eq!(
                *published.lock().unwrap(),
                [] as [u128; 0],
                "withdrawal waits"
            );
            gate_tx.send(()).unwrap();
        };
        let (watched, withdrawn, ()) = tokio::join!(watch, withdraw, release);
        assert_eq!(watched.unwrap().0.deposited_plur, 1200);
        withdrawn.unwrap();
        assert_eq!(*published.lock().unwrap(), [1200, 500, 500]);
    }

    /// A [`WithdrawChain`] whose first request is answered from the
    /// chain as it stands when it arrives, then held until `release`
    /// fires: an RPC backend that stalls after reading.
    #[cfg(feature = "chain-rpc")]
    struct StalledFirst {
        chain: std::sync::Arc<WithdrawChain>,
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    #[cfg(feature = "chain-rpc")]
    impl crate::transport::ChainTransport for StalledFirst {
        fn serve(&self, request_json: &str) -> Option<String> {
            let answer = self.chain.serve(request_json);
            let release = self.release.lock().unwrap().take();
            if let Some(release) = release {
                if let Some(entered) = self.entered.lock().unwrap().take() {
                    entered.send(()).unwrap();
                }
                release.recv().unwrap();
            }
            answer
        }
    }

    /// A stalled funds read holds no lock (R4-M1): another chequebook's
    /// withdrawal, its post-send re-read included, and another node's
    /// funds publish all go ahead while it hangs. When the stalled read
    /// (the full deposit, read before the withdrawal) finally lands, it
    /// gets the withdrawal taken off at that point, never the full 1200.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_funds_read_blocks_no_other_publish() {
        // Not 0xcb: that is [`CHEQUEBOOK`], whose funds other tests read.
        let stalled = withdraw_chain(0xcf, None);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let client = crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(
            std::sync::Arc::new(StalledFirst {
                chain: stalled.clone(),
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(Some(release_rx)),
            }),
        ));
        let stalled_cb = stalled.cb;
        let watch = tokio::spawn(async move {
            let published = std::sync::Mutex::new(Vec::new());
            let read = read_and_publish_retrieval_funds(&client, &stalled_cb, |funds| {
                published.lock().unwrap().push(funds.deposited_plur);
                async { true }
            })
            .await
            .unwrap();
            (read.0.deposited_plur, published.into_inner().unwrap())
        });
        entered_rx.await.unwrap();

        // Another chequebook withdraws, re-read and all, meanwhile.
        let other = withdraw_chain(0xcc, None);
        let (result, published) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            withdraw_with(&other, 700, &[Ok(500), Ok(500)]),
        )
        .await
        .expect("not held up by the stalled read");
        result.unwrap();
        assert_eq!(published, [500, 500]);
        // And another node's funds publish.
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(other.clone()));
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_and_publish_retrieval_funds(&client, &other.cb, |_| async { true }),
        )
        .await
        .expect("not held up by the stalled read")
        .unwrap();

        // The stalled chequebook withdraws too, while its read hangs on
        // the full deposit, then the read lands.
        let (result, published) = withdraw_with(&stalled, 700, &[Ok(500), Ok(500)]).await;
        result.unwrap();
        assert_eq!(published, [500, 500]);
        release_tx.send(()).unwrap();
        let (read, published) = watch.await.unwrap();
        assert_eq!(read, 500, "withdrawal taken off when published");
        assert_eq!(published, [500]);
    }

    /// A funds read whose RPC never answers fails after
    /// [`FUNDS_READ_TIMEOUT`] instead of hanging (R5-M1): a read stalled
    /// past [`LANDED_WITHDRAWAL_TTL`] would land after a withdrawal's
    /// entry expired and be published with the pre-withdrawal deposit.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test(start_paused = true)]
    async fn a_stalled_funds_read_times_out_inside_the_landed_ttl() {
        // Accepts connections and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(listener.accept().await.unwrap().0);
            }
        });
        let client = crate::ChainClient::new(url);
        let cb = [0xcd; 20];
        let started = tokio::time::Instant::now();
        let published = std::sync::Mutex::new(Vec::new());
        let err = read_and_publish_retrieval_funds(&client, &cb, |funds| {
            published.lock().unwrap().push(funds.deposited_plur);
            async { true }
        })
        .await
        .unwrap_err();
        let elapsed = started.elapsed();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(elapsed, FUNDS_READ_TIMEOUT);
        assert!(elapsed < LANDED_WITHDRAWAL_TTL);
        assert!(published.lock().unwrap().is_empty());
        assert!(read_retrieval_funds(&client, &cb).await.is_err());
        hold.abort();
    }

    /// A [`WithdrawChain`] whose host calls block until released while
    /// `hang` is set, counting how many entered `serve`.
    #[cfg(feature = "chain-rpc")]
    struct HangingHost {
        chain: std::sync::Arc<WithdrawChain>,
        hang: std::sync::atomic::AtomicBool,
        entered: std::sync::atomic::AtomicUsize,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    #[cfg(feature = "chain-rpc")]
    impl crate::transport::ChainTransport for HangingHost {
        fn serve(&self, request_json: &str) -> Option<String> {
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.hang.load(std::sync::atomic::Ordering::SeqCst) {
                self.release.lock().unwrap().recv().unwrap();
            }
            self.chain.serve(request_json)
        }
    }

    /// A host transport that never answers holds one blocking thread for
    /// the funds watch, not one more per tick (R6-M1): after its read
    /// times out, the watch starts no new read while that host call is
    /// still parked in `serve`, and reads again once the host returns.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test(start_paused = true)]
    async fn a_hung_host_parks_one_thread_per_funds_watch() {
        use std::sync::atomic::Ordering;
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let host = std::sync::Arc::new(HangingHost {
            chain: withdraw_chain(0xce, None),
            hang: std::sync::atomic::AtomicBool::new(true),
            entered: std::sync::atomic::AtomicUsize::new(0),
            release: std::sync::Mutex::new(release_rx),
        });
        let client =
            crate::ChainClient::new("http://127.0.0.1:1").with_transport(Some(host.clone()));
        let cb = host.chain.cb;
        let published = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let watch = tokio::spawn({
            let published = published.clone();
            async move {
                watch_retrieval_funds(client, cb, move |funds| {
                    published.lock().unwrap().push(funds.deposited_plur);
                    async { true }
                })
                .await;
            }
        });
        // A parked `spawn_blocking` keeps the paused clock from
        // auto-advancing, so move it by hand.
        async fn advance(by: std::time::Duration) {
            let step = std::time::Duration::from_secs(1);
            let mut left = by;
            while !left.is_zero() {
                tokio::time::advance(step.min(left)).await;
                left = left.saturating_sub(step);
                tokio::task::yield_now().await;
            }
        }
        // Ten ticks' worth: each would start a new read without the gate.
        advance(10 * (FUNDS_READ_TIMEOUT + RETRIEVAL_FUNDS_REFRESH)).await;
        assert_eq!(host.entered.load(Ordering::SeqCst), 1, "one parked call");
        assert!(published.lock().unwrap().is_empty());

        // The host answers at last: that late read is not published (it
        // was given up on), and the next tick reads again.
        host.hang.store(false, Ordering::SeqCst);
        release_tx.send(()).unwrap();
        for _ in 0..400 {
            if !published.lock().unwrap().is_empty() {
                break;
            }
            // Let the released thread finish before the clock moves on.
            std::thread::sleep(std::time::Duration::from_millis(1));
            advance(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(published.lock().unwrap().first(), Some(&1200));
        watch.abort();
    }

    /// A deposit this process makes after a withdrawal counts at once
    /// ([`note_deposit`]), and no backend, however far behind, reads
    /// above what the chain holds.
    #[cfg(feature = "chain-rpc")]
    #[test]
    fn a_deposit_after_a_withdrawal_counts_at_once() {
        // Its own: 0xcc withdraws in `a_stalled_funds_read_blocks_no_other_publish`.
        let cb = [0xd0; 20];
        let now = std::time::Instant::now();
        // 1200, withdraw 700 (500 left), then deposit 500: 1000 now.
        withdrawing_map().insert(
            cb,
            Withdrawals {
                in_flight: 0,
                landed: vec![Landed {
                    amount: 700,
                    ceiling: 500,
                    expires: now + LANDED_WITHDRAWAL_TTL,
                }],
            },
        );
        assert_eq!(withdrawals_applied(&cb, 1000), 300, "before the note");
        note_deposit(&cb, 500);
        assert_eq!(withdrawals_applied(&cb, 1000), 1000, "sees both");
        assert_eq!(
            withdrawals_applied(&cb, 500),
            500,
            "sees the withdrawal only"
        );
        assert_eq!(
            withdrawals_applied(&cb, 1700),
            1000,
            "sees the deposit only"
        );
        assert!(withdrawals_applied(&cb, 1200) <= 1000, "sees neither");
        // Less than withdrawn: a lagging read is still taken off.
        note_deposit(&cb, 0);
        withdrawing_map().get_mut(&cb).unwrap().landed[0].ceiling = 600;
        assert_eq!(withdrawals_applied(&cb, 1200), 500, "sees neither, 100 in");
        withdrawing_map().remove(&cb);
        // No withdrawal on record: nothing to do.
        note_deposit(&cb, 500);
        assert!(!withdrawing_map().contains_key(&cb));
    }

    /// Hard deposits: never more than `liquidBalance()`.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn withdraw_is_capped_at_the_liquid_balance() {
        let chain = withdraw_chain(0xc2, Some(100));
        let (result, _) = withdraw_with(&chain, 101, &[Ok(0)]).await;
        assert!(
            matches!(
                result,
                Err(WithdrawError::ExceedsAvailable {
                    available_plur: 100,
                    ..
                })
            ),
            "{result:?}"
        );
        assert!(chain.withdrawn.lock().unwrap().is_empty());
    }

    /// A cheque issued after the first check but before the node had the
    /// lowered funds still counts: refused, and the node gets its funds
    /// back.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn withdraw_rechecks_cheques_issued_meanwhile() {
        let chain = withdraw_chain(0xc3, None);
        let (result, published) = withdraw_with(&chain, 700, &[Ok(500), Ok(501)]).await;
        assert!(
            matches!(
                result,
                Err(WithdrawError::ExceedsAvailable {
                    available_plur: 699,
                    ..
                })
            ),
            "{result:?}"
        );
        assert!(chain.withdrawn.lock().unwrap().is_empty(), "nothing sent");
        assert_eq!(published, [500, 1200], "lowered, then restored");
    }

    /// An unknown issued total (no ledger loaded, a lost one) is not
    /// "nothing issued", and only the issuer may withdraw.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn withdraw_refuses_unknown_cheques_and_other_issuers() {
        let chain = withdraw_chain(0xc4, None);
        let (result, published) =
            withdraw_with(&chain, 1, &[Err("ledger unreadable".into())]).await;
        assert!(
            matches!(result, Err(WithdrawError::IssuedUnknown(_))),
            "{result:?}"
        );
        assert_eq!(published, [] as [u128; 0], "the node's funds untouched");

        let other = std::sync::Arc::new(WithdrawChain {
            issuer: [0x5e; 20],
            ..std::sync::Arc::into_inner(withdraw_chain(0xc5, None)).unwrap()
        });
        let (result, _) = withdraw_with(&other, 1, &[]).await;
        assert!(
            matches!(result, Err(WithdrawError::NotIssuer { .. })),
            "{result:?}"
        );

        let (result, _) = withdraw_with(&chain, 0, &[]).await;
        assert!(
            matches!(result, Err(WithdrawError::Invalid(_))),
            "{result:?}"
        );
        assert!(chain.withdrawn.lock().unwrap().is_empty());
    }

    #[cfg(feature = "chain-rpc")]
    #[test]
    fn plur_formats_as_bzz() {
        assert_eq!(format_plur_as_bzz(0), "0");
        assert_eq!(format_plur_as_bzz(15_000_000_000_000), "0.0015");
        assert_eq!(format_plur_as_bzz(57_600_000_000_000_000), "5.76");
        assert_eq!(format_plur_as_bzz(1), "0.0000000000000001");
    }

    #[cfg(feature = "chain-rpc")]
    const WALLET: [u8; 20] = [0x0a; 20];
    #[cfg(feature = "chain-rpc")]
    const CHEQUEBOOK: [u8; 20] = [0xcb; 20];

    /// At or above the target: nothing moves, never a withdrawal.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_leaves_a_funded_chequebook_alone() {
        for have in [
            DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR,
            100 * DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR,
        ] {
            let (result, others) = top_up_with(&[(CHEQUEBOOK, have), (WALLET, u128::MAX)]).await;
            assert_eq!(result.unwrap(), TopUp::NotNeeded);
            assert_eq!(others, 0, "no transfer");
        }
    }

    /// Short, but the wallet has no xBZZ: report the shortfall, no transfer.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_reports_an_empty_wallet() {
        let have = DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR / 4;
        let (result, others) = top_up_with(&[(CHEQUEBOOK, have), (WALLET, 0)]).await;
        assert_eq!(
            result.unwrap(),
            TopUp::WalletEmpty {
                shortfall: DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR - have
            }
        );
        assert_eq!(others, 0, "no transfer");
    }

    /// A deposit that can't be read is an error, not "empty": the caller
    /// must not treat it as a shortfall and send money.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_fails_on_an_unreadable_deposit() {
        let (result, others) = top_up_with(&[(WALLET, u128::MAX)]).await;
        assert!(result.is_err());
        assert_eq!(others, 0, "no transfer");
    }

    /// Short and the wallet can pay, but the chain says no: nothing is
    /// sent, whichever check refused.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_refuses_a_chequebook_the_chain_rejects() {
        let balances = [(CHEQUEBOOK, 0), (WALLET, u128::MAX)];
        let (result, others) = top_up_checked(&balances, Some(false), Some(WALLET)).await;
        assert_eq!(
            result.unwrap(),
            TopUp::Refused(ChequebookVerdict::NotRegistered)
        );
        assert_eq!(others, 0, "no transfer");

        let stranger = [0x5e; 20];
        let (result, others) = top_up_checked(&balances, Some(true), Some(stranger)).await;
        assert_eq!(
            result.unwrap(),
            TopUp::Refused(ChequebookVerdict::IssuerMismatch(stranger))
        );
        assert_eq!(others, 0, "no transfer");
    }

    /// A check that can't be read is an error before any transfer: the
    /// verdict's "failed read passes" rule doesn't apply to spending.
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_fails_when_the_checks_cannot_be_read() {
        let balances = [(CHEQUEBOOK, 0), (WALLET, u128::MAX)];
        for (registered, issuer) in [(None, Some(WALLET)), (Some(true), None)] {
            let (result, others) = top_up_checked(&balances, registered, issuer).await;
            assert!(result.is_err(), "{registered:?}/{issuer:?}");
            assert_eq!(others, 0, "no transfer");
        }
    }

    /// Both checks positive: the transfer is attempted (and here fails,
    /// since the script has no transaction backend).
    #[cfg(feature = "chain-rpc")]
    #[tokio::test]
    async fn top_up_transfers_after_both_checks_pass() {
        let (result, others) = top_up_with(&[(CHEQUEBOOK, 0), (WALLET, u128::MAX)]).await;
        assert!(result.is_err(), "scripted transfer failure");
        assert!(others > 0, "a transfer was attempted");
    }

    #[test]
    fn default_deposit_is_one_thousandth_of_a_bzz() {
        // 1 xBZZ = 1e16 PLUR (16 decimals, not 18).
        assert_eq!(
            DEFAULT_CHEQUEBOOK_DEPOSIT_PLUR * 1_000,
            10_000_000_000_000_000
        );
    }
}
