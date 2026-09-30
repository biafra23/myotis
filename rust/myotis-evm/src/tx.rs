//! [`TxRequest`]: the JSON-RPC transaction object of an `eth_estimateGas`
//! (geth's `TransactionArgs`) in the form the executor applies it (#509).
//!
//! Every field here changes the answer, so each one is either APPLIED to the
//! run or the request is REFUSED ([`TxRequest::validate`]) — never accepted and
//! dropped (CLAUDE.md §Trust). The dropped-field failure this exists for: a
//! type-4 estimate whose `authorizationList` was ignored ran the call against
//! an EOA with no code, returned ~59k for a transaction that needs several
//! hundred thousand, and the wallet's transaction ran out of gas on chain.
//!
//! Semantics follow geth's `eth_estimateGas` wherever it defines them, so a
//! wallet sees the same answer from this node as from a public one:
//!
//! - `authorizationList` (EIP-7702): each tuple is applied exactly as a mined
//!   transaction applies it — revm recovers the authority, checks chain id,
//!   nonce and code, installs `0xef0100 || address`, and SKIPS an invalid tuple
//!   without failing the transaction (the spec's rule, not a shortcut). The
//!   sender's nonce is bumped before the list is processed, so a self-sponsored
//!   authorization must carry the transaction nonce + 1.
//! - `accessList` (EIP-2930): charged in the intrinsic gas and pre-warmed.
//! - `gas`: the ceiling of the estimate (geth's `hi`): the answer never exceeds
//!   it, and a transaction that cannot succeed within it is "gas required
//!   exceeds allowance". Below 21000 it is treated as absent, as geth does.
//! - fees: the effective gas price is what GASPRICE reads, and a non-zero fee
//!   cap bounds the ceiling by what the sender can pay (`(balance − value) /
//!   feeCap`, geth's affordability cap).
//! - `nonce`: the sender's nonce when the transaction executes. Only 7702
//!   (self-sponsored authorizations) and contract creation (the new address)
//!   can observe it; both are simulated at the nonce the caller named.
//! - `type`: must agree with the fields; an explicit type is honoured, never
//!   rewritten (revm's `build_fill` would quietly add a dummy authorization to
//!   an empty type-4 list — so this module refuses first and the executor uses
//!   the strict `build`).
//!
//! Blob transactions (type 3, `blobVersionedHashes`) are refused by the host
//! parser: nothing here models blob gas, and BLOBHASH would read nothing.

use revm::primitives::{Bytes, U256};

/// The zero address — the sender of a request that names no `from` (geth's
/// default for simulated calls).
pub const ANONYMOUS_SENDER: [u8; 20] = [0u8; 20];

/// Legacy (type 0) transaction.
pub const TYPE_LEGACY: u8 = 0;
/// EIP-2930 access-list transaction.
pub const TYPE_ACCESS_LIST: u8 = 1;
/// EIP-1559 dynamic-fee transaction.
pub const TYPE_DYNAMIC_FEE: u8 = 2;
/// EIP-4844 blob transaction — refused (see the module docs).
pub const TYPE_BLOB: u8 = 3;
/// EIP-7702 set-code transaction.
pub const TYPE_SET_CODE: u8 = 4;

/// One EIP-2930 access-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// One EIP-7702 authorization tuple, as signed by its authority. Nothing here
/// is checked at parse time beyond its shape: an invalid signature, a foreign
/// chain id or a stale nonce makes the TUPLE invalid, which the spec resolves
/// by skipping it during execution — the transaction itself stays valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub chain_id: U256,
    pub address: [u8; 20],
    pub nonce: u64,
    pub y_parity: u8,
    pub r: U256,
    pub s: U256,
}

/// The fee fields, normalized. geth refuses `gasPrice` together with either
/// EIP-1559 field, so a request carries at most one of the two models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fees {
    /// No fee field: the run is priced at zero (GASPRICE reads 0) and the
    /// sender's balance does not bound the estimate.
    #[default]
    None,
    /// `gasPrice`.
    Legacy { gas_price: u128 },
    /// `maxFeePerGas` / `maxPriorityFeePerGas` (either may be absent = 0).
    DynamicFee { max_fee_per_gas: u128, max_priority_fee_per_gas: u128 },
}

impl Fees {
    /// The fee cap geth's affordability rule divides by: `maxFeePerGas` for a
    /// dynamic-fee request, else `gasPrice`, else zero (no cap).
    pub fn fee_cap(&self) -> u128 {
        match *self {
            Fees::None => 0,
            Fees::Legacy { gas_price } => gas_price,
            Fees::DynamicFee { max_fee_per_gas, .. } => max_fee_per_gas,
        }
    }
}

/// A transaction to simulate: every field of the JSON-RPC transaction object
/// this node applies. Built by the host from the request; [`Self::validate`]
/// refuses the contradictory ones before any state is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRequest {
    /// The sender ([`ANONYMOUS_SENDER`] when the request names none).
    pub from: [u8; 20],
    /// `None` is CONTRACT CREATION: `data` is init code.
    pub to: Option<[u8; 20]>,
    pub data: Bytes,
    pub value: U256,
    /// The caller's gas limit, if any (see the module docs for the estimate's
    /// reading of it).
    pub gas: Option<u64>,
    pub fees: Fees,
    /// The transaction nonce, if named: the sender's nonce as the run sees it.
    pub nonce: Option<u64>,
    /// The request's `chainId`, if named — must be the node's chain.
    pub chain_id: Option<U256>,
    /// The explicit `type`, if named. Absent, it is derived from the fields
    /// exactly as revm and geth derive it ([`Self::tx_type`]).
    pub tx_type: Option<u8>,
    /// `None` = no `accessList` field; an empty list is accepted (it changes
    /// nothing).
    pub access_list: Option<Vec<AccessListItem>>,
    /// `None` = no `authorizationList` field. When present it must be
    /// non-empty and the request must be a call (see [`Self::validate`]).
    pub authorization_list: Option<Vec<Authorization>>,
}

impl TxRequest {
    /// A plain call or creation — the `from`/`to`/`data`/`value` subset every
    /// pre-#509 entry point carries. Every other field absent.
    pub fn call(from: [u8; 20], to: Option<[u8; 20]>, data: Bytes, value: U256) -> TxRequest {
        TxRequest {
            from,
            to,
            data,
            value,
            gas: None,
            fees: Fees::None,
            nonce: None,
            chain_id: None,
            tx_type: None,
            access_list: None,
            authorization_list: None,
        }
    }

    /// Whether the request carries an access list or an authorization list —
    /// fields that change a plain transfer's price, so the executor's 21000
    /// short-circuit must not answer for it (geth runs the transfer instead of
    /// assuming, for the same reason).
    pub fn has_lists(&self) -> bool {
        self.access_list.as_ref().is_some_and(|l| !l.is_empty()) || self.authorization_list.is_some()
    }

    /// The transaction type the run uses: the explicit `type`, else derived
    /// from the fields in revm's (and geth's) order — an authorization list
    /// makes a set-code transaction, EIP-1559 fees a dynamic-fee one, a
    /// non-empty access list an access-list one, anything else legacy.
    pub fn tx_type(&self) -> u8 {
        if let Some(t) = self.tx_type {
            return t;
        }
        if self.authorization_list.is_some() {
            return TYPE_SET_CODE;
        }
        if matches!(self.fees, Fees::DynamicFee { .. }) {
            return TYPE_DYNAMIC_FEE;
        }
        if self.access_list.as_ref().is_some_and(|l| !l.is_empty()) {
            return TYPE_ACCESS_LIST;
        }
        TYPE_LEGACY
    }

    /// Refuse a request no transaction could be: `Err` carries the reason, and
    /// the executor surfaces it as a permanent refusal. Order matters only for
    /// which reason a doubly-broken request reports.
    pub fn validate(&self) -> Result<(), String> {
        let ty = self.tx_type();
        match ty {
            TYPE_LEGACY | TYPE_ACCESS_LIST | TYPE_DYNAMIC_FEE | TYPE_SET_CODE => {}
            TYPE_BLOB => {
                return Err("blob transactions (type 0x3) are not supported by this node".into())
            }
            other => return Err(format!("unsupported transaction type 0x{other:x}")),
        }
        if let Fees::DynamicFee { max_fee_per_gas, max_priority_fee_per_gas } = self.fees {
            if ty < TYPE_DYNAMIC_FEE {
                return Err(format!(
                    "maxFeePerGas/maxPriorityFeePerGas require transaction type 0x2 or later \
                     (the request names type 0x{ty:x})"
                ));
            }
            if max_priority_fee_per_gas > max_fee_per_gas {
                return Err(format!(
                    "maxPriorityFeePerGas ({max_priority_fee_per_gas}) is greater than \
                     maxFeePerGas ({max_fee_per_gas})"
                ));
            }
        }
        if ty == TYPE_LEGACY && self.access_list.as_ref().is_some_and(|l| !l.is_empty()) {
            return Err("accessList requires transaction type 0x1 or later \
                        (the request names type 0x0)"
                .into());
        }
        match (&self.authorization_list, ty) {
            (None, TYPE_SET_CODE) => {
                return Err("transaction type 0x4 requires an authorizationList".into())
            }
            (Some(_), t) if t != TYPE_SET_CODE => {
                return Err(format!(
                    "authorizationList requires transaction type 0x4 (the request names \
                     type 0x{t:x})"
                ))
            }
            (Some(list), _) if list.is_empty() => {
                return Err("authorizationList must not be empty (EIP-7702)".into())
            }
            _ => {}
        }
        if ty == TYPE_SET_CODE && self.to.is_none() {
            return Err("an EIP-7702 transaction cannot create a contract: \
                        authorizationList needs a 'to'"
                .into());
        }
        if self.nonce == Some(u64::MAX) {
            // EIP-2681: the nonce must stay incrementable.
            return Err("nonce 0xffffffffffffffff is not a valid transaction nonce (EIP-2681)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TO: [u8; 20] = [0x11; 20];

    fn auth() -> Authorization {
        Authorization { chain_id: U256::from(1), address: [0x22; 20], nonce: 0, y_parity: 0, r: U256::from(1), s: U256::from(1) }
    }

    fn call() -> TxRequest {
        TxRequest::call(ANONYMOUS_SENDER, Some(TO), Bytes::new(), U256::ZERO)
    }

    #[test]
    fn a_plain_call_is_legacy_and_valid() {
        assert_eq!(call().tx_type(), TYPE_LEGACY);
        assert_eq!(call().validate(), Ok(()));
        assert!(!call().has_lists());
    }

    #[test]
    fn the_type_is_derived_in_revms_order() {
        let mut t = call();
        t.access_list = Some(vec![AccessListItem { address: TO, storage_keys: vec![] }]);
        assert_eq!(t.tx_type(), TYPE_ACCESS_LIST);
        t.fees = Fees::DynamicFee { max_fee_per_gas: 2, max_priority_fee_per_gas: 1 };
        assert_eq!(t.tx_type(), TYPE_DYNAMIC_FEE);
        t.authorization_list = Some(vec![auth()]);
        assert_eq!(t.tx_type(), TYPE_SET_CODE);
        assert_eq!(t.validate(), Ok(()));
        // An EMPTY access list derives nothing: it changes nothing.
        let mut e = call();
        e.access_list = Some(vec![]);
        assert_eq!(e.tx_type(), TYPE_LEGACY);
        assert!(!e.has_lists());
    }

    #[test]
    fn an_explicit_type_is_honoured_not_rewritten() {
        let mut t = call();
        t.tx_type = Some(TYPE_DYNAMIC_FEE);
        assert_eq!(t.tx_type(), TYPE_DYNAMIC_FEE);
        assert_eq!(t.validate(), Ok(()), "type 2 with no fee field is priced at zero, as geth does");
    }

    /// The #509 shape's contradictions: revm's build_fill would "repair" each
    /// of these into a different transaction than the caller asked about.
    #[test]
    fn set_code_contradictions_are_refused() {
        let mut no_list = call();
        no_list.tx_type = Some(TYPE_SET_CODE);
        assert!(no_list.validate().unwrap_err().contains("requires an authorizationList"));

        let mut empty = call();
        empty.authorization_list = Some(vec![]);
        assert!(empty.validate().unwrap_err().contains("must not be empty"));

        let mut create = call();
        create.to = None;
        create.authorization_list = Some(vec![auth()]);
        assert!(create.validate().unwrap_err().contains("cannot create a contract"));

        let mut wrong_type = call();
        wrong_type.tx_type = Some(TYPE_DYNAMIC_FEE);
        wrong_type.authorization_list = Some(vec![auth()]);
        assert!(wrong_type.validate().unwrap_err().contains("requires transaction type 0x4"));
    }

    #[test]
    fn fee_and_list_contradictions_are_refused() {
        let mut tip_above_cap = call();
        tip_above_cap.fees = Fees::DynamicFee { max_fee_per_gas: 1, max_priority_fee_per_gas: 2 };
        assert!(tip_above_cap.validate().unwrap_err().contains("greater than maxFeePerGas"));

        let mut legacy_with_1559 = call();
        legacy_with_1559.tx_type = Some(TYPE_LEGACY);
        legacy_with_1559.fees = Fees::DynamicFee { max_fee_per_gas: 2, max_priority_fee_per_gas: 1 };
        assert!(legacy_with_1559.validate().unwrap_err().contains("require transaction type 0x2"));

        let mut legacy_with_list = call();
        legacy_with_list.tx_type = Some(TYPE_LEGACY);
        legacy_with_list.access_list = Some(vec![AccessListItem { address: TO, storage_keys: vec![] }]);
        assert!(legacy_with_list.validate().unwrap_err().contains("type 0x1 or later"));

        // gasPrice on a dynamic-fee type is geth's legacy pricing, not a contradiction.
        let mut legacy_price_type2 = call();
        legacy_price_type2.tx_type = Some(TYPE_DYNAMIC_FEE);
        legacy_price_type2.fees = Fees::Legacy { gas_price: 5 };
        assert_eq!(legacy_price_type2.validate(), Ok(()));
    }

    #[test]
    fn unknown_and_blob_types_and_a_maximal_nonce_are_refused() {
        let mut blob = call();
        blob.tx_type = Some(TYPE_BLOB);
        assert!(blob.validate().unwrap_err().contains("blob transactions"));
        let mut unknown = call();
        unknown.tx_type = Some(0x7e);
        assert!(unknown.validate().unwrap_err().contains("unsupported transaction type 0x7e"));
        let mut nonce = call();
        nonce.nonce = Some(u64::MAX);
        assert!(nonce.validate().unwrap_err().contains("EIP-2681"));
    }

    #[test]
    fn the_fee_cap_is_max_fee_else_gas_price() {
        assert_eq!(Fees::None.fee_cap(), 0);
        assert_eq!(Fees::Legacy { gas_price: 9 }.fee_cap(), 9);
        assert_eq!(Fees::DynamicFee { max_fee_per_gas: 7, max_priority_fee_per_gas: 1 }.fee_cap(), 7);
    }
}
