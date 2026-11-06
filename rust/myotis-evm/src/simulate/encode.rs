//! The consensus encodings a simulated block's roots are built from, as geth
//! builds them: a transaction's (EIP-2718 envelope: `type ‖ rlp(fields)`, a
//! legacy one plain RLP), a receipt's and a withdrawal's.

use myotis_core::bloom::LogsBloom;
use myotis_core::rlp::{encode_bytes, encode_list_payload, encode_u64};
use revm::primitives::{Log, U256};

use super::{SimTransaction, Withdrawal};
use crate::tx::{TYPE_ACCESS_LIST, TYPE_DYNAMIC_FEE, TYPE_LEGACY};

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    encode_list_payload(&items.concat())
}

/// An RLP scalar: minimal big-endian, zero as the empty string.
fn scalar(value: U256) -> Vec<u8> {
    let be = value.to_be_bytes::<32>();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    encode_bytes(&be[skip..])
}

fn scalar_u128(value: u128) -> Vec<u8> {
    scalar(U256::from(value))
}

/// The transaction's consensus encoding, unsigned (`v`, `r`, `s` zero): its
/// keccak is the hash geth gives a simulated call.
pub(super) fn transaction(tx: &SimTransaction) -> Vec<u8> {
    let to = match &tx.to {
        Some(to) => encode_bytes(to),
        None => encode_bytes(&[]),
    };
    let zero = || encode_u64(0);
    let access_list = list(
        &tx.access_list
            .iter()
            .flatten()
            .map(|item| {
                list(&[
                    encode_bytes(&item.address),
                    list(&item.storage_keys.iter().map(|key| encode_bytes(key)).collect::<Vec<_>>()),
                ])
            })
            .collect::<Vec<_>>(),
    );
    let chain_id = encode_u64(tx.chain_id.unwrap_or(0));
    let nonce = encode_u64(tx.nonce);
    let gas = encode_u64(tx.gas);
    let value = scalar(tx.value);
    let input = encode_bytes(&tx.input);
    let fee_cap = scalar_u128(tx.max_fee_per_gas.unwrap_or(0));
    let tip = scalar_u128(tx.max_priority_fee_per_gas.unwrap_or(0));
    let fields = match tx.tx_type {
        TYPE_LEGACY => {
            return list(&[nonce, scalar_u128(tx.gas_price), gas, to, value, input, zero(), zero(), zero()]);
        }
        TYPE_ACCESS_LIST => {
            vec![chain_id, nonce, scalar_u128(tx.gas_price), gas, to, value, input, access_list, zero(), zero(), zero()]
        }
        TYPE_DYNAMIC_FEE => vec![chain_id, nonce, tip, fee_cap, gas, to, value, input, access_list, zero(), zero(), zero()],
        // EIP-7702 (the only other type a request can name).
        _ => {
            let authorizations = list(
                &tx.authorization_list
                    .iter()
                    .flatten()
                    .map(|auth| {
                        list(&[
                            scalar(auth.chain_id),
                            encode_bytes(&auth.address),
                            encode_u64(auth.nonce),
                            encode_u64(u64::from(auth.y_parity)),
                            scalar(auth.r),
                            scalar(auth.s),
                        ])
                    })
                    .collect::<Vec<_>>(),
            );
            vec![chain_id, nonce, tip, fee_cap, gas, to, value, input, access_list, authorizations, zero(), zero(), zero()]
        }
    };
    let mut out = vec![tx.tx_type];
    out.extend(list(&fields));
    out
}

/// A receipt's consensus encoding: `type ‖ rlp([status, cumulativeGasUsed,
/// bloom, logs])`, a legacy one plain RLP.
pub(super) fn receipt(tx_type: u8, status: bool, cumulative_gas_used: u64, bloom: &LogsBloom, logs: &[Log]) -> Vec<u8> {
    let logs = list(
        &logs
            .iter()
            .map(|log| {
                list(&[
                    encode_bytes(log.address.as_slice()),
                    list(&log.data.topics().iter().map(|topic| encode_bytes(topic.as_slice())).collect::<Vec<_>>()),
                    encode_bytes(&log.data.data),
                ])
            })
            .collect::<Vec<_>>(),
    );
    let status = if status { encode_bytes(&[1]) } else { encode_bytes(&[]) };
    let body = list(&[status, encode_u64(cumulative_gas_used), encode_bytes(bloom), logs]);
    if tx_type == TYPE_LEGACY {
        return body;
    }
    let mut out = vec![tx_type];
    out.extend(body);
    out
}

/// A withdrawal's consensus encoding: `rlp([index, validatorIndex, address,
/// amount])`.
pub(super) fn withdrawal(withdrawal: &Withdrawal) -> Vec<u8> {
    list(&[
        encode_u64(withdrawal.index),
        encode_u64(withdrawal.validator_index),
        encode_bytes(&withdrawal.address),
        encode_u64(withdrawal.amount),
    ])
}
