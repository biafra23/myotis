//! EIP-1559's base fee update, as geth's `eip1559.CalcBaseFee` computes the
//! next block's base fee from its parent's (elasticity 2, denominator 8 — the
//! parameters of every chain this node serves, Gnosis included). One copy for
//! the fee estimates (`myotis-net`) and the simulated blocks (`myotis-evm`).

/// The base fee of the block after one with `parent_base_fee`, `gas_limit`
/// and `gas_used`: unchanged at the gas target (half the limit), up by at
/// least 1 wei above it, down below it, each by 1/8 of the base fee scaled by
/// the distance from the target. A limit below 2 has no target: unchanged.
pub fn next_base_fee(parent_base_fee: u128, gas_limit: u64, gas_used: u64) -> u128 {
    let gas_target = gas_limit / 2;
    if gas_target == 0 || gas_used == gas_target {
        return parent_base_fee;
    }
    let target = u128::from(gas_target);
    if gas_used > gas_target {
        let delta = (parent_base_fee.saturating_mul(u128::from(gas_used - gas_target)) / target / 8).max(1);
        parent_base_fee.saturating_add(delta)
    } else {
        let delta = parent_base_fee.saturating_mul(u128::from(gas_target - gas_used)) / target / 8;
        parent_base_fee.saturating_sub(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_parents_gas() {
        assert_eq!(next_base_fee(1_000, 60, 30), 1_000);
        assert_eq!(next_base_fee(1_000, 60, 60), 1_125);
        assert_eq!(next_base_fee(1_000, 60, 0), 875);
        // A rise is at least one wei, from zero too (geth's `max(num, 1)`).
        assert_eq!(next_base_fee(1, 60, 31), 2);
        assert_eq!(next_base_fee(0, 60, 31), 1);
        assert_eq!(next_base_fee(0, 60, 0), 0);
        assert_eq!(next_base_fee(7, 1, 1), 7);
    }
}
