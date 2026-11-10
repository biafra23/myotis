//! Exercise 3: errors as values: enums, `From`, `?` and `Display`.
//! Modelled on `OracleError` / `EvmError` in myotis-evm (oracle.rs, error.rs).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    StateUnavailable { address: [u8; 20] },
    InvalidProof { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmError {
    Oracle(OracleError),
    Reverted { data: Vec<u8> },
    OutOfGas,
}

/// Lets `?` turn an `OracleError` into an `EvmError` automatically.
impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        //@begin
        EvmError::Oracle(e)
        //@end
    }
}

/// Human-readable messages:
/// - `StateUnavailable` → "state unavailable for 0x<first 2 address bytes in hex>…"
/// - `InvalidProof` → "invalid proof: <detail>"
/// - `Reverted` → "reverted with <n> bytes of data"
/// - `OutOfGas` → "out of gas"
impl fmt::Display for EvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //@begin
        match self {
            EvmError::Oracle(OracleError::StateUnavailable { address }) => {
                write!(f, "state unavailable for 0x{:02x}{:02x}…", address[0], address[1])
            }
            EvmError::Oracle(OracleError::InvalidProof { detail }) => write!(f, "invalid proof: {detail}"),
            EvmError::Reverted { data } => write!(f, "reverted with {} bytes of data", data.len()),
            EvmError::OutOfGas => write!(f, "out of gas"),
        }
        //@end
    }
}

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError>;
}

/// Sum the balances of `addrs`, stopping at the first one that can't be read.
/// Use `?` (no `match`, no `map_err`): the `From` impl above does the work.
pub fn total_balance(src: &dyn StateSource, addrs: &[[u8; 20]]) -> Result<u64, EvmError> {
    //@begin
    let mut sum = 0u64;
    for a in addrs {
        sum += src.balance(*a)?;
    }
    Ok(sum)
    //@end
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl StateSource for Fixed {
        fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError> {
            match address[0] {
                0 => Err(OracleError::StateUnavailable { address }),
                n => Ok(u64::from(n)),
            }
        }
    }

    #[test]
    fn question_mark_converts_and_stops_early() {
        assert_eq!(total_balance(&Fixed, &[[1; 20], [2; 20]]), Ok(3));
        let err = total_balance(&Fixed, &[[1; 20], [0; 20], [5; 20]]).unwrap_err();
        assert_eq!(err, EvmError::Oracle(OracleError::StateUnavailable { address: [0; 20] }));
    }

    #[test]
    fn display_messages() {
        let e: EvmError = OracleError::StateUnavailable { address: [0xab; 20] }.into();
        assert_eq!(e.to_string(), "state unavailable for 0xabab…");
        assert_eq!(EvmError::Reverted { data: vec![0; 4] }.to_string(), "reverted with 4 bytes of data");
        assert_eq!(EvmError::OutOfGas.to_string(), "out of gas");
        assert_eq!(
            EvmError::from(OracleError::InvalidProof { detail: "bad node".into() }).to_string(),
            "invalid proof: bad node"
        );
    }
}
