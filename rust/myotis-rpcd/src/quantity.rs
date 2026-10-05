//! JSON-RPC QUANTITY / DATA encoding without a bignum dependency — a port of
//! the Kotlin router's `RpcQuantities` and its hex helpers. Wei values are
//! unsigned and capped at 256 bits, so schoolbook base conversion over digit
//! arrays is all that is needed; the engine hands balances and fees across as
//! decimal strings (the FFI-neutral form), and the wire wants minimal hex.

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// QUANTITY-encode a u64: minimal hex, `0x0` for zero.
pub fn hex_quantity(v: u64) -> String {
    format!("0x{v:x}")
}

/// QUANTITY-encode an unsigned decimal string. `None` for anything that is not
/// one — engine shape drift the caller fails closed on, never silent data.
pub fn hex_quantity_decimal(decimal: &str) -> Option<String> {
    if decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("0x{}", decimal_to_hex(decimal)))
}

/// Parse a JSON-RPC QUANTITY (`0x…` hex or decimal) as a wei value: unsigned,
/// at most 256 bits. Returns the NORMALIZED decimal (what the engine's value
/// parameters take), or `None` for malformed / negative / out-of-range input.
/// The length cap runs before any conversion, so a huge string cannot amplify
/// parsing cost.
pub fn parse_wei_quantity(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 80 {
        return None;
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // BigInteger parity (the JVM original): an explicit '+' after the prefix.
        let h = h.strip_prefix('+').unwrap_or(h);
        let h = if h.is_empty() { "0" } else { h };
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let h = h.to_ascii_lowercase();
        let minimal = h.trim_start_matches('0');
        let minimal = if minimal.is_empty() { "0" } else { minimal };
        if minimal.len() > 64 {
            return None;
        }
        return Some(hex_to_decimal(minimal));
    }
    let d = s.strip_prefix('+').unwrap_or(s);
    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let minimal = d.trim_start_matches('0');
    let minimal = if minimal.is_empty() { "0" } else { minimal };
    if decimal_to_hex(minimal).len() > 64 {
        return None;
    }
    Some(minimal.to_string())
}

/// Unsigned decimal digits → minimal lowercase hex (no `0x`).
pub fn decimal_to_hex(decimal: &str) -> String {
    let mut digits: Vec<u32> = decimal.bytes().map(|b| u32::from(b - b'0')).collect();
    let mut out = Vec::new();
    while !digits.is_empty() {
        // One schoolbook division of the decimal digit array by 16.
        let mut remainder = 0u32;
        let mut quotient = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = remainder * 10 + d;
            quotient.push(cur / 16);
            remainder = cur % 16;
        }
        out.push(HEX_DIGITS[remainder as usize]);
        let start = quotient
            .iter()
            .position(|&q| q != 0)
            .unwrap_or(quotient.len());
        digits = quotient.split_off(start);
    }
    if out.is_empty() {
        return "0".into();
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// Minimal hex digits (no `0x`) → unsigned decimal digits. The caller has
/// already checked every byte is a hex digit.
pub fn hex_to_decimal(hex: &str) -> String {
    let mut digits = vec![0u32]; // little-endian decimal digits
    for c in hex.chars() {
        let mut carry = c.to_digit(16).unwrap_or(0);
        for d in digits.iter_mut() {
            let cur = *d * 16 + carry;
            *d = cur % 10;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    let s: String = digits
        .iter()
        .rev()
        .map(|d| char::from(b'0' + *d as u8))
        .collect();
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

/// DATA-encode bytes: `0x` + every byte (leading zeros kept).
pub fn hex_data(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for &v in b {
        s.push(char::from(HEX_DIGITS[usize::from(v >> 4)]));
        s.push(char::from(HEX_DIGITS[usize::from(v & 0x0f)]));
    }
    s
}

/// Decode hex with an optional `0x`; `None` on odd length or a non-hex digit.
/// Strict on purpose: these carry verified data (calldata, code, storage), and
/// padding an odd-length value would byte-shift it.
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !h.len().is_multiple_of(2) {
        return None;
    }
    let b = h.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// The engine's DATA fields (`codeHex`, `resultHex`, `dataHex`, `valueHex`):
/// absent/null → empty, malformed → `None` (fail closed).
pub fn engine_bytes(v: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    match v {
        None | Some(serde_json::Value::Null) => Some(Vec::new()),
        Some(serde_json::Value::String(s)) => parse_hex(s),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_hex_round_trip() {
        assert_eq!(decimal_to_hex("0"), "0");
        assert_eq!(decimal_to_hex("255"), "ff");
        assert_eq!(decimal_to_hex("1000000000000000000"), "de0b6b3a7640000");
        assert_eq!(hex_to_decimal("de0b6b3a7640000"), "1000000000000000000");
        // 2^256 - 1 survives both ways.
        let max = "f".repeat(64);
        let dec = hex_to_decimal(&max);
        assert_eq!(
            dec,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(decimal_to_hex(&dec), max);
    }

    #[test]
    fn wei_quantity_parsing() {
        assert_eq!(parse_wei_quantity("0x0").as_deref(), Some("0"));
        assert_eq!(parse_wei_quantity("0x").as_deref(), Some("0"));
        assert_eq!(parse_wei_quantity("0x00ff").as_deref(), Some("255"));
        assert_eq!(parse_wei_quantity("1000").as_deref(), Some("1000"));
        assert_eq!(parse_wei_quantity("-1"), None);
        assert_eq!(parse_wei_quantity("0xzz"), None);
        assert_eq!(parse_wei_quantity(&format!("0x1{}", "0".repeat(64))), None); // 2^256
        assert_eq!(parse_wei_quantity(""), None);
    }

    #[test]
    fn quantity_and_data_encoding() {
        assert_eq!(hex_quantity(0), "0x0");
        assert_eq!(hex_quantity(100), "0x64");
        assert_eq!(
            hex_quantity_decimal("12345678900").as_deref(),
            Some("0x2dfdc1c34")
        );
        assert_eq!(hex_quantity_decimal("12a"), None);
        assert_eq!(hex_data(&[0, 1, 0xab]), "0x0001ab");
        assert_eq!(hex_data(&[]), "0x");
        assert_eq!(parse_hex("0x0001ab"), Some(vec![0, 1, 0xab]));
        assert_eq!(parse_hex("0x1"), None);
        assert_eq!(parse_hex("0xgg"), None);
    }
}
