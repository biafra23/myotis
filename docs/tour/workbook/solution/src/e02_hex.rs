//! Exercise 2: panic-free hex parsing with const generics (bytes and strings).
//! Modelled on `parse_hex_fixed` in myotis-engine/src/host.rs and the
//! `is_ascii()` lesson in `parse_boot_enodes` (myotis-net/src/el/reader.rs).

/// Parse `0x`-prefixed or bare hex into exactly `N` bytes. `None` for anything
/// malformed: wrong length, non-hex characters, multi-byte UTF-8. Never panics.
pub fn parse_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    //@begin
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
    //@end
}

/// Lowercase `0x`-prefixed hex, built in ONE `String` (no per-byte allocation).
pub fn to_hex(bytes: &[u8]) -> String {
    //@begin
    use std::fmt::Write;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
    //@end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let a: [u8; 4] = parse_hex_fixed("0xDEADbeef").unwrap();
        assert_eq!(a, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(to_hex(&a), "0xdeadbeef");
        assert_eq!(parse_hex_fixed::<2>("0102"), Some([1, 2]));
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(parse_hex_fixed::<2>("0x01"), None, "too short");
        assert_eq!(parse_hex_fixed::<2>("0x0g01"), None, "not hex");
        assert_eq!(parse_hex_fixed::<1>(""), None);
    }

    #[test]
    fn multibyte_utf8_does_not_panic() {
        // "éé" is FOUR bytes, so a naive length check passes and naive slicing
        // at byte 1 would panic inside a character.
        assert_eq!(parse_hex_fixed::<2>("éé"), None);
    }
}
