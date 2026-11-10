//! Exercise 8: verify a header chain with slices and iterators.
//! Modelled on `fetch_anchored_window` (myotis-net/src/el/reader.rs) and
//! `verify_header_chain` (myotis-net/src/el/verify.rs).

#[derive(Clone, Debug)]
pub struct Header {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    WrongHead,
    BrokenLink { at: u64 },
}

/// `headers` is NEWEST FIRST. Accept only if the first header's hash equals
/// `anchor` (the trusted head) and every header is the parent of the one
/// before it: `child.parent_hash == parent.hash` and
/// `child.number == parent.number + 1`. Report the first bad link by the
/// child's number. Hint: `headers.windows(2)`.
pub fn verify_chain(headers: &[Header], anchor: &[u8; 32]) -> Result<(), ChainError> {
    //@begin
    let first = headers.first().ok_or(ChainError::Empty)?;
    if &first.hash != anchor {
        return Err(ChainError::WrongHead);
    }
    for w in headers.windows(2) {
        let [child, parent] = w else { unreachable!("windows(2) yields pairs") };
        if child.parent_hash != parent.hash || parent.number.checked_add(1) != Some(child.number) {
            return Err(ChainError::BrokenLink { at: child.number });
        }
    }
    Ok(())
    //@end
}

/// Numbers of the headers whose hash starts with a zero byte, in input order,
/// as ONE iterator chain (`iter`, `filter`, `map`, `collect`).
pub fn zero_prefixed(headers: &[Header]) -> Vec<u64> {
    //@begin
    headers.iter().filter(|h| h.hash[0] == 0).map(|h| h.number).collect()
    //@end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<Header> {
        // newest first: numbers n-1 .. 0, hash = [number; 32], parent = [number-1; 32]
        (0..n)
            .rev()
            .map(|i| Header { number: i, hash: [i as u8; 32], parent_hash: [i.wrapping_sub(1) as u8; 32] })
            .collect()
    }

    #[test]
    fn good_chain_passes() {
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[4; 32]), Ok(()));
        assert_eq!(zero_prefixed(&c), vec![0]);
    }

    #[test]
    fn bad_chains_fail() {
        assert_eq!(verify_chain(&[], &[0; 32]), Err(ChainError::Empty));
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[9; 32]), Err(ChainError::WrongHead));
        let mut broken = c.clone();
        broken[2].parent_hash = [77; 32];
        assert_eq!(verify_chain(&broken, &[4; 32]), Err(ChainError::BrokenLink { at: 2 }));
    }
}
