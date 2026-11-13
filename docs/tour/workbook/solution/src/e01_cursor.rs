//! Exercise 1: a panic-free byte cursor (borrowing, slices, lifetimes).
//! Modelled on `Reader<'a>` in myotis-consensus/src/snapshot.rs.

/// Reads fields from a byte buffer it borrows; it owns nothing.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The next `len` bytes, borrowed from the ORIGINAL buffer (lifetime `'a`),
    /// not from the reader. `None`, without moving `pos`, if fewer remain or if
    /// `pos + len` would overflow. Must never panic.
    pub fn fixed(&mut self, len: usize) -> Option<&'a [u8]> {
        //@begin
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
        //@end
    }

    /// A big-endian u32 (4 bytes).
    pub fn u32_be(&mut self) -> Option<u32> {
        //@begin
        Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))
        //@end
    }

    /// A little-endian u64 (8 bytes).
    pub fn u64_le(&mut self) -> Option<u64> {
        //@begin
        Some(u64::from_le_bytes(self.fixed(8)?.try_into().ok()?))
        //@end
    }

    /// A length-prefixed field: a big-endian u32 length, then that many bytes.
    pub fn prefixed(&mut self) -> Option<&'a [u8]> {
        //@begin
        let len = usize::try_from(self.u32_be()?).ok()?;
        self.fixed(len)
        //@end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_borrow_the_buffer_not_the_reader() {
        let buf = vec![1u8, 2, 3, 4, 5, 6];
        let mut r = Reader::new(&buf);
        let a = r.fixed(2).unwrap();
        let b = r.fixed(2).unwrap(); // `a` is still alive here: only possible with `'a`
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[3, 4]);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn short_reads_fail_without_moving() {
        let buf = [9u8, 9, 9];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32_be(), None);
        assert_eq!(r.remaining(), 3, "a failed read must not consume bytes");
        assert_eq!(r.fixed(usize::MAX), None, "overflow is None, not a panic");
    }

    #[test]
    fn numbers_and_prefixed_fields() {
        let mut buf = vec![0, 0, 0, 3, b'a', b'b', b'c'];
        buf.extend_from_slice(&7u64.to_le_bytes());
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), Some(&b"abc"[..]));
        assert_eq!(r.u64_le(), Some(7));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn hostile_length_prefix_is_refused() {
        let buf = [0xff, 0xff, 0xff, 0xff, 1, 2];
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), None);
    }
}
