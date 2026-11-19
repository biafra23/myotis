//! Checks of what Swarm delivered: a content-addressed chunk against its address, a SOC
//! against its address and its owner's signature, a file against its root reference
//! (Bee's chunker, unencrypted, without erasure coding).

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use myotis_core::keccak::{keccak256, keccak256_concat};

use crate::{ensure, fail, hex, Result};

/// Maximum payload of one chunk.
pub const CHUNK_SIZE: usize = 4096;
const SEGMENT: usize = 32;
const BRANCHES: usize = CHUNK_SIZE / 32;
const ID_LEN: usize = 32;
const SIG_LEN: usize = 65;
const SPAN_LEN: usize = 8;

/// BMT root of a payload of at most [`CHUNK_SIZE`] bytes (every caller in this crate checks
/// the length first).
pub(crate) fn bmt_root(payload: &[u8]) -> [u8; 32] {
    assert!(
        payload.len() <= CHUNK_SIZE,
        "chunk payload over {CHUNK_SIZE}"
    );
    let mut level = vec![0u8; CHUNK_SIZE];
    level[..payload.len()].copy_from_slice(payload);
    while level.len() > SEGMENT {
        level = level.chunks(2 * SEGMENT).flat_map(keccak256).collect();
    }
    level.try_into().expect("32 bytes")
}

/// Address of a content-addressed chunk with the given span and payload.
pub(crate) fn cac_address(span: u64, payload: &[u8]) -> [u8; 32] {
    keccak256_concat(&span.to_le_bytes(), &bmt_root(payload))
}

/// Address of the SOC with `identifier` owned by `owner`.
pub fn soc_address(identifier: &[u8; 32], owner: &[u8; 20]) -> [u8; 32] {
    keccak256_concat(identifier, owner)
}

/// The payload of a content-addressed chunk in wire form (`span ‖ payload`), checked against
/// `address`. The address does not commit to the payload's length: the BMT pads it with
/// zeros, so trailing zero bytes can be added or removed (up to 4096) without changing it. A
/// caller binds the length itself: [`FileChunk::decode`] to the span, [`verify_soc`] too.
pub(crate) fn verify_cac(wire: &[u8], address: &[u8; 32]) -> Result<Vec<u8>> {
    ensure!(
        wire.len() >= SPAN_LEN && wire.len() <= SPAN_LEN + CHUNK_SIZE,
        "chunk of {} bytes",
        wire.len()
    );
    let span = u64::from_le_bytes(wire[..SPAN_LEN].try_into().expect("8"));
    let payload = &wire[SPAN_LEN..];
    let got = cac_address(span, payload);
    ensure!(
        got == *address,
        "chunk hashes to {}, requested {}",
        hex(&got),
        hex(address)
    );
    Ok(payload.to_vec())
}

/// The payload of a SOC in wire form (`identifier ‖ signature ‖ span ‖ payload`), checked:
/// the signer is `owner`, and the SOC's address `keccak256(identifier ‖ owner)` is `address`,
/// so a peer cannot answer one request with another validly signed record. The payload is
/// one chunk (span equal to its length).
pub fn verify_soc(wire: &[u8], address: &[u8; 32], owner: &[u8; 20]) -> Result<Vec<u8>> {
    ensure!(
        wire.len() >= ID_LEN + SIG_LEN + SPAN_LEN,
        "chunk too short for a SOC ({} bytes)",
        wire.len()
    );
    let identifier: [u8; 32] = wire[..ID_LEN].try_into().expect("32");
    let sig: [u8; 65] = wire[ID_LEN..ID_LEN + SIG_LEN].try_into().expect("65");
    let span_at = ID_LEN + SIG_LEN;
    let span = u64::from_le_bytes(wire[span_at..span_at + SPAN_LEN].try_into().expect("8"));
    let payload = &wire[span_at + SPAN_LEN..];
    ensure!(
        payload.len() <= CHUNK_SIZE && span == payload.len() as u64,
        "SOC wraps a multi-chunk or malformed payload (span {span}, {} bytes)",
        payload.len()
    );
    ensure!(
        soc_address(&identifier, owner) == *address,
        "SOC with identifier {} of owner {} is not the one requested ({})",
        hex(&identifier),
        hex(owner),
        hex(address)
    );
    // EIP-191 personal message over keccak256(identifier ‖ CAC address of the payload).
    let digest = keccak256_concat(&identifier, &cac_address(span, payload));
    let msg = keccak256_concat(b"\x19Ethereum Signed Message:\n32", &digest);
    let signer = recover_signer(&msg, &sig)?;
    ensure!(
        signer == *owner,
        "SOC signed by {}, expected owner {}",
        hex(&signer),
        hex(owner)
    );
    Ok(payload.to_vec())
}

/// The address that signed `hash` with `sig` (`r ‖ s ‖ v`), as the reference reader and Bee
/// accept it: `v` as 0/1 or 27/28, and a high `s` normalized (which flips the recovery id).
fn recover_signer(hash: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 20]> {
    let v = match sig[64] {
        v @ 0..=1 => v,
        v @ 27..=28 => v - 27,
        v => return Err(fail!("SOC signature with v = {v}")),
    };
    let mut s = Signature::from_slice(&sig[..64]).map_err(|_| fail!("malformed SOC signature"))?;
    let mut recid = v;
    if let Some(low) = s.normalize_s() {
        s = low;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).ok_or_else(|| fail!("bad recovery id"))?;
    let key = VerifyingKey::recover_from_prehash(hash, &s, recid)
        .map_err(|_| fail!("bad SOC signature: no key recovers"))?;
    let point = key.to_encoded_point(false);
    let public = &point.as_bytes()[1..];
    Ok(keccak256(public)[12..].try_into().expect("20"))
}

/// A chunk of a file's tree, checked against the reference it was fetched under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChunk {
    /// A leaf: up to 4096 bytes of the file.
    Leaf(Vec<u8>),
    /// An intermediate chunk: the bytes of the file below it, and its children's references,
    /// in order.
    Inner { span: u64, children: Vec<[u8; 32]> },
}

/// The largest file a reader walks: 1 TiB, far above any spill file (a top-level slice's
/// busiest address takes a few GB), and low enough that the tree arithmetic cannot overflow.
/// A reader that reads a file whole bounds it by [`MAX_FILE`](crate::records::MAX_FILE) at its
/// root ([`FileChunk::span`]).
pub const MAX_SPAN: u64 = 1 << 40;

/// The bytes each child of an intermediate chunk of `span` bytes covers at most: the largest
/// power of 128 leaves below the span. `span` is at most [`MAX_SPAN`], so the product cannot
/// overflow.
fn child_cap(span: u64) -> u64 {
    let mut cap = CHUNK_SIZE as u64;
    while cap * (BRANCHES as u64) < span {
        cap *= BRANCHES as u64;
    }
    cap
}

impl FileChunk {
    /// Decodes a chunk of a file tree (wire form `span ‖ payload`), fetched under
    /// `reference`: its content address must be `reference`, and its span `expected_span`
    /// (for the root, the file's size if the caller knows it; for a child, what
    /// [`FileChunk::child_spans`] of its parent says), so a tree can be neither larger nor
    /// deeper than its root states. A chunk whose span exceeds its payload is an intermediate
    /// one, whose payload is a whole number of references and has no more than the span
    /// needs. A span above [`MAX_SPAN`] is refused before any child is fetched; a caller that
    /// reads the file whole checks the root's [`FileChunk::span`] against
    /// [`MAX_FILE`](crate::records::MAX_FILE), and reads a larger one page by page
    /// ([`FileChunk::child_for`], `records::SpillPageCheck`).
    pub fn decode(wire: &[u8], reference: &[u8; 32], expected_span: Option<u64>) -> Result<Self> {
        let payload = verify_cac(wire, reference)?;
        let span = u64::from_le_bytes(wire[..SPAN_LEN].try_into().expect("8"));
        ensure!(
            span <= MAX_SPAN,
            "file chunk of span {span}, above the {MAX_SPAN} bytes a reader walks"
        );
        if let Some(e) = expected_span {
            ensure!(span == e, "file chunk of span {span}, its parent says {e}");
        }
        if span <= CHUNK_SIZE as u64 {
            ensure!(
                payload.len() as u64 == span,
                "leaf of {} bytes states span {span}",
                payload.len()
            );
            return Ok(Self::Leaf(payload));
        }
        ensure!(
            !payload.is_empty() && payload.len().is_multiple_of(32),
            "intermediate chunk of {} bytes",
            payload.len()
        );
        let children: Vec<[u8; 32]> = payload
            .chunks(32)
            .map(|c| c.try_into().expect("32"))
            .collect();
        // The span fixes the number of children.
        let cap = child_cap(span);
        ensure!(
            children.len() as u64 == span.div_ceil(cap),
            "intermediate chunk of span {span} with {} children",
            children.len()
        );
        Ok(Self::Inner { span, children })
    }

    /// The bytes of the file below this chunk.
    pub fn span(&self) -> u64 {
        match self {
            Self::Leaf(p) => p.len() as u64,
            Self::Inner { span, .. } => *span,
        }
    }

    /// Decodes a file's root chunk for a reader that reads the file whole: a span above
    /// [`MAX_FILE`](crate::records::MAX_FILE) is refused before any child is fetched.
    pub fn decode_whole_root(wire: &[u8], reference: &[u8; 32]) -> Result<Self> {
        let root = Self::decode(wire, reference, None)?;
        ensure!(
            root.span() <= crate::records::MAX_FILE as u64,
            "file of {} bytes, above the {} a client reads whole",
            root.span(),
            crate::records::MAX_FILE
        );
        Ok(root)
    }

    /// Child `k` of an intermediate chunk: its reference and the span it must have, to pass
    /// to [`FileChunk::decode`] when it is fetched (that binds the tree to its root).
    pub fn child(&self, k: usize) -> Option<([u8; 32], u64)> {
        let Self::Inner { span, children } = self else {
            return None;
        };
        let cap = child_cap(*span);
        let n = children.len();
        let s = if k + 1 < n {
            cap
        } else {
            span - cap * (n as u64 - 1)
        };
        children.get(k).map(|r| (*r, s))
    }

    /// For leaf `leaf` of the part of the file below this intermediate chunk (leaves are
    /// 4096-byte pages, counted from 0): the child it lies under ([`FileChunk::child`]), and
    /// its index below that child. `None` for a leaf chunk, or a leaf beyond the span.
    pub fn child_for(&self, leaf: u64) -> Option<(usize, u64)> {
        let Self::Inner { span, children } = self else {
            return None;
        };
        if leaf >= span.div_ceil(CHUNK_SIZE as u64) {
            return None;
        }
        let per_child = child_cap(*span) / CHUNK_SIZE as u64;
        let k = leaf / per_child;
        ((k as usize) < children.len()).then_some((k as usize, leaf - k * per_child))
    }

    /// The span of each child of an intermediate chunk, in order: every child but the last
    /// covers exactly the cap, the last one the rest. Empty for a leaf.
    pub fn child_spans(&self) -> Vec<u64> {
        match self {
            Self::Leaf(_) => Vec::new(),
            Self::Inner { span, children } => {
                let cap = child_cap(*span);
                let n = children.len() as u64;
                (0..n)
                    .map(|i| if i + 1 < n { cap } else { span - cap * (n - 1) })
                    .collect()
            }
        }
    }
}

/// Root reference of `data` as Bee computes it for `POST /bytes` (no encryption, no
/// erasure coding): 4096-byte leaves, 128 references per intermediate chunk, a single
/// reference at the end of a level carried up unwrapped.
pub fn file_reference(data: &[u8]) -> [u8; 32] {
    if data.len() <= CHUNK_SIZE {
        return cac_address(data.len() as u64, data);
    }
    let mut levels: Vec<Vec<([u8; 32], u64)>> = vec![Vec::new()];
    for leaf in data.chunks(CHUNK_SIZE) {
        push(
            &mut levels,
            0,
            (cac_address(leaf.len() as u64, leaf), leaf.len() as u64),
        );
    }
    let mut l = 0;
    loop {
        let top = levels.iter().skip(l + 1).all(Vec::is_empty);
        match levels[l].len() {
            0 => {}
            1 if top => return levels[l][0].0,
            1 => {
                let carried = levels[l].pop().expect("one");
                levels[l + 1].push(carried);
            }
            _ => {
                let wrapped = wrap(std::mem::take(&mut levels[l]));
                if levels.len() == l + 1 {
                    levels.push(Vec::new());
                }
                levels[l + 1].push(wrapped);
            }
        }
        l += 1;
        if levels.len() == l {
            levels.push(Vec::new());
        }
    }
}

fn push(levels: &mut Vec<Vec<([u8; 32], u64)>>, l: usize, r: ([u8; 32], u64)) {
    if levels.len() == l {
        levels.push(Vec::new());
    }
    levels[l].push(r);
    if levels[l].len() == BRANCHES {
        let wrapped = wrap(std::mem::take(&mut levels[l]));
        push(levels, l + 1, wrapped);
    }
}

fn wrap(refs: Vec<([u8; 32], u64)>) -> ([u8; 32], u64) {
    let span: u64 = refs.iter().map(|(_, s)| s).sum();
    let payload: Vec<u8> = refs.iter().flat_map(|(r, _)| *r).collect();
    (cac_address(span, &payload), span)
}

/// `data` checked against its file reference.
pub fn verify_file(data: &[u8], reference: &[u8; 32]) -> Result<()> {
    let got = file_reference(data);
    ensure!(
        got == *reference,
        "file hashes to {}, its reference is {}",
        hex(&got),
        hex(reference)
    );
    Ok(())
}

/// Every chunk of the file tree of `data`, under its reference, in wire form: what a Swarm
/// node stores for `POST /bytes` of `data`. For tests, and for walking a file as a reader does.
pub fn file_tree(data: &[u8]) -> Vec<([u8; 32], Vec<u8>)> {
    fn wire(span: u64, payload: &[u8]) -> Vec<u8> {
        let mut w = span.to_le_bytes().to_vec();
        w.extend_from_slice(payload);
        w
    }
    let mut out = Vec::new();
    if data.len() <= CHUNK_SIZE {
        out.push((
            cac_address(data.len() as u64, data),
            wire(data.len() as u64, data),
        ));
        return out;
    }
    let mut level: Vec<([u8; 32], u64)> = data
        .chunks(CHUNK_SIZE)
        .map(|leaf| {
            let r = cac_address(leaf.len() as u64, leaf);
            out.push((r, wire(leaf.len() as u64, leaf)));
            (r, leaf.len() as u64)
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        for group in level.chunks(BRANCHES) {
            if group.len() == 1 {
                // Carried up unwrapped, as Bee's chunker does.
                next.push(group[0]);
                continue;
            }
            let span: u64 = group.iter().map(|(_, s)| s).sum();
            let payload: Vec<u8> = group.iter().flat_map(|(r, _)| *r).collect();
            let r = cac_address(span, &payload);
            out.push((r, wire(span, &payload)));
            next.push((r, span));
        }
        level = next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::tests_support::unhex32;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// References Bee 2.8.3 returned for `POST /bytes` (`Swarm-Redundancy-Level: 0`), from
    /// eth2swarm's `src/swarm/file.rs` (bee-factory, 2026-11-18): the level boundaries and
    /// the carried single reference.
    const BEE: &[(usize, &str)] = &[
        (
            1,
            "fe60ba40b87599ddfb9e8947c1c872a4a1a5b56f7d1b80f0a646005b38db52a5",
        ),
        (
            4096,
            "6400c281c45741b07de93a8d45c7f1505a6c2891b5eb89064c39718e62cd4d04",
        ),
        (
            4097,
            "09354b8aa9bf76e7a3f9591397b07c98ddf373e24d6aae7d69de01803df644be",
        ),
        (
            8192,
            "3073a2e8f0607eb980fdcd6593c0948e916cac1d76c6e1dd8028d73f79b85a10",
        ),
        (
            524287,
            "d064c5989933c26efb72e38884bbfd4b475ac369d7aafaeab2cf3098e6d5bbff",
        ),
        (
            524288,
            "7e28d401302a8ffb4091e8ae4b2ca78b5dc74125b416cfbed6370d11f692beca",
        ),
        (
            524289,
            "63f72f51ebe9996af2d9c9ded7062484af525f1676603b838d91abd20b8a132d",
        ),
        (
            528384,
            "f37c8588cb133b31480a8f217dd3b813830ccd7b23d199cc156f5b666389f2dd",
        ),
        (
            528385,
            "dd2227d2dfe2d89be7918b97758068ecbd2d9a32a2e03bbefc4c98f9285b2bc1",
        ),
        (
            1052673,
            "a9d7c1cd9079e8e6c557e51bff6a33cb4bb830f7cd54d5d845fabf55f33fa179",
        ),
    ];

    #[test]
    fn file_references_match_bee() {
        assert_eq!(
            cac_address(11, b"hello swarm"),
            unhex32("f9335c1f06d729ae3e725352a445fa01a1e9dc20e937f0ef19ab199b1fb2827b")
        );
        for (len, expected) in BEE {
            assert_eq!(
                file_reference(&data(*len)),
                unhex32(expected),
                "length {len}"
            );
        }
        let d = data(5000);
        assert!(verify_file(&d, &file_reference(&d)).is_ok());
        assert!(verify_file(&d[1..], &file_reference(&d)).is_err());
    }

    /// A file walked chunk by chunk from its root, each chunk checked, gives the file back.
    fn walk(
        tree: &std::collections::HashMap<[u8; 32], Vec<u8>>,
        r: &[u8; 32],
        span: Option<u64>,
        out: &mut Vec<u8>,
    ) {
        let chunk = FileChunk::decode(&tree[r], r, span).unwrap();
        let spans = chunk.child_spans();
        match chunk {
            FileChunk::Leaf(p) => out.extend(p),
            FileChunk::Inner { children, .. } => {
                for (c, s) in children.iter().zip(spans) {
                    walk(tree, c, Some(s), out);
                }
            }
        }
    }

    /// Leaf `i` of the file under `root`, walking down by [`FileChunk::child_for`] and
    /// [`FileChunk::child`].
    fn leaf(
        tree: &std::collections::HashMap<[u8; 32], Vec<u8>>,
        root: &[u8; 32],
        i: u64,
    ) -> Vec<u8> {
        let mut chunk = FileChunk::decode(&tree[root], root, None).unwrap();
        let mut i = i;
        while let Some((k, below)) = chunk.child_for(i) {
            let (r, span) = chunk.child(k).unwrap();
            chunk = FileChunk::decode(&tree[&r], &r, Some(span)).unwrap();
            i = below;
        }
        match chunk {
            FileChunk::Leaf(p) => p,
            FileChunk::Inner { .. } => panic!("leaf {i} beyond the file"),
        }
    }

    #[test]
    fn any_leaf_is_reached_from_the_root() {
        // One, two and three levels (300 leaves: two full intermediate chunks and a third).
        for len in [4096usize, 129 * 4096 + 3, 300 * 4096 + 11] {
            let d = data(len);
            let tree: std::collections::HashMap<_, _> = file_tree(&d).into_iter().collect();
            let root = file_reference(&d);
            let leaves = len.div_ceil(4096) as u64;
            for i in [0, 1, 127, 128, 129, 200, leaves - 1] {
                if i >= leaves {
                    continue;
                }
                let start = i as usize * 4096;
                assert_eq!(
                    leaf(&tree, &root, i),
                    d[start..(start + 4096).min(len)],
                    "length {len}, leaf {i}"
                );
            }
            let top = FileChunk::decode(&tree[&root], &root, Some(len as u64)).unwrap();
            assert_eq!(top.span(), len as u64);
            assert_eq!(top.child_for(leaves), None);
        }
    }

    #[test]
    fn files_walk_from_their_root() {
        for len in [1usize, 4096, 4097, 524288, 524289, 1052673] {
            let d = data(len);
            let tree: std::collections::HashMap<_, _> = file_tree(&d).into_iter().collect();
            let root = file_reference(&d);
            assert!(tree.contains_key(&root), "length {len}");
            let mut got = Vec::new();
            walk(&tree, &root, Some(len as u64), &mut got);
            assert_eq!(got, d, "length {len}");
        }
        // A chunk under another reference is refused.
        let d = data(8192);
        let tree = file_tree(&d);
        assert!(FileChunk::decode(&tree[0].1, &tree[1].0, None).is_err());
        // A root whose span is not the file's size is refused.
        let root = file_reference(&d);
        let wire = &tree.iter().find(|(r, _)| *r == root).unwrap().1;
        assert!(FileChunk::decode(wire, &root, Some(8191)).is_err());
    }

    #[test]
    fn spans_beyond_what_a_reader_walks_are_refused() {
        // A span above 2^61 overflowed the cap computation: refused, at once.
        // An intermediate chunk with as many references as its span needs.
        let chunk = |span: u64| {
            let n = if span <= MAX_SPAN {
                span.div_ceil(child_cap(span)) as usize
            } else {
                1
            };
            let payload = vec![7u8; 32 * n];
            let mut wire = span.to_le_bytes().to_vec();
            wire.extend_from_slice(&payload);
            (wire, cac_address(span, &payload))
        };
        for span in [u64::MAX, 1 << 62, MAX_SPAN + 1] {
            let (wire, r) = chunk(span);
            assert!(FileChunk::decode(&wire, &r, None).is_err(), "span {span}");
        }
        // A file above MAX_FILE is walked page by page, never read whole.
        let big = crate::records::MAX_FILE as u64 + 1;
        let (wire, r) = chunk(big);
        assert!(FileChunk::decode(&wire, &r, None).is_ok());
        let err = FileChunk::decode_whole_root(&wire, &r).unwrap_err();
        assert!(err.0.contains("reads whole"), "{}", err.0);
    }

    #[test]
    fn signatures_normalize_like_the_reference() {
        // A known signer: Anvil's dev key #0 signs a digest; its high-S twin (s' = n - s,
        // v flipped) and v as 27/28 recover the same address.
        use k256::ecdsa::SigningKey;
        let key = SigningKey::from_slice(&crate::records::tests_support::unhex(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        ))
        .unwrap();
        let hash = keccak256(b"addr1");
        let (sig, recid) = key.sign_prehash_recoverable(&hash).unwrap();
        let mut low = [0u8; 65];
        low[..64].copy_from_slice(&sig.to_bytes());
        low[64] = recid.to_byte() + 27;
        let want = crate::records::tests_support::unhex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(recover_signer(&hash, &low).unwrap().to_vec(), want);
        // The high-S twin.
        let n = k256::Scalar::ZERO - sig.s().as_ref();
        let high = Signature::from_scalars(sig.r().as_ref().to_bytes(), n.to_bytes()).unwrap();
        let mut h = [0u8; 65];
        h[..64].copy_from_slice(&high.to_bytes());
        h[64] = recid.to_byte() ^ 1;
        assert_eq!(recover_signer(&hash, &h).unwrap().to_vec(), want);
        // v outside 0/1/27/28 is refused.
        let mut bad = low;
        bad[64] = 37;
        assert!(recover_signer(&hash, &bad).is_err());
    }

    #[test]
    fn cac_check() {
        let payload = b"hello swarm";
        let mut wire = (payload.len() as u64).to_le_bytes().to_vec();
        wire.extend_from_slice(payload);
        let addr = cac_address(11, payload);
        assert_eq!(verify_cac(&wire, &addr).unwrap(), payload);
        wire[9] ^= 1;
        assert!(verify_cac(&wire, &addr).is_err());
    }
}
