//! Checks of what Swarm delivered: a content-addressed chunk against its address, a SOC
//! against its address and its owner's signature, a file against its root reference
//! (Bee's chunker, unencrypted, without erasure coding).

use myotis_core::keccak::{keccak256, keccak256_concat};
use myotis_core::nodekey::recover_public_key;

use crate::{ensure, fail, hex, Result};

/// Maximum payload of one chunk.
pub const CHUNK_SIZE: usize = 4096;
const SEGMENT: usize = 32;
const BRANCHES: usize = CHUNK_SIZE / 32;
const ID_LEN: usize = 32;
const SIG_LEN: usize = 65;
const SPAN_LEN: usize = 8;

/// BMT root of a payload of at most [`CHUNK_SIZE`] bytes.
pub fn bmt_root(payload: &[u8]) -> [u8; 32] {
    assert!(
        payload.len() <= CHUNK_SIZE,
        "chunk payload over {CHUNK_SIZE}"
    );
    let mut level = vec![0u8; CHUNK_SIZE];
    level[..payload.len()].copy_from_slice(payload);
    while level.len() > SEGMENT {
        level = level
            .chunks(2 * SEGMENT)
            .flat_map(|pair| keccak256(pair))
            .collect();
    }
    level.try_into().expect("32 bytes")
}

/// Address of a content-addressed chunk with the given span and payload.
pub fn cac_address(span: u64, payload: &[u8]) -> [u8; 32] {
    keccak256_concat(&span.to_le_bytes(), &bmt_root(payload))
}

/// Address of the SOC with `identifier` owned by `owner`.
pub fn soc_address(identifier: &[u8; 32], owner: &[u8; 20]) -> [u8; 32] {
    keccak256_concat(identifier, owner)
}

/// The payload of a content-addressed chunk in wire form (`span ‖ payload`), checked against
/// `address`.
pub fn verify_cac(wire: &[u8], address: &[u8; 32]) -> Result<Vec<u8>> {
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
    let mut sig: [u8; 65] = wire[ID_LEN..ID_LEN + SIG_LEN].try_into().expect("65");
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
    if sig[64] >= 27 {
        sig[64] -= 27;
    }
    let public = recover_public_key(&msg, &sig).map_err(|e| fail!("bad SOC signature: {e:?}"))?;
    let signer: [u8; 20] = keccak256(&public)[12..].try_into().expect("20");
    ensure!(
        signer == *owner,
        "SOC signed by {}, expected owner {}",
        hex(&signer),
        hex(owner)
    );
    Ok(payload.to_vec())
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
