//! Splitting Nimbus's `light_client/updates` REST body into per-period chunks,
//! and re-framing them as a libp2p `light_client_updates_by_range` response.
//!
//! The REST body is a concatenation of
//!
//! ```text
//! u64 little-endian length | 4-byte fork digest | LightClientUpdate SSZ
//! ```
//!
//! where the length covers *digest + update*. Chunks vary in size by a few
//! bytes because `ExecutionPayloadHeader.extra_data` is variable-length, so
//! **the length prefix is the only authority for chunk boundaries** — never
//! assume a uniform stride (docs/lc-server-design.md, "The one framing detail").
//!
//! Converting to the libp2p response is then per chunk:
//! `encode_success_response(update_ssz, Some(fork_digest))`, concatenated. That
//! re-emits the digest the source already framed, which is the robust path:
//! since EIP-7892 the digest is not a function of the fork *name*, so a
//! name→digest table would silently go stale after a blob-parameter-only fork.
//!
//! # Trust boundary
//!
//! This parser walks a length prefix from an HTTP response. Even though that
//! response comes from our own Nimbus over loopback, every slice here is
//! checked (`get(..)`, `checked_add`, `usize::try_from`) and every length is
//! bounded — the design calls for this regardless of where the crate lives,
//! because it is cheap and because the same code will later walk bytes from
//! less friendly sources.

use myotis_net::codec::encode_success_response;

/// Upper bound on a single chunk's declared length.
///
/// A `LightClientUpdate` measures ~27 KB on sepolia (dominated by the 512×48-byte
/// sync committee), so 1 MiB is ~38× headroom — generous enough to survive a
/// future fork growing the type, tight enough that a corrupt or hostile length
/// prefix cannot make us allocate wildly.
pub const MAX_CHUNK_BYTES: usize = 1 << 20;

/// The fork digest is the first 4 bytes of each chunk's body.
const FORK_DIGEST_LEN: usize = 4;

/// The length prefix itself.
const LENGTH_PREFIX_LEN: usize = 8;

/// One period's update, as the REST endpoint framed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateChunk {
    /// Re-emitted verbatim as the libp2p response's context bytes.
    pub fork_digest: [u8; 4],
    /// The `LightClientUpdate` SSZ, with the digest stripped.
    pub ssz: Vec<u8>,
}

impl UpdateChunk {
    /// `0x00 || fork_digest || varint(len) || snappy(ssz)` — one chunk of a
    /// libp2p multi-chunk response.
    pub fn to_wire(&self) -> Vec<u8> {
        encode_success_response(&self.ssz, Some(self.fork_digest))
    }
}

/// Why a REST updates body could not be walked.
///
/// Every variant carries the offset it failed at: with a concatenated body, "it
/// didn't parse" is useless for telling a truncated download from a bad chunk
/// halfway in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// Fewer than 8 bytes remain where a length prefix should start.
    TruncatedLength { offset: usize, remaining: usize },
    /// The declared length does not fit in a `usize` (32-bit hosts) or would
    /// overflow when added to the offset.
    LengthOverflow { offset: usize, declared: u64 },
    /// Declared length exceeds [`MAX_CHUNK_BYTES`].
    ChunkTooLarge { offset: usize, declared: usize },
    /// Declared length leaves no room for the 4-byte fork digest.
    ChunkTooShort { offset: usize, declared: usize },
    /// The body ends before the declared chunk does.
    TruncatedChunk {
        offset: usize,
        need: usize,
        have: usize,
    },
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedLength { offset, remaining } => write!(
                f,
                "truncated length prefix at offset {offset}: {remaining} byte(s) remain, need {LENGTH_PREFIX_LEN}"
            ),
            Self::LengthOverflow { offset, declared } => {
                write!(f, "chunk length {declared} at offset {offset} overflows usize")
            }
            Self::ChunkTooLarge { offset, declared } => write!(
                f,
                "chunk length {declared} at offset {offset} exceeds MAX_CHUNK_BYTES ({MAX_CHUNK_BYTES})"
            ),
            Self::ChunkTooShort { offset, declared } => write!(
                f,
                "chunk length {declared} at offset {offset} leaves no room for the {FORK_DIGEST_LEN}-byte fork digest"
            ),
            Self::TruncatedChunk { offset, need, have } => write!(
                f,
                "truncated chunk at offset {offset}: need {need} byte(s), have {have}"
            ),
        }
    }
}

impl std::error::Error for FramingError {}

/// Walk a `light_client/updates` REST body into its per-period chunks.
///
/// An empty body is not an error — it is how Nimbus answers for a period below
/// its light-client window (verified against the live node: periods 1199–1322
/// return 0 bytes, 1323 upward return data). Callers distinguish "no data" from
/// "bad data" by the empty `Vec`.
pub fn split_updates(body: &[u8]) -> Result<Vec<UpdateChunk>, FramingError> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        // --- length prefix -------------------------------------------------
        let body_start = offset
            .checked_add(LENGTH_PREFIX_LEN)
            .ok_or(FramingError::LengthOverflow {
                offset,
                declared: 0,
            })?;
        let prefix = body
            .get(offset..body_start)
            .ok_or(FramingError::TruncatedLength {
                offset,
                remaining: body.len() - offset,
            })?;
        // The slice is exactly LENGTH_PREFIX_LEN long by construction.
        let declared_u64 = u64::from_le_bytes(prefix.try_into().expect("8-byte slice"));

        let declared =
            usize::try_from(declared_u64).map_err(|_| FramingError::LengthOverflow {
                offset,
                declared: declared_u64,
            })?;
        if declared > MAX_CHUNK_BYTES {
            return Err(FramingError::ChunkTooLarge { offset, declared });
        }
        // The length covers digest + update, so anything under 4 cannot even
        // carry the digest — and a 4-byte chunk would be a digest with an empty
        // update, which is equally malformed.
        if declared <= FORK_DIGEST_LEN {
            return Err(FramingError::ChunkTooShort { offset, declared });
        }

        // --- chunk body ----------------------------------------------------
        let chunk_end = body_start
            .checked_add(declared)
            .ok_or(FramingError::LengthOverflow {
                offset,
                declared: declared_u64,
            })?;
        let chunk = body
            .get(body_start..chunk_end)
            .ok_or(FramingError::TruncatedChunk {
                offset,
                need: declared,
                have: body.len() - body_start,
            })?;

        let mut fork_digest = [0u8; FORK_DIGEST_LEN];
        fork_digest.copy_from_slice(&chunk[..FORK_DIGEST_LEN]);
        chunks.push(UpdateChunk {
            fork_digest,
            ssz: chunk[FORK_DIGEST_LEN..].to_vec(),
        });

        offset = chunk_end;
    }

    Ok(chunks)
}

/// Concatenate chunks into a complete libp2p multi-chunk response body.
pub fn updates_to_wire(chunks: &[UpdateChunk]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(&c.to_wire());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a REST-shaped body from (digest, ssz) pairs.
    fn rest_body(items: &[([u8; 4], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (digest, ssz) in items {
            let len = (FORK_DIGEST_LEN + ssz.len()) as u64;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(digest);
            out.extend_from_slice(ssz);
        }
        out
    }

    #[test]
    fn empty_body_is_no_chunks_not_an_error() {
        // How Nimbus answers below its LC window — "no data", not "bad data".
        assert_eq!(split_updates(&[]).unwrap(), vec![]);
    }

    #[test]
    fn splits_multiple_chunks_of_differing_length() {
        // extra_data is variable-length, so a uniform stride would be wrong.
        let body = rest_body(&[
            ([0x74, 0xd0, 0x14, 0x59], &[1u8; 40]),
            ([0x74, 0xd0, 0x14, 0x59], &[2u8; 37]),
            ([0xaa, 0xbb, 0xcc, 0xdd], &[3u8; 41]),
        ]);
        let chunks = split_updates(&body).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].ssz, vec![1u8; 40]);
        assert_eq!(chunks[1].ssz, vec![2u8; 37]);
        assert_eq!(chunks[2].ssz, vec![3u8; 41]);
        assert_eq!(chunks[2].fork_digest, [0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn layout_matches_the_live_node() {
        // Observed on zbox's Nimbus v26.7.0, period 1327: the body opens
        // `2769000000000000` (26 919 LE) then digest `74d01459`, and the whole
        // response is 26 927 = 8 + 26 919.
        let mut body = Vec::new();
        body.extend_from_slice(&0x6927u64.to_le_bytes());
        body.extend_from_slice(&[0x74, 0xd0, 0x14, 0x59]);
        body.extend_from_slice(&vec![0u8; 26_919 - FORK_DIGEST_LEN]);
        assert_eq!(body.len(), 26_927);

        let chunks = split_updates(&body).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].fork_digest, [0x74, 0xd0, 0x14, 0x59]);
        assert_eq!(chunks[0].ssz.len(), 26_915);
    }

    #[test]
    fn round_trips_through_the_myotis_decoder() {
        // The closing of the loop: what we frame for the wire is what our own
        // wallets already decode. Same pairing the codec's own round-trip test
        // uses, driven from the REST side.
        let body = rest_body(&[
            ([0x74, 0xd0, 0x14, 0x59], &[7u8; 128]),
            ([0x74, 0xd0, 0x14, 0x59], &[9u8; 131]),
        ]);
        let chunks = split_updates(&body).unwrap();
        let wire = updates_to_wire(&chunks);

        let decoded = myotis_net::codec::decode_multi_chunk_response(&wire, 2).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], vec![7u8; 128]);
        assert_eq!(decoded[1], vec![9u8; 131]);
    }

    #[test]
    fn rejects_truncated_length_prefix() {
        let err = split_updates(&[1, 2, 3]).unwrap_err();
        assert_eq!(
            err,
            FramingError::TruncatedLength {
                offset: 0,
                remaining: 3
            }
        );
    }

    #[test]
    fn rejects_truncated_chunk_body() {
        let mut body = Vec::new();
        body.extend_from_slice(&100u64.to_le_bytes());
        body.extend_from_slice(&[0xaa; 20]); // 20 of the promised 100
        let err = split_updates(&body).unwrap_err();
        assert_eq!(
            err,
            FramingError::TruncatedChunk {
                offset: 0,
                need: 100,
                have: 20
            }
        );
    }

    #[test]
    fn rejects_absurd_length_without_allocating() {
        let mut body = Vec::new();
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        body.extend_from_slice(&[0xaa; 8]);
        // On 64-bit this is ChunkTooLarge (usize::try_from succeeds); on 32-bit
        // it is LengthOverflow. Both are refusals, and neither allocates.
        assert!(matches!(
            split_updates(&body).unwrap_err(),
            FramingError::ChunkTooLarge { .. } | FramingError::LengthOverflow { .. }
        ));
    }

    #[test]
    fn rejects_chunk_with_no_room_for_a_digest() {
        for declared in [0u64, 1, 4] {
            let mut body = Vec::new();
            body.extend_from_slice(&declared.to_le_bytes());
            body.extend_from_slice(&[0xaa; 8]);
            assert!(
                matches!(
                    split_updates(&body).unwrap_err(),
                    FramingError::ChunkTooShort { .. }
                ),
                "declared={declared} should be refused"
            );
        }
    }

    #[test]
    fn reports_the_offset_of_a_late_failure() {
        // A good chunk, then a bad one — the offset must point at the bad one,
        // so a truncated download is distinguishable from mid-body corruption.
        let mut body = rest_body(&[([0x74, 0xd0, 0x14, 0x59], &[1u8; 40])]);
        let good_len = body.len();
        body.extend_from_slice(&9_999u64.to_le_bytes());
        body.extend_from_slice(&[0xbb; 10]);

        let err = split_updates(&body).unwrap_err();
        assert_eq!(
            err,
            FramingError::TruncatedChunk {
                offset: good_len,
                need: 9_999,
                have: 10
            }
        );
    }
}
