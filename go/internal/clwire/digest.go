// Package clwire is the Go engine's beacon-chain p2p wire layer: the eth2
// req/resp protocol identities, the ssz_snappy framing, the Status message
// and the fork-digest math — a port of rust/myotis-wire/src/eth2
// (codec.rs, protocols.rs, status.rs), pinned to the same
// cross-language golden vectors the Rust codec tests assert. The fork
// digest gates everything: it is both the ENR filter for CL discovery
// and the first four bytes every peer compares its own to before
// answering a request (docs/spec/01 §13.5).
package clwire

import (
	"crypto/sha256"

	"github.com/biafra23/myotis/go/internal/chain"
)

// ForkDataRoot: SSZ container root [padded_root(fork_version),
// genesis_validators_root] — a 2-leaf container is ONE pair hash
// (status.rs:127-129; same merkleize as lc's containerRoot, and pinning
// this against the golden digest is what proves it — the double-hash
// misreading computes a root for a tree one level too deep).
func ForkDataRoot(forkVersion [4]byte, gvr [32]byte) [32]byte {
	var padded [64]byte
	copy(padded[:4], forkVersion[:])
	copy(padded[32:], gvr[:])
	return sha256.Sum256(padded[:])
}

// ForkDigest is the pre-Fulu compute_fork_digest: ForkData root [:4].
func ForkDigest(forkVersion [4]byte, gvr [32]byte) [4]byte {
	r := ForkDataRoot(forkVersion, gvr)
	return [4]byte{r[0], r[1], r[2], r[3]}
}

// ForkDigestBPO is the Fulu / EIP-7892 digest:
// (ForkDataRoot XOR sha256(u64_le(epoch) || u64_le(max_blobs)))[:4].
// epoch == 0 means no BPO is active and the base formula stands
// (status.rs:141-158). The mainnet consequence is that the ENR digest and
// the Status digest BOTH change at the BPO2 epoch — an engine that pins
// the base digest silently discovers zero peers from that block on.
func ForkDigestBPO(forkVersion [4]byte, gvr [32]byte, blobEpoch, maxBlobs uint64) [4]byte {
	base := ForkDataRoot(forkVersion, gvr)
	if blobEpoch == 0 {
		return [4]byte{base[0], base[1], base[2], base[3]}
	}
	var buf [16]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(blobEpoch >> (8 * uint(i)))
		buf[8+i] = byte(maxBlobs >> (8 * uint(i)))
	}
	h := sha256.Sum256(buf[:])
	return [4]byte{base[0] ^ h[0], base[1] ^ h[1], base[2] ^ h[2], base[3] ^ h[3]}
}

// KnownForkDigests lists every fork digest THIS build's pinned schedule
// can produce: each pinned fork version's plain digest, and — when a BPO
// epoch is pinned — the same versions under the EIP-7892 fold (pre-BPO
// answers carry the plain form, post-BPO ones the folded form; both are
// honest context bytes). A chunk whose context bytes match none of these
// names a fork past every fork this build can speak — the digest
// selects the wire shape (the Rust twin dispatches Gloas on it,
// sync.rs:657-666), so this engine REFUSES an unknown one rather than
// silently decoding a Gloas-shaped object in a pre-Gloas parser
// (CLAUDE.md: applied or refused, never accepted-and-ignored).
func KnownForkDigests(c *chain.Consensus) map[[4]byte]bool {
	out := make(map[[4]byte]bool, 2*len(c.Forks))
	for _, f := range c.Forks {
		out[ForkDigest(f.Version, c.GenesisValidatorsRoot)] = true
		if c.BlobParamsEpoch != 0 {
			out[ForkDigestBPO(f.Version, c.GenesisValidatorsRoot,
				c.BlobParamsEpoch, c.BlobParamsMaxBlobs)] = true
		}
	}
	return out
}

// CurrentForkDigest is the digest THIS engine accepts at the wall clock:
// the fork version active at the current epoch, with the network's BPO
// blob params folded once the BPO epoch has passed (the
// fork_digest_at_epoch(slip-0) the Rust config computes per candidate).
func CurrentForkDigest(c *chain.Consensus, unixSec int64) [4]byte {
	epoch := c.SlotAt(unixSec) / chain.SlotsPerEpoch
	v := c.ForkVersionAtEpoch(epoch)
	if c.BlobParamsEpoch != 0 && epoch >= c.BlobParamsEpoch {
		return ForkDigestBPO(v, c.GenesisValidatorsRoot, c.BlobParamsEpoch, c.BlobParamsMaxBlobs)
	}
	return ForkDigest(v, c.GenesisValidatorsRoot)
}
