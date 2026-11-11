// Package lc is the Go engine's consensus light client: the SSZ containers
// and merkleization of docs/spec/01, the BLS sync-committee check, and the
// update processor — a port of rust/myotis-consensus (types.rs, ssz.rs,
// verify.rs, store.rs, fork.rs) pinned to the same cross-language corpus
// (rust/testdata/lc/mainnet). Trust enters only through the pinned
// checkpoint and genesis validators root; every header above it is proven
// by sync-committee BLS and Merkle branches.
package lc

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// Domain type for sync-committee signatures (spec DOMAIN_SYNC_COMMITTEE).
var DomainSyncCommittee = [4]byte{0x07, 0x00, 0x00, 0x00}

const (
	// SyncCommitteeSize is the mainnet preset committee size.
	SyncCommitteeSize = 512
	// MaxPubkeys bounds the aggregate input like myotis-bls MAX_PUBKEYS —
	// reject arithmetic on absurd inputs before it happens.
	MaxPubkeys = 4096
)

type hash32 = [32]byte

func sha256Pair(a, b hash32) hash32 {
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	var out hash32
	copy(out[:], h.Sum(nil))
	return out
}

// zeroHashes[i] is the root of an all-zero subtree with 2^i leaves: the
// pad nodes verifyNormalizedMerkleBranch accepts, and the ladder a
// missing leaf pairs up through. (merkleize itself is NOT sparse — it
// visits every leaf up to limit; at these sizes that is fine.)
var zeroHashes = func() [41]hash32 {
	var z [41]hash32
	for i := 1; i < len(z); i++ {
		z[i] = sha256Pair(z[i-1], z[i-1])
	}
	return z
}()

func nextPow2(n uint64) uint64 {
	p := uint64(1)
	for p < n {
		p <<= 1
	}
	return p
}

// merkleize roots `chunks` over a tree of `limit` leaves (limit a power of
// two ≥ len(chunks)); missing leaves are the zero subtree at their depth.
func merkleize(chunks []hash32, limit uint64) hash32 {
	if limit == 0 {
		limit = 1
	}
	if uint64(len(chunks)) > limit {
		panic("lc: merkleize: chunks exceed limit")
	}
	return merkleizeRec(chunks, 0, limit)
}

func merkleizeRec(chunks []hash32, start, size uint64) hash32 {
	if size == 1 {
		if start < uint64(len(chunks)) {
			return chunks[start]
		}
		// A missing LEAF is zeroHashes[0] regardless of how deep it sits;
		// the paired-up zero subtrees (zeroHashes[d]) emerge from the
		// recursion itself. (The depth-from-root value here would be the
		// fill table for a whole missing subtree of that height, which
		// this leaf case is not.)
		return zeroHashes[0]
	}
	half := size / 2
	return sha256Pair(
		merkleizeRec(chunks, start, half),
		merkleizeRec(chunks, start+half, half),
	)
}

// chunkBytes splits b into 32-byte chunks, zero-padding the last.
func chunkBytes(b []byte) []hash32 {
	n := (len(b) + 31) / 32
	out := make([]hash32, n)
	for i := 0; i < len(b); i++ {
		out[i/32][i%32] = b[i]
	}
	return out
}

// vectorRoot roots a fixed byte vector (e.g. a 48-byte BLS pubkey: two
// chunks, padded to 4 leaves).
func vectorRoot(b []byte) hash32 {
	chunks := chunkBytes(b)
	return merkleize(chunks, nextPow2(uint64(len(chunks))))
}

// listRoot roots a byte list against its MAX_LENGTH (maxChunks chunks).
func listRoot(b []byte, maxChunks uint64) hash32 {
	chunks := chunkBytes(b)
	if uint64(len(chunks)) > maxChunks {
		panic("lc: byte list exceeds max length")
	}
	root := merkleize(chunks, nextPow2(maxChunks))
	return mixInLength(root, uint64(len(b)))
}

func mixInLength(root hash32, length uint64) hash32 {
	var l hash32
	binary.LittleEndian.PutUint64(l[:], length)
	return sha256Pair(root, l)
}

// containerRoot roots a fixed-size container from its field roots.
func containerRoot(fields ...hash32) hash32 {
	return merkleize(fields, nextPow2(uint64(len(fields))))
}

func uint64Root(v uint64) hash32 {
	var h hash32
	binary.LittleEndian.PutUint64(h[:], v)
	return h
}

// verifyMerkleBranch is the spec is_valid_merkle_branch: walk leaf up
// through branch with the low depth bits of index as the path.
func verifyMerkleBranch(leaf hash32, branch []hash32, index uint64, root hash32) bool {
	slot := leaf
	for i, b := range branch {
		if (index>>uint(i))&1 == 1 {
			slot = sha256Pair(b, slot)
		} else {
			slot = sha256Pair(slot, b)
		}
	}
	return slot == root
}

// verifyNormalizedMerkleBranch is the spec is_valid_normalized_merkle_branch
// (ssz.rs:151-166): depth comes from the gindex itself; a branch LONGER
// than that depth is accepted only when every extra LEADING node is zero,
// and those pads are STRIPPED before walking — the proof is proven at
// depth, not over the padded vector. (Walking the leaf through the zero
// node instead, as an earlier draft here did, computes a proof one level
// deeper than the gindex names and fails every genuine normalized
// proof.) This is how a Gloas-carried pre-Gloas header pads a shallower
// proof — the Deneb block hash at gindex 812 is depth 9 inside an 11-node
// vector (spec.rs:33-36), so ANY number of pads must pass, not just one.
func verifyNormalizedMerkleBranch(leaf hash32, branch []hash32, gindex uint64, root hash32) bool {
	if gindex < 2 {
		return false // gindex 1 is the root itself; 0 names nothing
	}
	depth := uint64(bits.Len64(gindex)) - 1
	if uint64(len(branch)) < depth {
		return false
	}
	extra := uint64(len(branch)) - depth
	for _, node := range branch[:extra] {
		if node != zeroHashes[0] {
			return false
		}
	}
	return verifyMerkleBranch(leaf, branch[extra:], gindex, root)
}
