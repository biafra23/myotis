// Package forkid implements the EIP-2124 fork id the eth Status must present
// and validate. Like both reference engines it ANNOUNCES a pinned
// (hash, next) rather than computing it from genesis (docs/spec README §6,
// 07-el-implementation-plan decision #5), but it can step a hash across a
// known activation with the resumable IEEE CRC32 — the same arithmetic as
// rust/myotis-core/src/forkid.rs.
package forkid

import (
	"encoding/binary"
	"hash/crc32"
)

// TimestampThreshold: activation values at or above this are unix seconds,
// below it block numbers (geth's threshold — the Frontier genesis
// timestamp). Every live fork since Shanghai is timestamped.
const TimestampThreshold = 1_438_269_973

// ID is an EIP-2124 fork id as it goes on the wire in Status.
type ID struct {
	Hash [4]byte
	Next uint64
}

// Successor is the fork hash in effect once a fork activating at
// `activation` has passed, given the hash in effect before it: CRC32
// continued over the big-endian uint64 activation.
func Successor(hash uint32, activation uint64) uint32 {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], activation)
	return crc32.Update(hash, crc32.IEEETable, b[:])
}

// IDAt resolves the fork id to announce at wall clock `now` for a build
// pinned to id: a known timestamp fork that has passed folds into the hash
// and the announcement resets to (successor, 0). A block-number Next never
// switches. Twin: Rust fork_id_at / Java ForkIds.effective.
func (id ID) IDAt(now uint64) ID {
	if id.Next >= TimestampThreshold && now >= id.Next {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], Successor(binary.BigEndian.Uint32(id.Hash[:]), id.Next))
		return ID{Hash: h, Next: 0}
	}
	return id
}

// Accept reports whether a peer's fork id is compatible with ours under
// EIP-2124: same hash — regardless of what Next they announce, per the EIP
// and geth's forkid.IsValid, which short-circuits on hash equality; peers
// fill Next with whatever future activation THEY know — or a hash reachable
// from ours by folding one known activation (the peer is one fork ahead of
// our pin). This is the minimum courtesy gate — a peer whose id we cannot
// relate to would drop us anyway; the trust anchor for headers is the light
// client, not this field (the Rust twin only checks network + genesis,
// myotis-wire eth.rs is_compatible).
func Accept(mine, theirs ID) bool {
	if theirs.Hash == mine.Hash {
		return true
	}
	// Peer one known timestamp fork ahead: our successor equals their hash.
	if mine.Next >= TimestampThreshold {
		var succ [4]byte
		binary.BigEndian.PutUint32(succ[:], Successor(binary.BigEndian.Uint32(mine.Hash[:]), mine.Next))
		if succ == theirs.Hash {
			return true
		}
	}
	return false
}
