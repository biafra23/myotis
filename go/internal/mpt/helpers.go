package mpt

// RLP item walking and hex-prefix (compact path) codec — the helpers
// mpt.go's descent needs, ported from rust/myotis-core's rlp.rs /
// trie.rs so both twins read a node alike. The walk reuses
// go-ethereum's rlp.Split (the "prefer settled geth plumbing"
// principle), but the ACCEPTANCE rules are this package's: every
// malformed shape must land in Invalid, never in Absent — Absent is a
// proven negative the reader returns to the caller as fact. The strict
// whole-node validation lives one layer down in rlpcode.ValidateNode
// (shared with snapwire's decoders, which check dropped range entries
// exactly as kept ones).

import (
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/biafra23/myotis/go/internal/rlpcode"
)

type itemKind int

const (
	kindBytes itemKind = iota
	kindList
	// kindMalformed: the raw bytes are not a well-formed single RLP
	// item. Rust has no such case (Item is fully decoded before
	// interpretation); in Go the list walk hands back raw sub-slices, so
	// a truncated tail can only be caught here. It must NOT read as
	// kindBytes-with-empty-content, or a corrupt node would masquerade
	// as a proven absence.
	kindMalformed
)

// classifyItem splits one raw item into kind + content. Content is the
// item's decoded payload (bytes content, or list content — callers of a
// list always use the raw item bytes instead, which ARE the item's own
// RLP encoding).
func classifyItem(item []byte) (itemKind, []byte, bool) {
	kind, content, rest, err := rlp.Split(item)
	if err != nil || len(rest) != 0 {
		return kindMalformed, nil, false
	}
	if kind == rlp.List {
		return kindList, content, true
	}
	return kindBytes, content, false
}

// rlpList returns a list item's items (each still fully encoded),
// rejecting non-lists and trailing bytes. Input must have passed
// rlpcode.ValidateNode already — like the Rust twin, VerifyProof
// validates a node once at the by-hash lookup and interpret then
// re-splits the (already-validated) node or an embedded child; the
// error return
// remains for the non-list case, which interpret renders as
// "malformed node RLP: expected list" (interpret's as_list arm).
func rlpList(b []byte) ([][]byte, error) {
	return rlpcode.Items(b)
}

func toNibbles(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, x>>4, x&0x0f)
	}
	return out
}

// hexPrefixDecode decodes a compact-encoded path into (isLeaf,
// nibbles) — trie.rs:322-341 verbatim, including the flag>3 refusal
// (flag nibbles 4..7 are unspecified in Appendix C; honest tries never
// emit them).
func hexPrefixDecode(encoded []byte) (bool, []byte, error) {
	if len(encoded) == 0 {
		return false, nil, errors.New("empty hex-prefix path")
	}
	flag := encoded[0] >> 4
	if flag > 3 {
		return false, nil, fmt.Errorf("invalid hex-prefix flag nibble: %d", flag)
	}
	leaf := flag&0x02 != 0
	odd := flag&0x01 != 0
	nibbles := make([]byte, 0, len(encoded)*2)
	if odd {
		nibbles = append(nibbles, encoded[0]&0x0f)
	}
	for _, b := range encoded[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return leaf, nibbles, nil
}

// hexPrefixEncode is the round-trip partner, used by tests (trie.rs:344).
func hexPrefixEncode(nibbles []byte, leaf bool) []byte {
	odd := len(nibbles)%2 == 1
	var flag byte
	if leaf {
		flag |= 2
	}
	if odd {
		flag |= 1
	}
	out := make([]byte, 0, 1+len(nibbles)/2)
	rest := nibbles
	if odd {
		out = append(out, flag<<4|nibbles[0]&0x0f)
		rest = nibbles[1:]
	} else {
		out = append(out, flag<<4)
	}
	for i := 0; i+1 < len(rest); i += 2 {
		out = append(out, rest[i]<<4|rest[i+1]&0x0f)
	}
	return out
}

// AccountLeaf is the Ethereum state-trie account leaf
// `RLP([nonce, balance, storageRoot, codeHash])` (trie.rs:158-166).
type AccountLeaf struct {
	Nonce uint64
	// Balance is the minimal big-endian wei value (empty = zero), kept
	// as bytes like the Rust twin — balances exceed int64.
	Balance     []byte
	StorageRoot [32]byte
	CodeHash    [32]byte
}

// DecodeAccountLeaf decodes a proof-verified account leaf value. THE
// ONLY legitimate source of StorageRoot/CodeHash (README §11.8) — never
// a peer's slim body. Stricter than lenient library readers: leading-
// zero scalars and out-of-range values are rejected; honest tries never
// contain them (trie.rs:176-196).
func DecodeAccountLeaf(value []byte) (*AccountLeaf, error) {
	items, err := rlpcode.Items(value)
	if err != nil {
		return nil, fmt.Errorf("account leaf: %v", err)
	}
	if len(items) != 4 {
		return nil, fmt.Errorf("account leaf: expected 4 fields, got %d", len(items))
	}
	// U64 is scalar_u64 (≤8 bytes, no leading zero); the extra cap is
	// as_u64_fitting_long's Java-parity guard — the twins read this
	// field with Tuweni's SIGNED readLong, so the signed-overflow range
	// is refused on every engine (rlp.rs:66-77).
	nonce, err := rlpcode.U64(items[0])
	if err != nil {
		return nil, fmt.Errorf("account leaf: nonce: %v", err)
	}
	if nonce > uint64(math.MaxInt64) {
		return nil, fmt.Errorf("account leaf: nonce: RLP: integer %d exceeds signed-64 range", nonce)
	}
	balance, err := rlpcode.LeafBytes(items[1])
	if err != nil {
		return nil, fmt.Errorf("account leaf: %v", err)
	}
	if len(balance) > 0 && balance[0] == 0 {
		return nil, errors.New("account leaf: balance has leading zero byte")
	}
	sr, err := rlpcode.FixedBytes(items[2], 32)
	if err != nil {
		return nil, fmt.Errorf("account leaf: %v", err)
	}
	ch, err := rlpcode.FixedBytes(items[3], 32)
	if err != nil {
		return nil, fmt.Errorf("account leaf: %v", err)
	}
	var a AccountLeaf
	a.Nonce = nonce
	a.Balance = balance
	copy(a.StorageRoot[:], sr)
	copy(a.CodeHash[:], ch)
	return &a, nil
}

// DecodeStorageLeaf decodes a proof-verified storage leaf value:
// rlp(trimmed_uint256) — the minimal big-endian slot value (empty =
// zero), rejecting over-long and leading-zero encodings
// (trie.rs:200-212).
func DecodeStorageLeaf(value []byte) ([]byte, error) {
	b, err := rlpcode.LeafBytes(value)
	if err != nil {
		return nil, fmt.Errorf("storage leaf: %v", err)
	}
	if len(b) > 32 {
		return nil, fmt.Errorf("storage leaf: value is %d bytes (> 32)", len(b))
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, errors.New("storage leaf: value has leading zero byte")
	}
	return b, nil
}

// Keccak exposes the package's hash to sibling packages (snapwire checks
// code against its hash the same way) without each re-picking a sha3
// constructor.
func Keccak(b []byte) [32]byte { return keccak(b) }
