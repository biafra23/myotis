// Package snapwire is the eth/snap sub-protocol message layer: pure
// encode/decode of the range requests and their proofs, plus the
// verify-on-fetch functions that turn a decoded response into trusted
// state (verify.go). Go port of rust/myotis-wire/src/snap/
// {messages,fetch}.rs, twin of the Java networking.snap.messages
// package (docs/spec/02 §7), pinned against the shared corpus
// rust/testdata/el/snap/ the way the MPT verifier is pinned to
// el/mpt.
//
// Snap uses GetAccountRange/GetStorageRanges (which return full
// root-to-leaf boundary proofs), NOT GetTrieNodes. Message codes are
// DYNAMIC: base = 0x10 + eth_protocol_length — 0x21 for eth/67-68,
// 0x22 for eth/69-70, 0x24 for eth/71; see Codes/NegotiatedCodes.
//
// Scope cut vs the Rust twin (owner brief: minimal engine, reads only):
// the BlockAccessLists pair (EIP-7928/8189 — a syncing full node's
// concern) is not decoded here, and snap/1 vs snap/2 is invisible to
// this engine anyway: the pair 0x00-0x05 this engine ever sends is
// byte-for-byte identical across both versions.
package snapwire

import (
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/rlpcode"
)

// OurSnapVersions must match the snap capabilities in our RLPx HELLO
// (the transport's own pin, like Rust's encode_hello round-trip test).
var OurSnapVersions = []uint64{1, 2}

// Codes are the absolute wire codes for the snap messages, derived
// from the negotiated eth protocol length. Offsets from base are fixed
// by the snap spec and identical in snap/1 and snap/2.
type Codes struct {
	SnapVersion     uint64 // the negotiated snap version (1 or 2)
	GetAccountRange uint64
	AccountRange    uint64
	GetStorageRange uint64
	StorageRanges   uint64
	GetByteCodes    uint64
	ByteCodes       uint64
	GetTrieNodes    uint64 // snap/1 only — snap/2 (EIP-8189) removed the pair
	TrieNodes       uint64
}

// NegotiatedCodes derives the code table: base = 0x10 +
// eth_protocol_length. eth/67-68 has length 17 (base 0x21); eth/69
// adds BlockRangeUpdate → 18 (0x22); eth/70 changes no message count;
// eth/71 adds its BAL pair → 20 (0x24) (messages.rs:49-73).
func NegotiatedCodes(ethVersion, snapVersion uint64) Codes {
	var base uint64
	switch {
	case ethVersion <= 68:
		base = 0x21
	case ethVersion <= 70:
		base = 0x22
	default:
		base = 0x24
	}
	return Codes{
		SnapVersion:     snapVersion,
		GetAccountRange: base,
		AccountRange:    base + 1,
		GetStorageRange: base + 2,
		StorageRanges:   base + 3,
		GetByteCodes:    base + 4,
		ByteCodes:       base + 5,
		GetTrieNodes:    base + 6,
		TrieNodes:       base + 7,
	}
}

var fullLimitHash = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// EncodeGetAccountRange: [reqId, stateRoot, startingHash, limitHash,
// responseBytes]. For a single-account lookup pass starting =
// keccak256(address) and a small responseBytes — the peer still
// returns one account PLUS the complete boundary proof (doc 02 §7.3).
func EncodeGetAccountRange(requestID uint64, stateRoot, startingHash, limitHash [32]byte, responseBytes uint64) []byte {
	return rlpcode.List(
		rlpcode.Uint(requestID),
		rlpcode.Bytes(stateRoot[:]),
		rlpcode.Bytes(startingHash[:]),
		rlpcode.Bytes(limitHash[:]),
		rlpcode.Uint(responseBytes),
	)
}

// EncodeGetAccount is the single-account request over
// [keccak(addr), 0xff…ff].
func EncodeGetAccount(requestID uint64, stateRoot, accountHash [32]byte, responseBytes uint64) []byte {
	return EncodeGetAccountRange(requestID, stateRoot, accountHash, fullLimitHash, responseBytes)
}

// EncodeGetStorageRanges: [reqId, stateRoot, [accountHash],
// startingHash, limitHash, responseBytes] for a single account.
func EncodeGetStorageRanges(requestID uint64, stateRoot, accountHash, startingHash, limitHash [32]byte, responseBytes uint64) []byte {
	return rlpcode.List(
		rlpcode.Uint(requestID),
		rlpcode.Bytes(stateRoot[:]),
		rlpcode.List(rlpcode.Bytes(accountHash[:])),
		rlpcode.Bytes(startingHash[:]),
		rlpcode.Bytes(limitHash[:]),
		rlpcode.Uint(responseBytes),
	)
}

// EncodeGetStorageSlot is the single-slot request over
// [keccak(slot), 0xff…ff].
func EncodeGetStorageSlot(requestID uint64, stateRoot, accountHash, slotHash [32]byte, responseBytes uint64) []byte {
	return EncodeGetStorageRanges(requestID, stateRoot, accountHash, slotHash, fullLimitHash, responseBytes)
}

// EncodeGetByteCodes: [reqId, [codeHash, …], responseBytes].
func EncodeGetByteCodes(requestID uint64, hashes [][32]byte, responseBytes uint64) []byte {
	items := make([]rlp.RawValue, 0, len(hashes))
	for i := range hashes {
		items = append(items, rlpcode.Bytes(hashes[i][:]))
	}
	return rlpcode.List(
		rlpcode.Uint(requestID),
		rlpcode.List(items...),
		rlpcode.Uint(responseBytes),
	)
}

// EncodeEmptyRange: [reqId, [], []] — an empty AccountRange or
// StorageRanges response.
func EncodeEmptyRange(requestID uint64) []byte {
	return rlpcode.List(rlpcode.Uint(requestID), rlpcode.List(), rlpcode.List())
}

// EncodeEmptyCodes: [reqId, []] — an empty ByteCodes response.
func EncodeEmptyCodes(requestID uint64) []byte {
	return rlpcode.List(rlpcode.Uint(requestID), rlpcode.List())
}

// MaxRangeEntries is the most range entries (accounts, or one
// account's storage slots) a response keeps. We ask for a single key
// with a 4096-byte budget, and an entry is at least 35 bytes, so an
// honest answer holds a few dozen at most. Nothing in production reads
// the entries (the proof carries the verified value), so any past this
// are checked exactly as a kept one, and dropped (#454).
const MaxRangeEntries = 1024

// MaxProofNodes is the most proof nodes a range response may carry. A
// range proof is two root-to-leaf paths, each at most 65 nodes deep in
// a trie of 32-byte keys; this leaves room for a peer that sends more
// than it must, and refuses a list of millions of nodes before each is
// copied and hashed (#454).
const MaxProofNodes = 1024

// kept is how many elements of a response to a request for `requested`
// to keep: one more than asked for, so a caller still sees a peer that
// over-serves. Any further element is checked exactly as a kept one
// would be (verdict unchanged), just not kept (#454).
func kept(requested int) int {
	if requested == math.MaxInt {
		return math.MaxInt
	}
	return requested + 1
}

// SlimAccount is one entry of an AccountRange's slim bodies. THE
// PEER'S CLAIM — the trustworthy account comes from the MPT-verified
// proof leaf (README §11.8), so verify.go never reads these fields;
// they exist so the shape is decoded and checked, nothing more.
type SlimAccount struct {
	AccountHash [32]byte
	Nonce       uint64
	// Balance is minimal big-endian wei.
	Balance     []byte
	StorageRoot [32]byte
	CodeHash    [32]byte
}

// AccountRange is a decoded AccountRange response.
type AccountRange struct {
	RequestID uint64
	Accounts  []SlimAccount
	Proof     [][]byte
}

// DecodeAccountRange decodes [reqId, [[accountHash, slimBody], …],
// [proofNode, …]]. The WHOLE message is validated first
// (rlpcode.ValidateNode) so an entry past the keep-cap is checked
// exactly as a kept one, whatever the walk ends up reading.
func DecodeAccountRange(b []byte) (*AccountRange, error) {
	if err := rlpcode.ValidateNode(b); err != nil {
		return nil, err
	}
	items, err := rlpcode.Items(b)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("AccountRange: empty")
	}
	requestID, err := rlpcode.U64(items[0])
	if err != nil {
		return nil, err
	}
	out := &AccountRange{RequestID: requestID}
	// A non-list accounts field is skipped, and the PROOF still comes
	// from the third slot (the Rust iterator consumes field 2 either
	// way — messages.rs:156-176).
	if len(items) > 1 && isList(items[1]) {
		pairs, err := rlpcode.Items(items[1])
		if err != nil {
			return nil, err
		}
		for i, pair := range pairs {
			fields, err := rlpcode.Items(pair)
			if err != nil {
				return nil, err
			}
			if len(fields) < 2 {
				return nil, errors.New("AccountRange: malformed pair")
			}
			hash, err := rlpcode.FixedBytes(fields[0], 32)
			if err != nil {
				return nil, err
			}
			slim, err := readSlimFields(fields[1])
			if err != nil {
				return nil, err
			}
			if i < MaxRangeEntries {
				var h [32]byte
				copy(h[:], hash)
				slim.AccountHash = h
				out.Accounts = append(out.Accounts, *slim)
			}
		}
	}
	if len(items) > 2 {
		out.Proof, err = decodeProof(items[2])
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readSlimFields reads a slim account body: either a nested list
// [nonce, balance, root?, codeHash?] or a byte string wrapping that
// list's RLP (go-ethereum's []byte form). The nonce uses the plain
// ≤8-byte integer reader, NOT the signed-64-capped one — messages.rs
// reads it with as_u64; the capped reader is for proof-verified leaves.
func readSlimFields(body []byte) (*SlimAccount, error) {
	inner := body
	if !isList(body) {
		content, err := rlpcode.LeafBytes(body)
		if err != nil {
			return nil, err
		}
		inner = content
	}
	// The wrapped form is validated HERE (Rust's View::new on the
	// unwrapped bytes); re-validating the inline form is harmless.
	if err := rlpcode.ValidateNode(inner); err != nil {
		return nil, err
	}
	fields, err := rlpcode.Items(inner)
	if err != nil {
		return nil, err
	}
	var a SlimAccount
	if len(fields) > 0 {
		if a.Nonce, err = rlpcode.U64(fields[0]); err != nil {
			return nil, err
		}
	}
	if len(fields) > 1 {
		if a.Balance, err = rlpcode.LeafBytes(fields[1]); err != nil {
			return nil, err
		}
	}
	if a.StorageRoot, err = slimHash(field(fields, 2), &mpt.EmptyTrieRoot); err != nil {
		return nil, err
	}
	if a.CodeHash, err = slimHash(field(fields, 3), &mpt.EmptyCodeHash); err != nil {
		return nil, err
	}
	return &a, nil
}

// slimHash is a slim-encoded 32-byte hash: empty or absent defaults.
func slimHash(item []byte, def *[32]byte) ([32]byte, error) {
	var out [32]byte
	if item == nil {
		return *def, nil
	}
	b, err := rlpcode.LeafBytes(item)
	if err != nil {
		return out, err
	}
	switch len(b) {
	case 0:
		return *def, nil
	case 32:
		copy(out[:], b)
		return out, nil
	default:
		return out, fmt.Errorf("slim account: hash is %d bytes", len(b))
	}
}

// StorageSlot is one storage slot from the wire. INFORMATIONAL ONLY —
// the trusted value comes from the MPT proof (verify.go), never this
// field. NOTE the representation: the raw trie value
// `rlp(trimmed_uint256)`, one wire layer stripped by decoding — NOT
// the bare integer (the Rust twin's raw_trie_value, messages.rs:256-274).
type StorageSlot struct {
	SlotHash     [32]byte
	RawTrieValue []byte
}

// StorageRanges is a decoded StorageRanges response (first account
// only — we always query one account).
type StorageRanges struct {
	RequestID uint64
	Slots     []StorageSlot
	Proof     [][]byte
}

// DecodeStorageRanges decodes [reqId, [[slots-for-account-0], …],
// [proofNode, …]].
func DecodeStorageRanges(b []byte) (*StorageRanges, error) {
	if err := rlpcode.ValidateNode(b); err != nil {
		return nil, err
	}
	items, err := rlpcode.Items(b)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("StorageRanges: empty")
	}
	requestID, err := rlpcode.U64(items[0])
	if err != nil {
		return nil, err
	}
	out := &StorageRanges{RequestID: requestID}
	if len(items) > 1 && isList(items[1]) {
		perAccount, err := rlpcode.Items(items[1])
		if err != nil {
			return nil, err
		}
		if len(perAccount) > 0 && isList(perAccount[0]) {
			pairs, err := rlpcode.Items(perAccount[0])
			if err != nil {
				return nil, err
			}
			for i, pair := range pairs {
				fields, err := rlpcode.Items(pair)
				if err != nil {
					return nil, err
				}
				if len(fields) < 2 {
					return nil, errors.New("StorageRanges: malformed slot")
				}
				hash, err := rlpcode.FixedBytes(fields[0], 32)
				if err != nil {
					return nil, err
				}
				// fields[1] is the trie value: its bytes, one RLP
				// layer already stripped by the item read.
				value, err := rlpcode.LeafBytes(fields[1])
				if err != nil {
					return nil, err
				}
				if i < MaxRangeEntries {
					var h [32]byte
					copy(h[:], hash)
					out.Slots = append(out.Slots, StorageSlot{SlotHash: h, RawTrieValue: value})
				}
			}
		}
	}
	if len(items) > 2 {
		out.Proof, err = decodeProof(items[2])
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeByteCodes decodes [reqId, [bytecode, …]] for a request of
// `requested` code hashes. A peer answers in request order and may
// send fewer; at most one more than asked for is kept, and any
// further one is checked but not kept (#454). The caller hashes each
// code and matches it against the requested codeHash (VerifyBytecode).
func DecodeByteCodes(b []byte, requested int) (uint64, [][]byte, error) {
	if err := rlpcode.ValidateNode(b); err != nil {
		return 0, nil, err
	}
	items, err := rlpcode.Items(b)
	if err != nil {
		return 0, nil, err
	}
	if len(items) == 0 {
		return 0, nil, errors.New("ByteCodes: empty")
	}
	requestID, err := rlpcode.U64(items[0])
	if err != nil {
		return 0, nil, err
	}
	var codes [][]byte
	if len(items) > 1 && isList(items[1]) {
		list, err := rlpcode.Items(items[1])
		if err != nil {
			return 0, nil, err
		}
		for i, c := range list {
			code, err := rlpcode.LeafBytes(c) // a list where a code must be fails, kept or dropped
			if err != nil {
				return 0, nil, err
			}
			if i < kept(requested) {
				codes = append(codes, code)
			}
		}
	}
	return requestID, codes, nil
}

// decodeProof returns the byte-string nodes of a proof list (list
// elements are skipped), refusing more than MaxProofNodes.
func decodeProof(item []byte) ([][]byte, error) {
	if item == nil || !isList(item) {
		return nil, nil
	}
	nodes, err := rlpcode.Items(item)
	if err != nil {
		return nil, err
	}
	if len(nodes) > MaxProofNodes {
		return nil, fmt.Errorf("proof has more than %d nodes", MaxProofNodes)
	}
	var out [][]byte
	for _, n := range nodes {
		if b, err := rlpcode.LeafBytes(n); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

func isList(item []byte) bool {
	kind, _, _, err := rlp.Split(item)
	return err == nil && kind == rlp.List
}

func field(items [][]byte, i int) []byte {
	if i < len(items) {
		return items[i]
	}
	return nil
}
