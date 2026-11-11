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

// The versions we speak live with the HELLO encoder (ethwire
// OurSnapVersions) — one definition, like the Rust pin between
// OUR_SNAP_VERSIONS and encode_hello.

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
// eth_protocol_length. eth/69 adds BlockRangeUpdate → 18 (0x22);
// eth/70 changes no message count; eth/71 adds its BAL pair → 20
// (0x24) (messages.rs:49-73).
//
// eth/66 shares eth/67-68's 17-message lineup (base 0x21) — decided
// here, noted on PR review against the real-world geth table where
// eth/66 measures 15. docs/spec/02 §6.3 lists ONE absolute lineup for
// the whole advertised range eth/66-71 (`0x10 Status … 0x20
// Receipts` = 17 messages), and §7.1 introduces new counts only from
// eth/69 ("adds BlockRangeUpdate 0x11") — if 66 measured 15, that
// sentence would name 67 as the bump. This is the spec's protocol,
// not historical geth's; all three engines implement `≤68 → 0x21`
// (Java golden, Rust `..=68 => 0x21`, Go here), so the ladder is
// cross-engine policy, not a Go slip. If the spec ever gives eth/66
// its own count, change all three together.
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

// FullLimitHash is the "no upper bound" limit hash for range requests
// (0xff…ff). Exported so readers and tests share ONE copy of the value
// the request encoders actually send.
var FullLimitHash = [32]byte{
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
	return EncodeGetAccountRange(requestID, stateRoot, accountHash, FullLimitHash, responseBytes)
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
	return EncodeGetStorageRanges(requestID, stateRoot, accountHash, slotHash, FullLimitHash, responseBytes)
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

// headItems reads the (up to) first n items of an already-validated
// list WITHOUT materializing the rest. A hostile list — ten million
// one-byte items inside the 10 MiB frame cap — is walked in O(n)
// memory, which rlpcode.Items (one slice header per element, all of
// them) is not: that is the #454 allocation lesson ethwire's
// DecodeBlockHeaders already applies. Extra items past n are skipped,
// as the Rust View consumers skip positional fields they do not read.
func headItems(b []byte, n int) (items [][]byte, err error) {
	kind, content, rest, err := rlp.Split(b)
	if err != nil {
		return nil, err
	}
	if kind != rlp.List {
		return nil, errors.New("expected list")
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after list")
	}
	for len(content) > 0 && len(items) < n {
		it, next, err := rlpcode.SplitItem(content)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
		content = next
	}
	return items, nil
}

// eachItem streams the elements of an already-validated list, calling
// fn(index, item) with NO intermediate slice (#454: a multi-MiB list
// of one-byte items must not become a multi-hundred-MB [][]byte
// before the first per-entry check runs).
func eachItem(list []byte, fn func(i int, item []byte) error) error {
	kind, content, rest, err := rlp.Split(list)
	if err != nil {
		return err
	}
	if kind != rlp.List {
		return errors.New("expected list")
	}
	if len(rest) != 0 {
		return errors.New("trailing bytes after list")
	}
	for i := 0; len(content) > 0; i++ {
		it, next, err := rlpcode.SplitItem(content)
		if err != nil {
			return err
		}
		if err := fn(i, it); err != nil {
			return err
		}
		content = next
	}
	return nil
}

// DecodeAccountRange decodes [reqId, [[accountHash, slimBody], …],
// [proofNode, …]]. The WHOLE message is validated first
// (rlpcode.ValidateNode) so an entry past the keep-cap is checked
// exactly as a kept one, whatever the walk ends up reading — and the
// entries are then STREAMED (eachItem), so "checked but dropped" costs
// no allocation (#454; ValidateNode's full-message walk is what does
// the checking, exactly as the Rust ViewIter consumes without cloning
// past the cap).
func DecodeAccountRange(b []byte) (*AccountRange, error) {
	if err := rlpcode.ValidateNode(b); err != nil {
		return nil, err
	}
	items, err := headItems(b, 3)
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
		err := eachItem(items[1], func(_ int, pair []byte) error {
			fields, err := headItems(pair, 2) // the pair's tail, if any, is not read
			if err != nil {
				return err
			}
			if len(fields) < 2 {
				return errors.New("AccountRange: malformed pair")
			}
			hash, err := rlpcode.FixedBytes(fields[0], 32)
			if err != nil {
				return err
			}
			slim, err := readSlimFields(fields[1])
			if err != nil {
				return err
			}
			if len(out.Accounts) < MaxRangeEntries {
				var h [32]byte
				copy(h[:], hash)
				slim.AccountHash = h
				out.Accounts = append(out.Accounts, *slim)
			}
			return nil
		})
		if err != nil {
			return nil, err
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
	// Four fields are the whole slim shape; a hostile long tail is
	// skipped positionally (headItems), not materialized (#454).
	fields, err := headItems(inner, 4)
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
// [proofNode, …]]. Peer-controlled lists (per-account, slots, proof)
// are streamed — headItems/eachItem — never materialized whole: a
// 10 MiB frame of one-byte items must not become hundreds of MB of
// slice headers before the first check runs (#454).
func DecodeStorageRanges(b []byte) (*StorageRanges, error) {
	if err := rlpcode.ValidateNode(b); err != nil {
		return nil, err
	}
	items, err := headItems(b, 3)
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
		// One account per ask, always: only the FIRST account's slot
		// list is read; further ones are skipped positionally, exactly
		// as the Rust consumer skips accounts it did not query.
		perAccount, err := headItems(items[1], 1)
		if err != nil {
			return nil, err
		}
		if len(perAccount) > 0 && isList(perAccount[0]) {
			err := eachItem(perAccount[0], func(_ int, pair []byte) error {
				fields, err := headItems(pair, 2)
				if err != nil {
					return err
				}
				if len(fields) < 2 {
					return errors.New("StorageRanges: malformed slot")
				}
				hash, err := rlpcode.FixedBytes(fields[0], 32)
				if err != nil {
					return err
				}
				// fields[1] is the trie value: its bytes, one RLP
				// layer already stripped by the item read.
				value, err := rlpcode.LeafBytes(fields[1])
				if err != nil {
					return err
				}
				if len(out.Slots) < MaxRangeEntries {
					var h [32]byte
					copy(h[:], hash)
					out.Slots = append(out.Slots, StorageSlot{SlotHash: h, RawTrieValue: value})
				}
				return nil
			})
			if err != nil {
				return nil, err
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
	items, err := headItems(b, 2)
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
		err := eachItem(items[1], func(i int, c []byte) error {
			code, err := rlpcode.LeafBytes(c) // a list where a code must be fails, kept or dropped
			if err != nil {
				return err
			}
			if i < kept(requested) {
				codes = append(codes, code)
			}
			return nil
		})
		if err != nil {
			return 0, nil, err
		}
	}
	return requestID, codes, nil
}

// decodeProof returns the byte-string nodes of a proof list (list
// elements are skipped), refusing more than MaxProofNodes. The cap
// fires DURING the stream, not after materializing the whole list:
// the million-node case must fail at node 1025 with O(1024) memory,
// which is what the cap's comment promises (#454).
func decodeProof(item []byte) ([][]byte, error) {
	if item == nil || !isList(item) {
		return nil, nil
	}
	var out [][]byte
	err := eachItem(item, func(i int, n []byte) error {
		if i >= MaxProofNodes {
			return fmt.Errorf("proof has more than %d nodes", MaxProofNodes)
		}
		if b, err := rlpcode.LeafBytes(n); err == nil {
			out = append(out, b)
		}
		return nil
	})
	if err != nil {
		return nil, err
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
