// Package mpt verifies Merkle-Patricia proofs against a trusted root —
// the state trust anchor for SNAP-served data (docs/spec/03 §2). Go port
// of rust/myotis-core/src/trie.rs (itself the twin of the Java
// MerklePatriciaProofVerifier + HexPrefix), pinned cross-language by the
// shared corpus rust/testdata/el/mpt/ the same way parts 2–3 pin RLPx
// and the LC processor.
//
// Like the Rust twin the walk is ITERATIVE and total: a hostile proof
// chaining zero-nibble extension nodes must neither grow the stack nor
// loop, and Invalid is the only error channel (the functions here never
// panic and VerifyProof never returns an error — an outcome is always
// Found / Absent / Invalid with a reason).
package mpt

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/biafra23/myotis/go/internal/rlpcode"
)

// EmptyTrieRoot = keccak256(rlp("")) — the conventional root of the
// empty trie; EmptyCodeHash = keccak256("") — an account with no code.
// (Literals from trie.rs:22-34; they cannot be derived at const time.)
var (
	EmptyTrieRoot = [32]byte{
		0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
		0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
		0xb4, 0x21,
	}
	EmptyCodeHash = [32]byte{
		0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
		0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
		0xa4, 0x70,
	}
)

type Status int

const (
	Found Status = iota
	Absent
	Invalid
)

func (s Status) String() string {
	switch s {
	case Found:
		return "found"
	case Absent:
		return "absent"
	default:
		return "invalid"
	}
}

// Result is one verification outcome. Reason is set only for Invalid,
// and the strings match the Rust twin verbatim — they are the
// classification channel the reader's PrunedRoot-vs-BadProof taxonomy
// is built from (fetch.rs PROOF_INVALID_MARKER / UNKNOWN_ROOT_REASON),
// so the "empty proof for non-empty root" wording is load-bearing.
type Result struct {
	Status Status
	Value  []byte
	Reason string
}

func found(v []byte) Result   { return Result{Status: Found, Value: v} }
func absent() Result          { return Result{Status: Absent} }
func invalid(r string) Result { return Result{Status: Invalid, Reason: r} }

func keccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyProof walks a proof for key under a trusted root. key is the
// raw trie key — for the state trie keccak256(address), for a storage
// trie keccak256(slot32); the verifier only splits to nibbles. A snap
// range proof's left-boundary path IS a single-key Merkle proof for the
// origin, so this is what the account/storage reads verify with
// (fetch.rs:74-76); unused nodes (second boundary, neighbours) are
// simply not visited.
func VerifyProof(root [32]byte, key []byte, proofNodes [][]byte) Result {
	if len(key) == 0 {
		return invalid("empty key")
	}
	if len(proofNodes) == 0 {
		// The empty trie has a well-known root: with no nodes we may
		// assert absence only if the root says the trie is empty.
		if root == EmptyTrieRoot {
			return absent()
		}
		return invalid("empty proof for non-empty root")
	}

	// Index by keccak256 so descent picks the next node by hash match:
	// tolerates out-of-order node lists (fetch.rs:95-100).
	byHash := make(map[[32]byte][]byte, len(proofNodes))
	for _, n := range proofNodes {
		byHash[keccak(n)] = n
	}

	path := toNibbles(key)

	// Iterative descent with a structural termination bound: one walk
	// visits each supplied node AT MOST once — revisiting would require
	// a keccak cycle, which no proof (honest or hostile) constructs;
	// the counter makes termination not rest on that argument
	// (trie.rs:107-112). Embedded in-node descent is bounded by the
	// node's own finite RLP depth.
	expected := root
	idx := 0
	lookups := 0
	for {
		lookups++
		if lookups > len(byHash) {
			return invalid("proof walk exceeded the supplied node count (cycle)")
		}
		nodeRLP, ok := byHash[expected]
		if !ok {
			return invalid(fmt.Sprintf("missing node %s (path idx=%d)",
				hex.EncodeToString(expected[:]), idx))
		}
		// Validate the WHOLE node once, here, before interpreting any of
		// it — the Rust twin decodes the full item tree at this point
		// (walk's rlp::decode, trie.rs:132-136), so a malformed slot the
		// walk would never visit still invalidates the proof (corpus
		// 084), and deep nesting fails on the RLP cap, not the stack.
		// Embedded children need no re-validation: they were validated
		// as part of their parent.
		if err := rlpcode.ValidateNode(nodeRLP); err != nil {
			return invalid("malformed node RLP: " + err.Error())
		}
		// Interpret this node, following embedded (<32-byte) children
		// in-line until we terminate or reach the next hash reference.
		current := nodeRLP
	descend:
		for {
			st := interpret(current, path, idx)
			switch st.kind {
			case stepDone:
				return st.result
			case stepHash:
				expected = st.hash
				idx = st.idx
				break descend // back to the by-hash lookup
			case stepEmbedded:
				current = st.child
				idx = st.idx
			}
		}
	}
}

type stepKind int

const (
	stepDone stepKind = iota
	stepHash
	stepEmbedded
)

// step is one descent decision: terminate with a result, descend to the
// node with this hash, or descend into an embedded (<32-byte) child
// carried inside the current node (a raw item slice IS its own RLP
// encoding, so the child rides as bytes — the Rust Step::Embedded's
// decoded Item, in wire form).
type step struct {
	kind   stepKind
	hash   [32]byte
	child  []byte
	idx    int
	result Result
}

// interpret decodes one node and decides the descent step. current is
// the RAW bytes of the node (or embedded child), so a list child keeps
// its exact encoding — the Java-parity passthrough (a Found value that
// is a list is returned as its RLP bytes) is just "return the item's
// bytes", because a raw item slice IS its own RLP encoding.
func interpret(current []byte, path []byte, idx int) step {
	items, err := rlpList(current)
	if err != nil {
		return step{kind: stepDone, result: invalid("malformed node RLP: expected list")}
	}
	switch len(items) {
	case 17:
		return interpretBranch(items, path, idx)
	case 2:
		return interpretShort(items, path, idx)
	default:
		return step{kind: stepDone, result: invalid(fmt.Sprintf("unexpected node arity: %d", len(items)))}
	}
}

// interpretBranch: 16 child slots + a value slot at index 16.
func interpretBranch(items [][]byte, path []byte, idx int) step {
	if idx == len(path) {
		// Path exhausted; the value lives at slot 16. Empty bytes →
		// absent; any other item (bytes or list) → found with the
		// item's own RLP bytes (Java passthrough parity).
		kind, content, list := classifyItem(items[16])
		switch {
		case list:
			return step{kind: stepDone, result: found(items[16])}
		case kind == kindBytes && len(content) == 0:
			return step{kind: stepDone, result: absent()}
		case kind == kindBytes:
			return step{kind: stepDone, result: found(content)}
		default:
			return step{kind: stepDone, result: invalid("branch value slot is not a value")}
		}
	}
	nibble := int(path[idx] & 0x0f)
	kind, content, list := classifyItem(items[nibble])
	switch {
	case list:
		return step{kind: stepEmbedded, child: items[nibble], idx: idx + 1}
	case kind == kindBytes && len(content) == 0:
		return step{kind: stepDone, result: absent()}
	case kind == kindBytes && len(content) == 32:
		var h [32]byte
		copy(h[:], content)
		return step{kind: stepHash, hash: h, idx: idx + 1}
	default:
		return step{kind: stepDone, result: invalid(fmt.Sprintf(
			"branch child %d is %d bytes; expected 32-byte hash or embedded list", nibble, len(content)))}
	}
}

// interpretShort: leaf or extension — encoded path + value/child.
func interpretShort(items [][]byte, path []byte, idx int) step {
	kind, encPath, list := classifyItem(items[0])
	if kind != kindBytes || list {
		return step{kind: stepDone, result: invalid("bad hex-prefix path: not a byte string")}
	}
	leaf, nodeNibbles, err := hexPrefixDecode(encPath)
	if err != nil {
		return step{kind: stepDone, result: invalid("bad hex-prefix path: " + err.Error())}
	}
	// The remaining path must start with the node's nibbles, else the
	// queried key cannot live below this node — a valid exclusion.
	remaining := len(path) - idx
	if len(nodeNibbles) > remaining || !nibblesEqual(nodeNibbles, path[idx:idx+len(nodeNibbles)]) {
		return step{kind: stepDone, result: absent()}
	}
	newIdx := idx + len(nodeNibbles)
	if leaf {
		if newIdx != len(path) {
			// Leaf ends the key here but our path has more nibbles: a
			// different key lives here.
			return step{kind: stepDone, result: absent()}
		}
		k, content, l := classifyItem(items[1])
		switch {
		case l:
			return step{kind: stepDone, result: found(items[1])} // Java passthrough parity
		case k == kindBytes:
			return step{kind: stepDone, result: found(content)}
		default:
			return step{kind: stepDone, result: invalid("leaf value is not a value")}
		}
	}
	// Extension: descend.
	k, content, l := classifyItem(items[1])
	switch {
	case l:
		return step{kind: stepEmbedded, child: items[1], idx: newIdx}
	case k == kindBytes && len(content) == 32:
		var h [32]byte
		copy(h[:], content)
		return step{kind: stepHash, hash: h, idx: newIdx}
	default:
		return step{kind: stepDone, result: invalid(fmt.Sprintf(
			"extension child is %d bytes; expected 32-byte hash or embedded list", len(content)))}
	}
}

func nibblesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		// path bytes hold one nibble each (low 4 bits); mask like the
		// Rust index does on read, not here — toNibbles already emits
		// one nibble per byte.
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
