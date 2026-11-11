package mpt

// Unit tests ported from rust/myotis-core/src/trie.rs's test module,
// plus the replay of the shared cross-language corpus
// rust/testdata/el/mpt/ against its single expected.txt — the same
// discipline as the RLPx (part 2) and LC (part 3) conformance tests:
// one set of vectors, every engine reproduces the same verdicts. The
// corpus pins the mpt.* keys; the triehash.*/bloom.* pins belong to
// geth's trie package and Java's OrderedTrieRoot — the Go engine
// reuses geth there (docs/spec/README §7), so nothing here re-pins
// them.

import (
	"bufio"
	"encoding/hex"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"sort"

	"github.com/ethereum/go-ethereum/rlp"
	"strconv"
	"strings"
	"testing"

	"github.com/biafra23/myotis/go/internal/rlpcode"
)

// leafNode builds RLP([hexprefix(nibbles, leaf), value]) — trie.rs
// tests' leaf_node.
func leafNode(t *testing.T, nibbles []byte, value []byte) []byte {
	t.Helper()
	enc, err := hexPrefixEncodeChecked(nibbles, true)
	if err != nil {
		t.Fatal(err)
	}
	return rlpcode.List(rlpcode.Bytes(enc), rlpcode.Bytes(value))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSingleLeafFoundAndExcluded(t *testing.T) {
	key := []byte{0xab, 0xcd}
	value := []byte("myotis-value")
	node := leafNode(t, toNibbles(key), value)
	root := keccak(node)
	r := VerifyProof(root, key, [][]byte{node})
	if r.Status != Found || string(r.Value) != "myotis-value" {
		t.Fatalf("want found(myotis-value), got %v %q", r.Status, r.Value)
	}
	// Different key under the same root: leaf path diverges → Absent.
	if r := VerifyProof(root, []byte{0xab, 0xce}, [][]byte{node}); r.Status != Absent {
		t.Fatalf("want absent, got %v", r.Status)
	}
}

func TestEmptyTrieAndEmptyProof(t *testing.T) {
	if r := VerifyProof(EmptyTrieRoot, []byte{0x01}, nil); r.Status != Absent {
		t.Fatalf("want absent, got %v", r.Status)
	}
	r := VerifyProof([32]byte{0x11}, []byte{0x01}, nil)
	if r.Status != Invalid || r.Reason != "empty proof for non-empty root" {
		t.Fatalf("want invalid(empty proof for non-empty root), got %v %q", r.Status, r.Reason)
	}
	if r := VerifyProof(EmptyTrieRoot, nil, nil); r.Status != Invalid {
		t.Fatalf("empty key: want invalid, got %v", r.Status)
	}
}

func TestMissingNodeIsInvalid(t *testing.T) {
	node := leafNode(t, toNibbles([]byte{0x01}), []byte("v"))
	root := keccak(node)
	other := leafNode(t, toNibbles([]byte{0x02}), []byte("w"))
	if r := VerifyProof(root, []byte{0x01}, [][]byte{other}); r.Status != Invalid {
		t.Fatalf("want invalid, got %v", r.Status)
	}
}

// twoLeafTrie: a root branch over two hashed leaves (path nibble 1 and
// 2), leaves keyed by 31 remaining bytes so each leaf node exceeds 32
// bytes and is referenced by hash.
func twoLeafTrie(t *testing.T) ([32]byte, []byte, []byte, []byte) {
	t.Helper()
	leafA := leafNode(t, toNibbles(bytes32(0x11))[1:], bytesRepeat(0xaa, 40))
	leafB := leafNode(t, toNibbles(bytes32(0x22))[1:], bytesRepeat(0xbb, 40))
	items := make([]rlp.RawValue, 17)
	for i := range items {
		items[i] = rlpcode.Bytes(nil)
	}
	items[1] = rlpcode.Bytes(keccakSlice(leafA))
	items[2] = rlpcode.Bytes(keccakSlice(leafB))
	branch := rlpcode.List(items...)
	return keccak(branch), branch, leafA, leafB
}

func TestTwoLeafBranchWalk(t *testing.T) {
	root, branch, leafA, leafB := twoLeafTrie(t)
	// Out of order, with the neighbour's leaf in the set — a snap range
	// proof's shape; the by-hash index must not care.
	set := [][]byte{leafB, leafA, branch}
	r := VerifyProof(root, bytes32(0x11), set)
	if r.Status != Found || !equalBytes(r.Value, bytesRepeat(0xaa, 40)) {
		t.Fatalf("want found(aa*40), got %v %x", r.Status, r.Value)
	}
	// Exclusion: the walk ends at the branch's empty child, and the
	// branch alone proves it.
	if r := VerifyProof(root, bytes32(0x33), set); r.Status != Absent {
		t.Fatalf("want absent, got %v", r.Status)
	}
	// Without the referenced leaf the walk cannot complete.
	if r := VerifyProof(root, bytes32(0x11), [][]byte{branch}); r.Status != Invalid {
		t.Fatalf("want invalid, got %v", r.Status)
	}
}

func TestEmbeddedLeafFound(t *testing.T) {
	// Tiny leaves (< 32 bytes) are embedded in the branch, not listed.
	items := make([]rlp.RawValue, 17)
	for i := range items {
		items[i] = rlpcode.Bytes(nil)
	}
	items[1] = rlpcode.List(rlpcode.Bytes(hexPrefixEncode([]byte{0xa}, true)), rlpcode.Bytes([]byte("v1")))
	items[2] = rlpcode.List(rlpcode.Bytes(hexPrefixEncode([]byte{0xb}, true)), rlpcode.Bytes([]byte("v2")))
	branch := rlpcode.List(items...)
	root := keccak(branch)
	r := VerifyProof(root, []byte{0x1a}, [][]byte{branch})
	if r.Status != Found || string(r.Value) != "v1" {
		t.Fatalf("want found(v1), got %v %q", r.Status, r.Value)
	}
}

func TestHexPrefixRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		nibbles []byte
		leaf    bool
	}{
		{nil, false},
		{[]byte{1}, true},
		{[]byte{1, 2, 3}, false},
		{[]byte{0xf, 0xe, 0xd, 0xc}, true},
	} {
		enc := hexPrefixEncode(tc.nibbles, tc.leaf)
		leaf, nibbles, err := hexPrefixDecode(enc)
		if err != nil || leaf != tc.leaf || !equalBytes(nibbles, tc.nibbles) {
			t.Fatalf("round trip %v/%v → %v %v %v", tc.nibbles, tc.leaf, leaf, nibbles, err)
		}
	}
	if _, _, err := hexPrefixDecode(nil); err == nil {
		t.Fatal("empty path must error")
	}
	if _, _, err := hexPrefixDecode([]byte{0x40}); err == nil {
		t.Fatal("flag nibble 4 must error")
	}
}

func TestAccountAndStorageLeafDecode(t *testing.T) {
	// [nonce=7, balance=0x0de0b6b3a7640000 (1 ETH), storageRoot, codeHash]
	balance := []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}
	leaf := rlpcode.List(
		rlpcode.Bytes([]byte{7}),
		rlpcode.Bytes(balance),
		rlpcode.Bytes(EmptyTrieRoot[:]),
		rlpcode.Bytes(EmptyCodeHash[:]),
	)
	a, err := DecodeAccountLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce != 7 || !equalBytes(a.Balance, balance) || a.StorageRoot != EmptyTrieRoot || a.CodeHash != EmptyCodeHash {
		t.Fatalf("decoded %+v", a)
	}
	if _, err := DecodeAccountLeaf([]byte("junk")); err == nil {
		t.Fatal("junk must error")
	}
	// The Java-parity nonce cap: 0xffffffffffffffff decodes as u64 but
	// goes SIGNED-negative under Tuweni readLong — refused (rlp.rs:66-77).
	big := rlpcode.List(
		rlpcode.Bytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		rlpcode.Bytes(nil),
		rlpcode.Bytes(EmptyTrieRoot[:]),
		rlpcode.Bytes(EmptyCodeHash[:]),
	)
	if _, err := DecodeAccountLeaf(big); err == nil || !strings.Contains(err.Error(), "signed-64") {
		t.Fatalf("want signed-64 refusal, got %v", err)
	}

	slot := rlpcode.Bytes([]byte{0x2a})
	if v, err := DecodeStorageLeaf(slot); err != nil || !equalBytes(v, []byte{0x2a}) {
		t.Fatalf("slot: %x %v", v, err)
	}
	if v, err := DecodeStorageLeaf(rlpcode.Bytes(nil)); err != nil || len(v) != 0 {
		t.Fatalf("empty slot: %x %v", v, err)
	}
	if _, err := DecodeStorageLeaf(rlpcode.Bytes([]byte{0x00, 0x01})); err == nil {
		t.Fatal("leading zero must error")
	}
	if _, err := DecodeStorageLeaf(rlpcode.Bytes(bytesRepeat(0x11, 33))); err == nil {
		t.Fatal("33-byte value must error")
	}
}

func TestValidateNodeStrictness(t *testing.T) {
	// Depth boundary, long-form wrapped chain (rlp.rs test lines
	// 839-846 — the c1-chain form of that test dies on element-overrun
	// long before depth, so real depth needs proper wrapping): the
	// innermost item sits at depth = number of wrappers, refused at 33.
	chain := func(n int) []byte {
		cur := bytesRepeat(0x01, 56)
		for i := 0; i < n; i++ {
			cur = append([]byte{0xf8, byte(len(cur))}, cur...)
		}
		return cur
	}
	if err := rlpcode.ValidateNode(chain(32)); err != nil {
		t.Fatalf("32-deep must pass: %v", err)
	}
	if err := rlpcode.ValidateNode(chain(33)); err == nil {
		t.Fatal("33-deep must be refused")
	}
	// Non-canonical single byte: 0x81 0x05 must be 0x05.
	if err := rlpcode.ValidateNode([]byte{0x81, 0x05}); err == nil {
		t.Fatal("8105 must be refused")
	}
	// Trailing bytes after the top-level item.
	if err := rlpcode.ValidateNode([]byte{0x05, 0x06}); err == nil {
		t.Fatal("trailing byte must be refused")
	}
	// The MAX short list (0xf7 = 55-byte payload) is CANONICAL, not a
	// long-form abuse — corpus vector 001 uses exactly this shape.
	node := leafNode(t, toNibbles(bytes32(0xaa)), []byte("myotis-account-value"))
	if node[0] != 0xf7 {
		t.Fatalf("test fixture should exercise the 0xf7 max-short-list form, got %02x", node[0])
	}
	if err := rlpcode.ValidateNode(node); err != nil {
		t.Fatalf("0xf7 short list must pass: %v", err)
	}
	// Long element overrunning its list container (corpus 084's shape).
	if err := rlpcode.ValidateNode([]byte{0xc2, 0x83, 0x01}); err == nil {
		t.Fatal("element overrun must be refused")
	}
}

func TestValidateNodeFuzzNoPanic(t *testing.T) {
	// The Rust fuzz corpus doubles as a no-panic contract: random bytes,
	// truncated and mutated, must yield a verdict or an error, never a
	// crash or a hang.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		n := rng.Intn(48)
		b := make([]byte, n)
		rng.Read(b)
		if err := rlpcode.ValidateNode(b); err != nil {
			continue
		}
		root := [32]byte{}
		copy(root[:], b)
		VerifyProof(root, b, [][]byte{b, append([]byte{}, b...)})
	}
}

// --- corpus replay -----------------------------------------------------

func TestCorpusReplay(t *testing.T) {
	corpus := filepath.Join("..", "..", "..", "rust", "testdata", "el", "mpt")
	if _, err := os.Stat(corpus); err != nil {
		t.Skipf("el/mpt conformance corpus not present at %s: %v", corpus, err)
	}
	expected := map[string]string{}
	f, err := os.Open(filepath.Join(corpus, "expected.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			expected[line[:i]] = line[i+1:]
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	names, err := filepath.Glob(filepath.Join(corpus, "[0-9][0-9][0-9]-proof-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no proof vectors found")
	}

	actual := map[string]string{}
	for _, p := range names {
		base := strings.TrimSuffix(filepath.Base(p), ".txt")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, l := range strings.Split(string(raw), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		root := mustHex(t, lines[0])
		key := mustHex(t, lines[1])
		var nodes [][]byte
		for _, l := range lines[2:] {
			nodes = append(nodes, mustHex(t, l))
		}
		var rootArr [32]byte
		copy(rootArr[:], root)

		k := "mpt." + base
		r := VerifyProof(rootArr, key, nodes)
		switch r.Status {
		case Found:
			actual[k+".result"] = "found"
			actual[k+".value"] = hex.EncodeToString(r.Value)
			// Leaf-decode pins for the realistic vectors — the same
			// base-name rule as the Java and Rust tests (keep in
			// lockstep). Numbers go through big.Int so the strings match
			// Java's BigInteger.toString(16) exactly.
			if strings.Contains(base, "account") {
				a, err := DecodeAccountLeaf(r.Value)
				if err != nil {
					t.Fatalf("%s: decode account leaf: %v", base, err)
				}
				actual[k+".account.nonce"] = strconv.FormatUint(a.Nonce, 10)
				actual[k+".account.balance"] = new(big.Int).SetBytes(a.Balance).Text(16)
				actual[k+".account.storageRoot"] = hex.EncodeToString(a.StorageRoot[:])
				actual[k+".account.codeHash"] = hex.EncodeToString(a.CodeHash[:])
			}
			if strings.Contains(base, "storage-leaf") {
				v, err := DecodeStorageLeaf(r.Value)
				if err != nil {
					t.Fatalf("%s: decode storage leaf: %v", base, err)
				}
				actual[k+".storage.value"] = new(big.Int).SetBytes(v).Text(16)
			}
		case Absent:
			actual[k+".result"] = "absent"
		case Invalid:
			actual[k+".result"] = "invalid"
		}
	}

	for key, want := range expected {
		if !strings.HasPrefix(key, "mpt.") {
			continue // triehash.*/bloom.* are geth/Javam's pins, see header
		}
		got, ok := actual[key]
		if !ok {
			t.Errorf("corpus missing key %s (want %s)", key, want)
			continue
		}
		if got != want {
			t.Errorf("%s: want %q, got %q", key, want, got)
		}
	}
	for key, got := range actual {
		if _, ok := expected[key]; !ok {
			t.Errorf("%s: unexpected key produced (got %q) — expected.txt out of date?", key, got)
		}
	}
}

// --- small helpers -----------------------------------------------------

func hexPrefixEncodeChecked(nibbles []byte, leaf bool) ([]byte, error) {
	return hexPrefixEncode(nibbles, leaf), nil
}

func keccakSlice(b []byte) []byte {
	h := keccak(b)
	return h[:]
}

func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

func bytesRepeat(fill byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
