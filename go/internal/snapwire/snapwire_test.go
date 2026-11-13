package snapwire

// Unit tests ported from rust/myotis-wire/src/snap/{messages,fetch}.rs
// plus the replay of rust/testdata/el/snap/ against the expected.txt
// the Java test records — the strong pin: Go decodes Java's committed
// AccountRange/StorageRanges message bytes and runs the verify-on-fetch
// path against the committed roots, and the proof-verified fields must
// match Java's verdicts byte-for-byte.

import (
	"bufio"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/rlpcode"
)

func TestNegotiatedCodes(t *testing.T) {
	if c := NegotiatedCodes(68, 1); c.GetAccountRange != 0x21 || c.ByteCodes != 0x26 {
		t.Fatalf("eth/68: %+v", c)
	}
	if c := NegotiatedCodes(69, 1); c.GetAccountRange != 0x22 || c.ByteCodes != 0x27 {
		t.Fatalf("eth/69: %+v", c)
	}
	// snap/2 keeps 0x00-0x05 where they were — the read path is
	// version-blind. eth/70 adds no message; eth/71's BAL pair pushes
	// snap to 0x24.
	if c := NegotiatedCodes(70, 2); c.GetAccountRange != 0x22 {
		t.Fatalf("eth/70: %+v", c)
	}
	if c := NegotiatedCodes(71, 2); c.GetAccountRange != 0x24 {
		t.Fatalf("eth/71: %+v", c)
	}
	for _, eth := range []uint64{68, 69, 70, 71} {
		v1, v2 := NegotiatedCodes(eth, 1), NegotiatedCodes(eth, 2)
		if v2.GetAccountRange != v1.GetAccountRange || v2.StorageRanges != v1.StorageRanges || v2.ByteCodes != v1.ByteCodes {
			t.Fatalf("eth/%d: snap/2 moved the read-path codes", eth)
		}
	}
}

func TestGetAccountRangeEncoding(t *testing.T) {
	root := keccak([]byte("state"))
	acct := keccak([]byte("addr"))
	msg := EncodeGetAccount(7, root, acct, 4096)
	items, err := rlpcode.Items(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 {
		t.Fatalf("want 5 fields, got %d", len(items))
	}
	if id, _ := rlpcode.U64(items[0]); id != 7 {
		t.Fatalf("reqId %d", id)
	}
	if b, _ := rlpcode.FixedBytes(items[1], 32); !equal(b, root[:]) {
		t.Fatal("stateRoot")
	}
	if b, _ := rlpcode.FixedBytes(items[3], 32); !allFF(b) {
		t.Fatal("limit must be 0xff*32")
	}
	if v, _ := rlpcode.U64(items[4]); v != 4096 {
		t.Fatalf("responseBytes %d", v)
	}
}

func TestAccountRangeDecodeBothSlimForms(t *testing.T) {
	acctHash := keccak([]byte("account"))
	sroot := keccak([]byte("storage"))
	chash := keccak([]byte("code"))
	// Inline-list form: [nonce, balance, storageRoot, codeHash].
	body := rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.Bytes([]byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}),
		rlpcode.Bytes(sroot[:]),
		rlpcode.Bytes(chash[:]),
	)
	msg := rlpcode.List(
		rlpcode.Uint(1),
		rlpcode.List(rlpcode.List(rlpcode.Bytes(acctHash[:]), body)),
		rlpcode.List(),
	)
	d, err := DecodeAccountRange(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Accounts) != 1 {
		t.Fatalf("accounts %d", len(d.Accounts))
	}
	a := d.Accounts[0]
	if a.AccountHash != acctHash || a.Nonce != 5 || a.StorageRoot != sroot || a.CodeHash != chash {
		t.Fatalf("decoded %+v", a)
	}

	// Bytes-wrapped form: the body is a byte string of the same RLP;
	// empty storageRoot/codeHash default to the empty-trie / empty-code
	// hashes.
	wrappedBody := rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.Bytes([]byte{1}),
		rlpcode.Bytes(nil),
		rlpcode.Bytes(nil),
	)
	msg2 := rlpcode.List(
		rlpcode.Uint(1),
		rlpcode.List(rlpcode.List(rlpcode.Bytes(acctHash[:]), rlpcode.Bytes(wrappedBody))),
		rlpcode.List(),
	)
	d2, err := DecodeAccountRange(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Accounts[0].StorageRoot != mpt.EmptyTrieRoot || d2.Accounts[0].CodeHash != mpt.EmptyCodeHash {
		t.Fatalf("wrapped defaults: %+v", d2.Accounts[0])
	}
}

func TestByteCodesRoundTripAndOverServe(t *testing.T) {
	h := keccak([]byte("code"))
	msg := EncodeGetByteCodes(3, [][32]byte{h}, 8192)
	items, err := rlpcode.Items(msg)
	if err != nil || len(items) != 3 {
		t.Fatalf("get encoding: %v %v", items, err)
	}
	resp := rlpcode.List(rlpcode.Uint(3), rlpcode.List(rlpcode.Bytes([]byte{0x60, 0x00})))
	id, codes, err := DecodeByteCodes(resp, 1)
	if err != nil || id != 3 || len(codes) != 1 || !equal(codes[0], []byte{0x60, 0x00}) {
		t.Fatalf("decode: %d %x %v", id, codes, err)
	}

	// Four codes for one requested hash: one over is kept (so the
	// over-serving shows), the rest dropped.
	code := func(b byte) rlp.RawValue { return rlpcode.Bytes([]byte{0x60, b}) }
	resp4 := rlpcode.List(rlpcode.Uint(3), rlpcode.List(code(0), code(1), code(2), code(3)))
	_, codes, err = DecodeByteCodes(resp4, 1)
	if err != nil || len(codes) != 2 {
		t.Fatalf("keep one past: %x %v", codes, err)
	}
	// A dropped code is still checked: a list where a code must be fails.
	bad := rlpcode.List(rlpcode.Uint(3), rlpcode.List(code(0), code(1), rlpcode.List()))
	if _, _, err := DecodeByteCodes(bad, 1); err == nil {
		t.Fatal("dropped-but-malformed code must fail")
	}
}

func TestEmptyResponders(t *testing.T) {
	d, err := DecodeAccountRange(EncodeEmptyRange(9))
	if err != nil || len(d.Accounts) != 0 || d.RequestID != 9 {
		t.Fatalf("empty range: %+v %v", d, err)
	}
	id, codes, err := DecodeByteCodes(EncodeEmptyCodes(9), 1)
	if err != nil || id != 9 || len(codes) != 0 {
		t.Fatalf("empty codes: %d %v %v", id, codes, err)
	}
}

func TestRangeEntriesPastTheCapAreCheckedNotKept(t *testing.T) {
	account := func(nonce byte) rlp.RawValue {
		return rlpcode.List(
			rlpcode.Bytes(bytesFill(nonce, 32)),
			rlpcode.List(rlpcode.Bytes([]byte{nonce}), rlpcode.Bytes([]byte{1})),
		)
	}
	rangeMsg := func(accounts []rlp.RawValue) []byte {
		return rlpcode.List(rlpcode.Uint(5), rlpcode.List(accounts...), rlpcode.List())
	}
	var many []rlp.RawValue
	for i := 0; i < MaxRangeEntries+5; i++ {
		many = append(many, account(byte(1+i%100)))
	}
	d, err := DecodeAccountRange(rangeMsg(many))
	if err != nil || len(d.Accounts) != MaxRangeEntries {
		t.Fatalf("cap: %d %v", len(d.Accounts), err)
	}
	// An entry past the cap with a bad hash still fails the response.
	bad := append(append([]rlp.RawValue{}, many...),
		rlpcode.List(rlpcode.Bytes(bytesFill(1, 31)), rlpcode.List()))
	if _, err := DecodeAccountRange(rangeMsg(bad)); err == nil {
		t.Fatal("past-cap malformed entry must fail")
	}
}

func TestProofOverTheNodeCapIsRefused(t *testing.T) {
	rangeMsg := func(nodes int) []byte {
		var list []rlp.RawValue
		for i := 0; i < nodes; i++ {
			list = append(list, rlpcode.Bytes(bytesFill(byte(i), 40)))
		}
		return rlpcode.List(rlpcode.Uint(5), rlpcode.List(), rlpcode.List(list...))
	}
	d, err := DecodeAccountRange(rangeMsg(MaxProofNodes))
	if err != nil || len(d.Proof) != MaxProofNodes {
		t.Fatalf("cap: %d %v", len(d.Proof), err)
	}
	if _, err := DecodeAccountRange(rangeMsg(MaxProofNodes + 1)); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Fatalf("over cap: %v", err)
	}
	// StorageRanges shares the cap.
	storage := func(nodes int) []byte {
		var list []rlp.RawValue
		for i := 0; i < nodes; i++ {
			list = append(list, rlpcode.Bytes(bytesFill(1, 40)))
		}
		return rlpcode.List(rlpcode.Uint(5), rlpcode.List(rlpcode.List()), rlpcode.List(list...))
	}
	if _, err := DecodeStorageRanges(storage(MaxProofNodes)); err != nil {
		t.Fatalf("storage cap: %v", err)
	}
	if _, err := DecodeStorageRanges(storage(MaxProofNodes + 1)); err == nil {
		t.Fatal("storage over cap must be refused")
	}
}

// --- verify-on-fetch (fetch.rs) ---------------------------------------

// singleLeafTrie builds a single-leaf trie proving key -> value.
func singleLeafTrie(key [32]byte, value []byte) ([32]byte, [][]byte) {
	compact := append([]byte{0x20}, key[:]...)
	node := rlpcode.List(rlpcode.Bytes(compact), rlpcode.Bytes(value))
	return keccak(node), [][]byte{node}
}

func TestAccountPresentFromProofNotSlimBody(t *testing.T) {
	var address [20]byte
	for i := range address {
		address[i] = 0x11
	}
	key := keccak(address[:])
	// The trusted leaf: nonce=5, balance=1 ETH, real roots.
	sroot := keccak([]byte("real-storage-root"))
	chash := keccak([]byte("real-code"))
	leafValue := rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.Bytes([]byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}),
		rlpcode.Bytes(sroot[:]),
		rlpcode.Bytes(chash[:]),
	)
	stateRoot, proof := singleLeafTrie(key, leafValue)
	// The peer's slim body LIES about storageRoot/codeHash — must be
	// ignored: the outcome's fields come from the proof leaf.
	msg := rlpcode.List(
		rlpcode.Uint(1),
		rlpcode.List(rlpcode.List(
			rlpcode.Bytes(key[:]),
			rlpcode.List(rlpcode.Uint(5), rlpcode.Bytes([]byte{1}),
				rlpcode.Bytes(bytesFill(0xaa, 32)), rlpcode.Bytes(bytesFill(0xbb, 32)))),
		),
		rlpcode.List(rawProofNodes(proof)...),
	)
	ar, err := DecodeAccountRange(msg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := VerifyAccount(stateRoot, address, ar)
	if err != nil {
		t.Fatal(err)
	}
	if out.Absent() {
		t.Fatal("want present")
	}
	if out.Account.StorageRoot != sroot || out.Account.CodeHash != chash || out.Account.Nonce != 5 {
		t.Fatalf("fields not from proof: %+v", out.Account)
	}
}

func TestUnservableRootClassification(t *testing.T) {
	var address [20]byte
	address[0] = 0x33
	// The #355 failure: empty proof against a non-empty root. Must
	// classify as unservable-root AND unknown-root (excused on a
	// finalized read).
	var root42 [32]byte
	for i := range root42 {
		root42[i] = 0x42
	}
	_, err := VerifyAccount(root42, address, &AccountRange{RequestID: 1})
	if err == nil {
		t.Fatal("want error")
	}
	if !IsUnservableRootError(err) {
		t.Fatalf("empty-proof error must take the fallback: %v", err)
	}
	if !IsUnknownRootError(err) {
		t.Fatalf("empty-proof must be the excused shape: %v", err)
	}
	// A garbage proof counts as unservable but is NOT excused.
	_, err = VerifyAccount(root42, address, &AccountRange{Proof: [][]byte{{0xde, 0xad, 0xbe, 0xef}}})
	if err == nil || !IsUnservableRootError(err) {
		t.Fatalf("garbage proof: %v", err)
	}
	if IsUnknownRootError(err) {
		t.Fatalf("garbage proof is a strike: %v", err)
	}
	// Transport-shaped failures must take neither path.
	for _, s := range []string{"request timed out", "peer disconnected", "connection reset by peer"} {
		e := errString(s)
		if IsUnservableRootError(e) || IsUnknownRootError(e) {
			t.Fatalf("transport error %q must not classify", s)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestAccountAbsentOnExclusionProof(t *testing.T) {
	presentKey := keccak([]byte("some-other-account"))
	stateRoot, proof := singleLeafTrie(presentKey, []byte("whatever"))
	var address [20]byte
	address[0] = 0x22
	out, err := VerifyAccount(stateRoot, address, &AccountRange{RequestID: 1, Proof: proof})
	if err != nil || !out.Absent() {
		t.Fatalf("want absent: %+v %v", out, err)
	}
}

func TestAccountInvalidProofErrors(t *testing.T) {
	var address [20]byte
	address[0] = 0x33
	var root99 [32]byte
	for i := range root99 {
		root99[i] = 0x99
	}
	if _, err := VerifyAccount(root99, address, &AccountRange{Proof: [][]byte{{0xc0}}}); err == nil {
		t.Fatal("want invalid error")
	}
}

func TestStorageEmptyRootIsZeroWithoutProof(t *testing.T) {
	account := &mpt.AccountLeaf{StorageRoot: mpt.EmptyTrieRoot, CodeHash: mpt.EmptyCodeHash}
	var slot [32]byte
	slot[0] = 1
	v, err := VerifyStorage(account, slot, &StorageRanges{RequestID: 1})
	if err != nil || len(v) != 0 {
		t.Fatalf("want zero: %x %v", v, err)
	}
}

func TestStorageValueFromProof(t *testing.T) {
	var slot [32]byte
	for i := range slot {
		slot[i] = 0x07
	}
	key := keccak(slot[:])
	slotValue := rlpcode.Bytes([]byte{0x2a}) // rlp(42)
	storageRoot, proof := singleLeafTrie(key, slotValue)
	account := &mpt.AccountLeaf{StorageRoot: storageRoot, CodeHash: mpt.EmptyCodeHash}
	resp := &StorageRanges{
		RequestID: 1,
		Slots:     []StorageSlot{{SlotHash: key, RawTrieValue: slotValue}},
		Proof:     proof,
	}
	v, err := VerifyStorage(account, slot, resp)
	if err != nil || !equal(v, []byte{0x2a}) {
		t.Fatalf("want 2a: %x %v", v, err)
	}
}

func TestBytecodeMatchesHash(t *testing.T) {
	code := []byte{0x60, 0x00, 0x60, 0x00}
	h := keccak(code)
	if got, ok := VerifyBytecode(h, [][]byte{code}); !ok || !equal(got, code) {
		t.Fatalf("want code match: %x %v", got, ok)
	}
	if _, ok := VerifyBytecode([32]byte{}, [][]byte{{0x60}}); ok {
		t.Fatal("mismatch must report false")
	}
	if got, ok := VerifyBytecode(mpt.EmptyCodeHash, nil); !ok || len(got) != 0 {
		t.Fatal("empty-code hash short-circuits to verified-empty")
	}
}

func TestDecodeFuzzNoPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.Intn(64))
		rng.Read(b)
		_, _ = DecodeAccountRange(b)
		_, _ = DecodeStorageRanges(b)
		_, _, _ = DecodeByteCodes(b, rng.Intn(4))
	}
}

// --- corpus replay -----------------------------------------------------

func TestCorpusReplay(t *testing.T) {
	corpus := filepath.Join("..", "..", "..", "rust", "testdata", "el", "snap")
	if _, err := os.Stat(corpus); err != nil {
		// FAIL CLOSED, same rule as the mpt replay and the rlpx/lc
		// conformance tests: these goldens are the snap wire's only
		// cross-engine pin; a missing corpus must break the build,
		// not pass vacuously.
		t.Fatalf("el/snap conformance corpus must be present at %s: %v", corpus, err)
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
	if len(expected) == 0 {
		t.Fatal("corpus present but expected.txt missing/empty — regenerate on the Java side")
	}

	// Deterministic inputs shared with the Java and Rust tests.
	addrPreimage := keccak([]byte("snap:account"))
	var address [20]byte
	copy(address[:], addrPreimage[:20])
	accountHash := keccak(address[:])
	slot := keccak([]byte("snap:slot"))
	codeHash := keccak([]byte("snap:some-code"))
	stateRoot := mustHash(t, expected["account.stateRoot"])

	actual := map[string]string{
		"encode.getAccountRange": hex.EncodeToString(
			EncodeGetAccount(1, stateRoot, accountHash, 4096)),
		"encode.getStorageRanges": hex.EncodeToString(
			EncodeGetStorageRanges(2, stateRoot, accountHash, keccak(slot[:]), fullFF, 4096)),
		"encode.getByteCodes": hex.EncodeToString(
			EncodeGetByteCodes(3, [][32]byte{codeHash}, 262144)),
	}

	// Verify-on-fetch against Java's committed message bytes.
	acctMsg := mustRead(t, filepath.Join(corpus, "001-accountrange.bin"))
	ar, err := DecodeAccountRange(acctMsg)
	if err != nil {
		t.Fatalf("decode AccountRange: %v", err)
	}
	actual["account.stateRoot"] = hex.EncodeToString(stateRoot[:])
	out, err := VerifyAccount(stateRoot, address, ar)
	if err != nil {
		t.Fatalf("verify_account: %v", err)
	}
	if out.Absent() {
		actual["account.verified"] = "Absent"
	} else {
		actual["account.verified"] = "found"
		actual["account.nonce"] = itoa(out.Account.Nonce)
		actual["account.balance"] = scalarHex(out.Account.Balance)
		actual["account.storageRoot"] = hex.EncodeToString(out.Account.StorageRoot[:])
		actual["account.codeHash"] = hex.EncodeToString(out.Account.CodeHash[:])
	}

	stgMsg := mustRead(t, filepath.Join(corpus, "002-storageranges.bin"))
	sr, err := DecodeStorageRanges(stgMsg)
	if err != nil {
		t.Fatalf("decode StorageRanges: %v", err)
	}
	storageRoot := mustHash(t, expected["storage.storageRoot"])
	actual["storage.storageRoot"] = hex.EncodeToString(storageRoot[:])
	account := &mpt.AccountLeaf{StorageRoot: storageRoot, CodeHash: mpt.EmptyCodeHash}
	value, err := VerifyStorage(account, slot, sr)
	if err != nil {
		t.Fatalf("verify_storage: %v", err)
	}
	actual["storage.verified"] = "found"
	actual["storage.value"] = scalarHex(value)

	for k, want := range expected {
		got, ok := actual[k]
		if !ok {
			t.Errorf("expected key %s missing from Go replay", k)
			continue
		}
		if got != want {
			t.Errorf("verdict diverges for %s: want %q, got %q", k, want, got)
		}
	}
	for k := range actual {
		if _, ok := expected[k]; !ok {
			t.Errorf("Go replay produced key %s the recorded expected.txt does not have", k)
		}
	}
}

// --- helpers ------------------------------------------------------------

func keccak(b []byte) [32]byte { return crypto.Keccak256Hash(b) }

var fullFF = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func mustHash(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hash %q: %v", s, err)
	}
	var h [32]byte
	copy(h[:], b)
	return h
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scalarHex is Java BigInteger.toString(16) shape: minimal hex, "0"
// for zero.
func scalarHex(b []byte) string {
	trimmed := strings.TrimLeft(hex.EncodeToString(b), "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

func rawProofNodes(nodes [][]byte) []rlp.RawValue {
	out := make([]rlp.RawValue, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, rlpcode.Bytes(n))
	}
	return out
}

func bytesFill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func equal(a, b []byte) bool {
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

func allFF(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	for _, x := range b {
		if x != 0xff {
			return false
		}
	}
	return true
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for v > 0 {
		i--
		d[i] = byte('0' + v%10)
		v /= 10
	}
	return string(d[i:])
}

// --- allocation bounds (#454) ----------------------------------------

func TestHostileListsDecodeInBoundedMemory(t *testing.T) {
	// A peer answers the single-key ask with a MULTI-MiB list of
	// one-byte items at every peer-controlled position this codec
	// reads. ValidateNode passes (valid RLP, under the frame cap);
	// the decoders must stream past it — kept entries capped, the rest
	// checked positionally and dropped — where rlpcode.Items would
	// first build a ~24-bytes-per-item [][]byte before the first
	// check ran.
	items := make([]rlp.RawValue, 100_000)
	for i := range items {
		items[i] = rlp.RawValue{0x01}
	}
	bigList := []byte(rlpcode.List(items...))

	// Accounts position: 100k [hash, body] pairs for a one-account ask.
	pair := rlpcode.List(
		rlpcode.Bytes(make([]byte, 32)),
		rlpcode.List(rlpcode.Uint(1), rlpcode.Bytes(nil)),
	)
	accPairs := make([]rlp.RawValue, 100_000)
	for i := range accPairs {
		accPairs[i] = pair
	}
	accMsg := []byte(rlpcode.List(
		rlpcode.Uint(7), rlpcode.List(accPairs...), rlpcode.List()))
	ar, err := DecodeAccountRange(accMsg)
	if err != nil {
		t.Fatalf("account range: %v", err)
	}
	if len(ar.Accounts) > MaxRangeEntries {
		t.Fatalf("kept %d accounts over the cap", len(ar.Accounts))
	}

	// Proof slot: a 100k-node list — refused AT the cap, mid-stream.
	proofMsg := []byte(rlpcode.List(
		rlpcode.Uint(7), rlpcode.List(), rlpcode.List(items...)))
	if _, err := DecodeAccountRange(proofMsg); err == nil ||
		!strings.Contains(err.Error(), "proof has more than") {
		t.Fatalf("oversized proof must be refused at MaxProofNodes, got %v", err)
	}

	// ByteCodes position: 100k one-byte codes for a 1-hash ask.
	bcMsg := []byte(rlpcode.List(rlpcode.Uint(8), bigList))
	_, codes, err := DecodeByteCodes(bcMsg, 1)
	if err != nil {
		t.Fatalf("byte codes: %v", err)
	}
	if len(codes) != 2 { // kept(requested)=2; the other 99,998 checked, dropped
		t.Fatalf("kept %d codes", len(codes))
	}

	// Top level: extra fields past the third are skipped, not read.
	if _, _, err := DecodeByteCodes([]byte(rlpcode.List(
		rlpcode.Uint(9), rlpcode.List(rlpcode.Bytes([]byte{0xaa})),
		rlpcode.List(), rlpcode.List(),
	)), 1); err != nil {
		t.Fatalf("extra top-level fields must be skipped: %v", err)
	}
}
