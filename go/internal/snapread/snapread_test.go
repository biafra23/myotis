package snapread

// Policy tests over fake peers: the attempt cap (address-disclosure
// bound), the three-way fault classification, the aggregate failure
// shape, and the two-hop trust chain (storage anchored at the
// PROVEN storageRoot, code at the PROVEN codeHash, with the
// short-circuits for provably-empty accounts). The wire itself is
// covered by the transport round trip and the corpus replays.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/rlpcode"
	"github.com/biafra23/myotis/go/internal/snapwire"
)

type fake struct {
	id      string
	snap    bool
	order   *[]string // records every call, for cap/order assertions
	ar      *snapwire.AccountRange
	sr      *snapwire.StorageRanges
	codes   [][]byte
	failAcc error
	failSto error
	failBC  error
}

func (f *fake) ID() string    { return f.id }
func (f *fake) HasSnap() bool { return f.snap }
func (f *fake) note() {
	if f.order != nil {
		*f.order = append(*f.order, f.id)
	}
}

func (f *fake) GetAccountRange(stateRoot, startingHash, limitHash [32]byte, _ uint64) (*snapwire.AccountRange, error) {
	f.note()
	if f.failAcc != nil {
		return nil, f.failAcc
	}
	return f.ar, nil
}

func (f *fake) GetStorageRanges(stateRoot, accountHash, startingHash, limitHash [32]byte, _ uint64) (*snapwire.StorageRanges, error) {
	f.note()
	if f.failSto != nil {
		return nil, f.failSto
	}
	return f.sr, nil
}

func (f *fake) GetByteCodes(hashes [][32]byte, _ uint64) ([][]byte, error) {
	f.note()
	if f.failBC != nil {
		return nil, f.failBC
	}
	return f.codes, nil
}

// fixture builds an account at `address` with a single-leaf state
// trie, a storage trie holding slot→42, and code keccak'd to
// codeHash — everything one test needs for all three reads.
type fixture struct {
	address   [20]byte
	stateRoot [32]byte
	account   *mpt.AccountLeaf
	slot      [32]byte
	code      []byte
	ar        *snapwire.AccountRange
	sr        *snapwire.StorageRanges
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	var fx fixture
	copy(fx.address[:], crypto.Keccak256([]byte("snapread-test"))[:20])
	fx.slot = crypto.Keccak256Hash([]byte("slot-1"))
	fx.code = []byte{0x60, 0x00, 0x60, 0x00}
	codeHash := crypto.Keccak256Hash(fx.code)

	// Storage trie: slot → rlp(42).
	slotKey := crypto.Keccak256Hash(fx.slot[:])
	slotNode := leafNode(t, slotKey, rlpcode.Bytes([]byte{0x2a}))
	storageRoot := crypto.Keccak256Hash(slotNode)

	fx.account = &mpt.AccountLeaf{Nonce: 9, Balance: []byte{0x01}, CodeHash: codeHash, StorageRoot: storageRoot}
	leafValue := rlpcode.List(
		rlpcode.Uint(fx.account.Nonce),
		rlpcode.Bytes(fx.account.Balance),
		rlpcode.Bytes(storageRoot[:]),
		rlpcode.Bytes(codeHash[:]),
	)
	acctKey := crypto.Keccak256Hash(fx.address[:])
	acctNode := leafNode(t, acctKey, leafValue)
	fx.stateRoot = crypto.Keccak256Hash(acctNode)

	var err error
	fx.ar, err = snapwire.DecodeAccountRange(rlpcode.List(
		rlpcode.Uint(1), rlpcode.List(), rlpcode.List(rlpcode.Bytes(acctNode))))
	if err != nil {
		t.Fatal(err)
	}
	fx.sr, err = snapwire.DecodeStorageRanges(rlpcode.List(
		rlpcode.Uint(2), rlpcode.List(), rlpcode.List(rlpcode.Bytes(slotNode))))
	if err != nil {
		t.Fatal(err)
	}
	return &fx
}

func leafNode(t *testing.T, key [32]byte, value []byte) []byte {
	t.Helper()
	compact := append([]byte{0x20}, key[:]...)
	return rlpcode.List(rlpcode.Bytes(compact), rlpcode.Bytes(value))
}

func TestAccountGoodProof(t *testing.T) {
	fx := newFixture(t)
	p := &fake{id: strings.Repeat("aa", 16), snap: true, ar: fx.ar}
	out, err := Account([]Peer{p}, fx.stateRoot, fx.address)
	if err != nil {
		t.Fatal(err)
	}
	if out.Absent() || out.Account.Nonce != 9 || out.Account.StorageRoot != fx.account.StorageRoot ||
		out.Account.CodeHash != fx.account.CodeHash {
		t.Fatalf("verified fields wrong: %+v", out.Account)
	}
}

func TestRetryAcrossPeers(t *testing.T) {
	fx := newFixture(t)
	var order []string
	bad := &fake{id: strings.Repeat("bb", 16), snap: true, order: &order,
		failAcc: errors.New("transport: timed out awaiting account range")}
	good := &fake{id: strings.Repeat("cc", 16), snap: true, order: &order, ar: fx.ar}
	if _, err := Account([]Peer{bad, good}, fx.stateRoot, fx.address); err != nil {
		t.Fatalf("want retry to succeed: %v", err)
	}
	if len(order) != 2 || order[1] != good.id {
		t.Fatalf("attempt order: %v", order)
	}
}

func TestAttemptCapIsTheDisclosureBound(t *testing.T) {
	fx := newFixture(t)
	var order []string
	var peers []Peer
	for i := 0; i < 5; i++ {
		peers = append(peers, &fake{
			id:      fmt.Sprintf("peer-%d-%s", i, strings.Repeat("dd", 14)),
			snap:    true,
			order:   &order,
			failAcc: errors.New("transport: read: EOF"),
		})
	}
	_, err := Account(peers, fx.stateRoot, fx.address)
	if err == nil {
		t.Fatal("want aggregate failure")
	}
	if !strings.Contains(err.Error(), "all 3 snap peer(s) failed to serve account") {
		t.Fatalf("aggregate shape: %v", err)
	}
	if len(order) != 3 {
		t.Fatalf("disclosure bound violated: %d peers contacted", len(order))
	}
}

func TestNonSnapPeersAreSkipped(t *testing.T) {
	fx := newFixture(t)
	var order []string
	var peers []Peer
	for i := 0; i < 3; i++ {
		peers = append(peers, &fake{id: fmt.Sprintf("ethonly%d", i), snap: false, order: &order})
	}
	peers = append(peers, &fake{id: strings.Repeat("ee", 16), snap: true, order: &order, ar: fx.ar})
	if _, err := Account(peers, fx.stateRoot, fx.address); err != nil {
		t.Fatal(err)
	}
	if len(order) != 1 {
		t.Fatalf("non-snap peers were asked: %v", order)
	}
	if _, err := Account([]Peer{&fake{id: "x", snap: false}}, fx.stateRoot, fx.address); err == nil ||
		!strings.Contains(err.Error(), "no snap-capable") {
		t.Fatalf("want no-snap-capable error, got %v", err)
	}
}

func TestClassification(t *testing.T) {
	pruned := fmt.Errorf("account %s: %s", snapwire.ProofInvalidMarker, snapwire.UnknownRootReason)
	garbage := fmt.Errorf("account %s: malformed node RLP: expected list", snapwire.ProofInvalidMarker)
	transport := errors.New("transport: timed out awaiting account range")
	if Classify(pruned) != FaultPrunedRoot {
		t.Error("empty proof must be pruned-root")
	}
	if Classify(garbage) != FaultBadProof {
		t.Error("garbage proof must be bad-proof")
	}
	if Classify(transport) != FaultTransport {
		t.Error("timeout must be transport")
	}
}

func TestAggregateNamesTheFaultKinds(t *testing.T) {
	fx := newFixture(t)
	p1 := &fake{id: strings.Repeat("11", 16), snap: true,
		failAcc: fmt.Errorf("account %s: %s", snapwire.ProofInvalidMarker, snapwire.UnknownRootReason)}
	p2 := &fake{id: strings.Repeat("22", 16), snap: true,
		failAcc: fmt.Errorf("storage %s: malformed node RLP", snapwire.ProofInvalidMarker)}
	_, err := Account([]Peer{p1, p2}, fx.stateRoot, fx.address)
	if err == nil {
		t.Fatal("want failure")
	}
	msg := err.Error()
	if !strings.Contains(msg, "pruned-root") || !strings.Contains(msg, "bad-proof") {
		t.Fatalf("summary must name both kinds: %v", msg)
	}
}

func TestSlotAnchorsAtProvenStorageRoot(t *testing.T) {
	fx := newFixture(t)
	p := &fake{id: strings.Repeat("ff", 16), snap: true, ar: fx.ar, sr: fx.sr}
	v, err := Slot([]Peer{p}, fx.stateRoot, fx.address, fx.slot)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0] != 0x2a {
		t.Fatalf("slot value %x", v)
	}
}

func TestSlotAtReusesTheProvenAccount(t *testing.T) {
	// The CLI's one-logical-read path: after Account, SlotAt must do
	// ONLY the storage hop — no second account request, no widened
	// address disclosure.
	fx := newFixture(t)
	var order []string
	p := &fake{id: strings.Repeat("66", 16), snap: true, order: &order, ar: fx.ar, sr: fx.sr}
	out, err := Account([]Peer{p}, fx.stateRoot, fx.address)
	if err != nil || out.Absent() {
		t.Fatalf("account: %+v %v", out, err)
	}
	v, err := SlotAt([]Peer{p}, fx.stateRoot, fx.address, fx.slot, out)
	if err != nil || len(v) != 1 || v[0] != 0x2a {
		t.Fatalf("slot: %x %v", v, err)
	}
	if len(order) != 2 {
		t.Fatalf("want exactly account+storage, got %v", order)
	}
}

func TestSlotEmptyTrieShortCircuits(t *testing.T) {
	// Account whose storageRoot is the empty trie: Slot must answer
	// zero WITHOUT a storage round trip.
	var address [20]byte
	copy(address[:], crypto.Keccak256([]byte("empty-storage"))[:20])
	leafValue := rlpcode.List(
		rlpcode.Uint(1), rlpcode.Bytes(nil),
		rlpcode.Bytes(mpt.EmptyTrieRoot[:]), rlpcode.Bytes(mpt.EmptyCodeHash[:]))
	acctKey := crypto.Keccak256Hash(address[:])
	acctNode := leafNode(t, acctKey, leafValue)
	root := crypto.Keccak256Hash(acctNode)
	msg := rlpcode.List(rlpcode.Uint(1), rlpcode.List(), rlpcode.List(rlpcode.Bytes(acctNode)))
	ar, err := snapwire.DecodeAccountRange(msg)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	p := &fake{id: strings.Repeat("99", 16), snap: true, order: &order, ar: ar}
	v, err := Slot([]Peer{p}, root, address, [32]byte{7})
	if err != nil || v != nil {
		t.Fatalf("want provable zero: %x %v", v, err)
	}
	if len(order) != 1 {
		t.Fatalf("storage round trip against a proven empty trie: %v", order)
	}
}

func TestCodeAttestsTheHash(t *testing.T) {
	fx := newFixture(t)
	var order []string
	wrong := &fake{id: strings.Repeat("33", 16), snap: true, order: &order,
		ar: fx.ar, codes: [][]byte{{0xde, 0xad}}} // served, hashes to nothing requested
	right := &fake{id: strings.Repeat("44", 16), snap: true, order: &order,
		ar: fx.ar, codes: [][]byte{fx.code}}
	code, err := Code([]Peer{wrong, right}, fx.stateRoot, fx.address)
	if err != nil {
		t.Fatalf("want retry to the matching code: %v", err)
	}
	if string(code) != string(fx.code) {
		t.Fatalf("code %x", code)
	}
	// account served by the first peer, its code mismatch, second
	// peer's matching code: three calls.
	if len(order) != 3 {
		t.Fatalf("call order %v", order)
	}
}

func TestCodeAttestedEOAShortCircuits(t *testing.T) {
	var address [20]byte
	copy(address[:], crypto.Keccak256([]byte("eoa"))[:20])
	leafValue := rlpcode.List(
		rlpcode.Uint(3), rlpcode.Bytes([]byte{2}),
		rlpcode.Bytes(mpt.EmptyTrieRoot[:]), rlpcode.Bytes(mpt.EmptyCodeHash[:]))
	acctNode := leafNode(t, crypto.Keccak256Hash(address[:]), leafValue)
	root := crypto.Keccak256Hash(acctNode)
	ar, err := snapwire.DecodeAccountRange(rlpcode.List(
		rlpcode.Uint(1), rlpcode.List(), rlpcode.List(rlpcode.Bytes(acctNode))))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	p := &fake{id: strings.Repeat("55", 16), snap: true, order: &order, ar: ar}
	code, err := Code([]Peer{p}, root, address)
	if err != nil || code != nil {
		t.Fatalf("want verified-empty EOA code: %x %v", code, err)
	}
	if len(order) != 1 {
		t.Fatalf("bytecode round trip for a proven EOA: %v", order)
	}
}
