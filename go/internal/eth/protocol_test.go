package eth

import (
	"bytes"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestHighestCommon(t *testing.T) {
	cases := []struct {
		peer []uint
		want uint
	}{
		{[]uint{66, 67, 68, 69, 70, 71}, 68},
		{[]uint{67}, 67},
		{[]uint{65, 64}, 0}, // pre-66 has no request ids: rejected
		{[]uint{69, 70}, 0}, // 69-only: we don't implement its serving half yet
		{nil, 0},
	}
	for _, c := range cases {
		if got := HighestCommon(c.peer); got != c.want {
			t.Errorf("HighestCommon(%v) = %d, want %d", c.peer, got, c.want)
		}
	}
}

func TestStatusRoundTrip(t *testing.T) {
	in := status68{
		Version:   68,
		NetworkID: 1,
		TD:        rlp.RawValue{0x80},
		BestHash:  common.HexToHash("0xabc123"),
		Genesis:   common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
		ForkID:    forkIDRLP{Hash: [4]byte{0x07, 0xc9, 0x46, 0x2e}, Next: 0},
	}
	enc, err := rlp.EncodeToBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	var out status68
	if err := rlp.DecodeBytes(enc, &out); err != nil {
		t.Fatalf("decode our own status: %v", err)
	}
	if out.Version != 68 || out.NetworkID != 1 || out.BestHash != in.BestHash ||
		out.Genesis != in.Genesis || out.ForkID != in.ForkID {
		t.Errorf("round trip changed status: %+v", out)
	}
	// The shape peers check: TD must be the empty string 0x80, fork id a
	// 2-item list. Byte-level: [..., 0x80, ...] — assert on the re-encode
	// being canonical (same bytes both ways).
	enc2, err := rlp.EncodeToBytes(out)
	if err != nil || string(enc2) != string(enc) {
		t.Errorf("status re-encode is not canonical")
	}
}

func TestHelloShape(t *testing.T) {
	// helloMsg must decode a geth-shaped hello: [5, clientId, caps, listen,
	// 64-byte nodeId].
	nodeID := make([]byte, 64)
	nodeID[0] = 0xaa
	raw, err := rlp.EncodeToBytes([]any{
		uint32(5),
		"Geth/v1.16.8",
		[]any{[]any{"eth", uint64(68)}, []any{"snap", uint64(1)}},
		uint16(30303),
		nodeID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var h helloMsg
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		t.Fatalf("decode geth-shaped hello: %v", err)
	}
	if h.ClientID != "Geth/v1.16.8" || h.Capability != 5 {
		t.Errorf("hello parsed wrong: %+v", h)
	}
	var ethVersions []uint
	for _, c := range h.Capabilities {
		if c.Name == "eth" {
			ethVersions = append(ethVersions, c.Version)
		}
	}
	if len(ethVersions) != 1 || ethVersions[0] != 68 {
		t.Errorf("eth caps = %v", ethVersions)
	}
	if h.NodeID[0] != 0xaa {
		t.Error("node id mangled")
	}
}

func TestFirstRequestID(t *testing.T) {
	payload := mustRLP([]any{uint64(7), []any{}})
	id, err := firstRequestID(payload)
	if err != nil || id != 7 {
		t.Errorf("firstRequestID = %d, %v; want 7", id, err)
	}
	if _, err := firstRequestID([]byte{0xc0, 0xff}); err == nil {
		t.Error("non-integer id must fail")
	}
}

func header(t *testing.T, number uint64, parent common.Hash) []byte {
	t.Helper()
	h := &types.Header{
		ParentHash: parent,
		Number:     new(big.Int).SetUint64(number),
		Time:       1_700_000_000 + number,
		GasLimit:   30_000_000,
		Difficulty: big.NewInt(0),
	}
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyBackwardChain(t *testing.T) {
	p := &Peer{log: slog.New(slog.DiscardHandler)}

	// A reverse walk delivers head, head-1, head-2: each entry's hash must
	// equal the previous entry's parentHash, so build bottom-up.
	h2 := header(t, 100, common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"))
	h2h := crypto.Keccak256Hash(h2)
	h1 := header(t, 101, h2h)
	h1h := crypto.Keccak256Hash(h1)
	h0 := header(t, 102, h1h)
	h0h := crypto.Keccak256Hash(h0)

	raws := [][]byte{h0, h1, h2}
	got, err := p.verifyBackwardChain(h0h, raws)
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if len(got) != 3 || got[0].Number != 102 || got[2].Number != 100 {
		t.Errorf("chain = %+v", got)
	}

	// Head mismatch.
	if _, err := p.verifyBackwardChain(common.HexToHash("0xdead"), raws); err == nil {
		t.Error("head mismatch accepted")
	}
	// Broken link (drop the middle header → 102 then 100).
	if _, err := p.verifyBackwardChain(h0h, [][]byte{h0, h2}); err == nil {
		t.Error("broken link accepted")
	}
	// Empty.
	if _, err := p.verifyBackwardChain(h0h, nil); err == nil {
		t.Error("empty response accepted")
	}
	// Non-canonical junk.
	if _, err := p.verifyBackwardChain(h0h, [][]byte{{0x01}}); err == nil {
		t.Error("undecodable header accepted")
	}
	// All of the above must be ErrBadAnswer — the stage drops lying peers
	// on the strength of it.
	if _, err := p.verifyBackwardChain(common.HexToHash("0xdead"), raws); !errors.Is(err, ErrBadAnswer) {
		t.Errorf("head mismatch err = %v, want ErrBadAnswer", err)
	}
}

// TestHeaderCoreToleratesFutureFields runs the shared conformance corpus's
// 006-header-future-extra case (a Prague header plus one unknown 20-byte
// trailing field) through the walk: decode=ok, the fields we verify on
// match, and the identity hash equals the corpus value — proving future
// fields are covered by the hash while remaining unreadable-proof (spec
// §6.6; the Amsterdam fork appends two such fields for real).
func TestHeaderCoreToleratesFutureFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("../../../rust/testdata/el/core/006-header-future-extra.rlp"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	hc, err := headerCore(raw)
	if err != nil {
		t.Fatalf("future-extra header rejected: %v", err)
	}
	if hc.Number != 22_431_084 {
		t.Errorf("number = %d, want 22431084", hc.Number)
	}
	if hc.Time != 1_700_000_006 {
		t.Errorf("time = %d, want 1700000006", hc.Time)
	}
	if want := common.HexToHash("98560aa1b9114e7df7023b9b69f6f915618204f6549fed1ed04dfb975b0433da"); hc.StateRoot != want {
		t.Errorf("stateRoot = %s, want %s", hc.StateRoot, want)
	}
	if want := common.HexToHash("d824da4e02a957ecace9ad9a346a02c7281fd9f9459dea9c04bc06e483a7a931"); hc.ParentHash != want {
		t.Errorf("parentHash = %s, want %s", hc.ParentHash, want)
	}
	if got := crypto.Keccak256Hash(raw); got != common.HexToHash("2a16161642dfbaf69daf247cdabf7d695319b35636fa4413653d0f2ab00abe8c") {
		t.Errorf("header hash = %s, want corpus 2a161616…", got)
	}

	// Corpus negatives: short stateRoot and trailing bytes are decode errors.
	short, err := os.ReadFile(filepath.FromSlash("../../../rust/testdata/el/core/092-header-short-stateroot.rlp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := headerCore(short); err == nil {
		t.Error("31-byte stateRoot accepted")
	}
	trailing, err := os.ReadFile(filepath.FromSlash("../../../rust/testdata/el/core/093-header-trailing-byte.rlp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := headerCore(trailing); err == nil {
		t.Error("trailing byte after the list accepted")
	}
}

func TestWalkBlockHeaders(t *testing.T) {
	h := header(t, 5, common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"))
	payload := func(n int) rlp.RawValue {
		raws := make([][]byte, n)
		for i := range raws {
			raws[i] = h
		}
		return mustRLP([]any{uint64(9), raws})
	}
	got, err := walkBlockHeaders(payload(2), 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("walk of a correct answer: %d headers, %v", len(got), err)
	}
	// One over the request is kept (so the caller reports the over-serve),
	// anything beyond is refused without touching the rest.
	if got, err := walkBlockHeaders(payload(3), 2); err != nil || len(got) != 3 {
		t.Errorf("amount+1 = %d headers, err %v; want 3 kept for the caller to reject", len(got), err)
	}
	if _, err := walkBlockHeaders(payload(4), 2); err == nil {
		t.Error("over-serving past amount+1 accepted")
	}
	if _, err := walkBlockHeaders(rlp.RawValue{0x01}, 2); err == nil {
		t.Error("junk payload accepted")
	}
}

func TestDisconnectReasonShapes(t *testing.T) {
	// Wire form per devp2p/geth: a ONE-element list. This is the `c104`
	// the live dial pool keeps hitting (reason 0x04, too-many-peers).
	if got := disconnectReason([]byte{0xc1, 0x04}); !strings.Contains(got, "too-many-peers") {
		t.Errorf("list-encoded 0x04 = %q, want too-many-peers named", got)
	}
	// Historical bare form still decodes.
	if got := disconnectReason([]byte{0x04}); !strings.Contains(got, "too-many-peers") {
		t.Errorf("bare 0x04 = %q, want too-many-peers named", got)
	}
	// Our OWN outbound encoding must be the list form a geth peer can parse.
	if enc := mustRLP([]uint{0x04}); !bytes.Equal(enc, []byte{0xc1, 0x04}) {
		t.Errorf("outbound disconnect encoding = %x, want c104", enc)
	}
	// Junk and oversized payloads degrade without a hex flood.
	if got := disconnectReason([]byte{0xff, 0xf8, 0x05}); strings.Contains(got, "reason") {
		t.Errorf("junk parsed as reason: %q", got)
	}
	big := make([]byte, 4096)
	if got := disconnectReason(big); len(got) > 128 {
		t.Errorf("huge payload rendered as %d chars, want the hex capped", len(got))
	}
}

func TestDeliverResponseCopiesPayload(t *testing.T) {
	p := &Peer{pending: map[uint64]chan rlp.RawValue{}}
	ch := p.registerRequest(7)
	buf := []byte{0xc1, 0x04, 0x00}
	p.deliverResponse(7, buf)
	buf[0] = 0xff // the read loop's next frame lands in this same buffer
	got := <-ch
	if got[0] != 0xc1 {
		t.Errorf("delivered payload aliases the read buffer: %x", []byte(got))
	}
	// Unknown id: delivered nowhere, no panic, no leak.
	p.deliverResponse(8, buf)
}
