package eth

import (
	"log/slog"
	"math/big"
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

	raws := []rlp.RawValue{h0, h1, h2}
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
	if _, err := p.verifyBackwardChain(h0h, []rlp.RawValue{h0, h2}); err == nil {
		t.Error("broken link accepted")
	}
	// Empty.
	if _, err := p.verifyBackwardChain(h0h, nil); err == nil {
		t.Error("empty response accepted")
	}
	// Non-canonical junk.
	if _, err := p.verifyBackwardChain(h0h, []rlp.RawValue{{0x01}}); err == nil {
		t.Error("undecodable header accepted")
	}
}
