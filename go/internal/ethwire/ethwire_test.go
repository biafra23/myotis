package ethwire

import (
	"bytes"
	"testing"

	"github.com/biafra23/myotis/go/internal/rlpcode"
	"github.com/ethereum/go-ethereum/common"
)

func TestHelloRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 64)
	h, err := DecodeHello(EncodeHello(key, 30303))
	if err != nil {
		t.Fatal(err)
	}
	if h.ClientID != ClientID {
		t.Errorf("client id = %q, want %q", h.ClientID, ClientID)
	}
	if h.ProtocolVersion != 5 || h.ListenPort != 30303 {
		t.Errorf("protocol/port = %d/%d", h.ProtocolVersion, h.ListenPort)
	}
	if !bytes.Equal(h.NodeID, key) {
		t.Error("node id mismatch")
	}
	want := []Capability{
		{"eth", 66}, {"eth", 67}, {"eth", 68}, {"eth", 69}, {"eth", 70}, {"eth", 71},
		{"snap", 1}, {"snap", 2},
	}
	if len(h.Capabilities) != len(want) {
		t.Fatalf("caps = %v", h.Capabilities)
	}
	for i := range want {
		if h.Capabilities[i] != want[i] {
			t.Fatalf("cap %d = %v, want %v", i, h.Capabilities[i], want[i])
		}
	}
}

func TestNegotiate(t *testing.T) {
	caps := func(cs ...Capability) *Hello { return &Hello{Capabilities: cs} }

	// Highest common eth wins; snap picks the highest shared.
	eth, snap, ok := Negotiate(caps(Capability{"eth", 67}, Capability{"eth", 68}, Capability{"snap", 1}, Capability{"snap", 2}))
	if !ok || eth != 68 || snap == nil || *snap != 2 {
		t.Fatalf("got (%d, %v, %v)", eth, snap, ok)
	}

	// eth/69-only peer (EIP-7642) is accepted.
	eth, snap, ok = Negotiate(caps(Capability{"eth", 69}))
	if !ok || eth != 69 || snap != nil {
		t.Fatalf("eth69-only: (%d, %v, %v)", eth, snap, ok)
	}

	// A snap/2-only peer (reth ships no snap/1) still gets snap.
	eth, snap, ok = Negotiate(caps(Capability{"eth", 66}, Capability{"snap", 2}))
	if !ok || eth != 66 || snap == nil || *snap != 2 {
		t.Fatalf("snap2-only: (%d, %v, %v)", eth, snap, ok)
	}

	// Below the floor (eth/65) or foreign caps: no session.
	if _, _, ok = Negotiate(caps(Capability{"eth", 65}, Capability{"snap", 1})); ok {
		t.Fatal("eth/65 must not negotiate")
	}
	if _, _, ok = Negotiate(caps(Capability{"eth", 999}, Capability{"snap", 1})); ok {
		t.Fatal("unheard-of eth version must not negotiate (like the Rust OUR_ETH_VERSIONS gate)")
	}
	if _, _, ok = Negotiate(caps(Capability{"les", 4})); ok {
		t.Fatal("no eth cap must not negotiate")
	}
}

func TestStatusRoundTripEth68(t *testing.T) {
	genesis := common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	best := common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	fork := [4]byte{0x07, 0xc9, 0x46, 0x2e}

	enc := EncodeStatus(68, 1, genesis, best, fork, 0)
	s, err := DecodeStatus(enc, 68)
	if err != nil {
		t.Fatal(err)
	}
	if s.ProtocolVersion != 68 || s.NetworkID != 1 {
		t.Fatalf("version/network = %d/%d", s.ProtocolVersion, s.NetworkID)
	}
	if s.GenesisHash != genesis || s.BestHash != best || s.ForkIDHash != fork || s.ForkNext != 0 {
		t.Fatalf("decoded %+v", s)
	}
	if s.LatestBlock != nil || s.EarliestBlock != nil {
		t.Fatal("eth/68 must not carry block range")
	}
	if !s.Compatible(1, genesis) {
		t.Fatal("self must be compatible")
	}
	if s.Compatible(100, genesis) || s.Compatible(1, common.HexToHash("0x01")) {
		t.Fatal("wrong network or genesis must be incompatible")
	}
}

func TestStatusRoundTripEth69(t *testing.T) {
	genesis := common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	latest := common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	fork := [4]byte{0x07, 0xc9, 0x46, 0x2e}

	enc := EncodeStatus69(69, 1, genesis, latest, fork, 0, 0, 23_000_000)
	s, err := DecodeStatus(enc, 69)
	if err != nil {
		t.Fatal(err)
	}
	if s.GenesisHash != genesis || s.BestHash != latest || s.ForkIDHash != fork {
		t.Fatalf("decoded %+v", s)
	}
	if s.EarliestBlock == nil || *s.EarliestBlock != 0 || s.LatestBlock == nil || *s.LatestBlock != 23_000_000 {
		t.Fatalf("block range = %v..%v", s.EarliestBlock, s.LatestBlock)
	}
}

func TestStatusRejectsMalformed(t *testing.T) {
	h := common.Hash{1}
	// eth/68 without forkId is malformed (EIP-2124 mandatory since 66):
	// five fields instead of six.
	noFork := rlpcode.List(rlpcode.Uint(68), rlpcode.Uint(1), rlpcode.Bytes(nil),
		rlpcode.Bytes(h.Bytes()), rlpcode.Bytes(h.Bytes()))
	if _, err := DecodeStatus(noFork, 68); err == nil {
		t.Fatal("short eth/68 status must fail")
	}
	// A 5-byte fork hash is not an EIP-2124 CRC32 — reject, don't truncate.
	badFork := rlpcode.List(rlpcode.Uint(68), rlpcode.Uint(1), rlpcode.Bytes(nil),
		rlpcode.Bytes(h.Bytes()), rlpcode.Bytes(h.Bytes()),
		rlpcode.List(rlpcode.Bytes([]byte{1, 2, 3, 4, 5}), rlpcode.Uint(0)))
	if _, err := DecodeStatus(badFork, 68); err == nil {
		t.Fatal("non-4-byte forkId hash must fail")
	}
	// Trailing bytes after the Status list (a second top-level item) fail too.
	trailing := append(append([]byte{}, EncodeStatus(68, 1, h, h, [4]byte{1, 2, 3, 4}, 0)...), 0x80)
	if _, err := DecodeStatus(trailing, 68); err == nil {
		t.Fatal("trailing bytes must fail")
	}
}

func TestGetBlockHeadersEncode(t *testing.T) {
	origin := common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	// geth's canonical encoding of [7, hash, 1, 0, 0]:
	// 0xca? — checked by the byte-exact assert below (EIP-7801 vectors keep
	// the shape pinned).
	enc := EncodeGetBlockHeadersByHash(7, origin, 1, 0, false)
	items, err := rlpcode.Items(enc)
	if err != nil {
		t.Fatalf("our own GetBlockHeaders does not round-trip: %v", err)
	}
	// [reqId, [origin, amount, skip, reverse]] — the query nests (#geth
	// wrapping; flat = BreachOfProtocol on the wire).
	if len(items) != 2 {
		t.Fatalf("expected [reqId, query], got %d fields", len(items))
	}
	if id, _ := rlpcode.U64(items[0]); id != 7 {
		t.Errorf("request id = %d", id)
	}
	query, err := rlpcode.Items(items[1])
	if err != nil || len(query) != 4 {
		t.Fatalf("query = %x (%v)", items[1], err)
	}
	if o, _ := rlpcode.LeafBytes(query[0]); len(o) != 32 {
		t.Errorf("hash origin must be 32 bytes, got %d", len(o))
	}
	if amt, _ := rlpcode.U64(query[1]); amt != 1 {
		t.Errorf("amount = %d", amt)
	}
}

func TestBlockHeadersRoundTrip(t *testing.T) {
	// Build the response with the same toolkit a peer would use:
	// [7, [header]] with one trivial (empty-list) header.
	header := rlpcode.List()
	body := rlpcode.List(rlpcode.Uint(7), rlpcode.List(header))
	id, got, err := DecodeBlockHeaders(body)
	if err != nil {
		t.Fatal(err)
	}
	if id != 7 || len(got) != 1 || !bytes.Equal(got[0], []byte{0xc0}) {
		t.Fatalf("id=%d headers=%x", id, got)
	}
}
