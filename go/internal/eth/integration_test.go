// Integration test: our dialer against a real go-ethereum p2p server with a
// mock eth/68 protocol handler, over loopback TCP. Deterministic proof of the
// full path — RLPx EIP-8 handshake, Hello/capability negotiation with
// geth's own snappy toggling, Status exchange with our pinned fork id, and
// request-id correlated GetBlockHeaders — without depending on public
// mainnet peers having free inbound slots.
package eth

import (
	"context"
	"crypto/ecdsa"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

type mockEth struct {
	// overrides for what the mock sends in its Status; zero values are the
	// correct mainnet-shaped ones.
	networkID  uint64
	forkHash   [4]byte
	forkNext   uint64
	badGenesis bool
}

// newMockGeth starts a geth p2p.Server on a free loopback port speaking a
// single mock eth/68 capability. Returns the server and its ENR.
func newMockGeth(t *testing.T, m mockEth) (*p2p.Server, *enode.Node) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if m.networkID == 0 {
		m.networkID = 1
	}
	if m.forkHash == [4]byte{} {
		m.forkHash = [4]byte{0x07, 0xc9, 0x46, 0x2e}
	}

	srv := &p2p.Server{Config: p2p.Config{
		PrivateKey:  key,
		MaxPeers:    4,
		NoDiscovery: true,
		ListenAddr:  "127.0.0.1:0",
		Protocols: []p2p.Protocol{{
			Name:    "eth",
			Version: 68,
			Length:  17,
			Run:     m.run,
		}},
	}}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv, srv.LocalNode().Node()
}

// Protocol-relative codes: the MsgReadWriter handed to a p2p.Protocol's Run
// strips the capability's base offset (0x10), so eth Status arrives as 0x00
// and messages sent here are re-based on the wire.
const (
	relStatus          = 0x00
	relGetBlockHeaders = 0x03
	relBlockHeaders    = 0x04
)

func (m mockEth) run(_ *p2p.Peer, rw p2p.MsgReadWriter) error {
	genesis := chain.Mainnet().GenesisHash
	if m.badGenesis {
		genesis = chain.Mainnet().GenesisHash
		genesis[0] ^= 0xff
	}
	// Read our Status, then answer with theirs.
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	var their status68
	if err := msg.Decode(&their); err != nil {
		return err
	}

	head := mockHeaderChain(3) // head, head-1, head-2 in wire order
	bestHash := head[0].hash

	st := status68{
		Version:   68,
		NetworkID: m.networkID,
		TD:        rlp.RawValue{0x80},
		BestHash:  bestHash,
		Genesis:   genesis,
		ForkID:    forkIDRLP{Hash: m.forkHash, Next: m.forkNext},
	}
	if err := p2p.Send(rw, relStatus, st); err != nil {
		return err
	}

	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			return err
		}
		switch msg.Code {
		case relGetBlockHeaders:
			var req struct {
				ReqID uint64
				Query struct {
					Origin  rlp.RawValue
					Amount  uint32
					Skip    uint32
					Reverse bool
				}
			}
			if err := msg.Decode(&req); err != nil {
				return err
			}
			sent := head
			if !req.Query.Reverse {
				sent = head[:1] // forward from the head can answer only one
			}
			raws := make([]rlp.RawValue, 0, len(sent))
			for _, h := range sent {
				raws = append(raws, h.raw)
			}
			if err := p2p.Send(rw, relBlockHeaders, []any{req.ReqID, raws}); err != nil {
				return err
			}
		default:
			_, _ = io.Copy(io.Discard, msg.Payload)
		}
	}
}

type mockHeader struct {
	raw  []byte
	hash [32]byte
	num  uint64
}

// mockHeaderChain builds n linked mainnet-ish headers, returned head-first.
func mockHeaderChain(n int) []mockHeader {
	out := make([]mockHeader, n)
	parent := [32]byte{}
	for i := n - 1; i >= 0; i-- {
		num := uint64(21_000_000 - uint64(i))
		h := &types.Header{
			ParentHash: parent,
			Number:     new(big.Int).SetUint64(num),
			Time:       1_760_000_000 + num,
			GasLimit:   36_000_000,
			Difficulty: big.NewInt(0),
		}
		raw, err := rlp.EncodeToBytes(h)
		if err != nil {
			panic(err)
		}
		hh := h.Hash()
		out[i] = mockHeader{raw: raw, hash: hh, num: num}
		parent = hh
	}
	// Built lowest-first with parent links forward; delivered head-first
	// already: num = 21_000_000 - i means out[0] carries the highest number.
	return out
}

func dialCtx(t *testing.T) (context.Context, *ecdsa.PrivateKey, *chain.Network) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx, key, chain.Mainnet()
}

func TestDialMockGethHandshakeAndHeaders(t *testing.T) {
	_, srvNode := newMockGeth(t, mockEth{})
	ctx, key, netw := dialCtx(t)

	peer, err := Dial(ctx, key, srvNode, netw, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer peer.Close()

	if peer.Version != 68 {
		t.Errorf("negotiated %d, want 68", peer.Version)
	}
	if peer.Status.NetworkID != 1 {
		t.Errorf("status network = %d", peer.Status.NetworkID)
	}

	headers, err := peer.GetBlockHeaders(peer.Status.BestHash, 3)
	if err != nil {
		t.Fatalf("GetBlockHeaders: %v", err)
	}
	if len(headers) != 3 {
		t.Fatalf("got %d headers", len(headers))
	}
	if headers[0].Hash != peer.Status.BestHash {
		t.Errorf("head %s != status best %s", headers[0].Hash, peer.Status.BestHash)
	}
	if headers[0].Number != 21_000_000 || headers[2].Number != 20_999_998 {
		t.Errorf("numbers %d..%d", headers[0].Number, headers[2].Number)
	}
}

// The mismatch tests must fail for the protocol reason, not a timeout.
func dialFailsWith(t *testing.T, m mockEth, want string) {
	t.Helper()
	_, srvNode := newMockGeth(t, m)
	ctx, key, netw := dialCtx(t)
	start := time.Now()
	_, err := Dial(ctx, key, srvNode, netw, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatalf("expected rejection (%s)", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("rejection reason = %v, want it to mention %q", err, want)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("rejection took %v — looks like a timeout, not a protocol decision", d)
	}
}

func TestDialNetworkMismatch(t *testing.T) {
	dialFailsWith(t, mockEth{networkID: 100, forkHash: [4]byte{0x01, 0x02, 0x03, 0x04}}, "network 100")
}

func TestDialGenesisMismatch(t *testing.T) {
	dialFailsWith(t, mockEth{badGenesis: true}, "genesis")
}

func TestDialForkIDMismatch(t *testing.T) {
	dialFailsWith(t, mockEth{forkHash: [4]byte{0xde, 0xad, 0xbe, 0xef}}, "fork id")
}
