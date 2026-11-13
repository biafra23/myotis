package clsync

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/biafra23/myotis/go/internal/lc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// TestCatchUpThroughCorpusOverLibp2p replays the shared LC corpus
// through the LIVE loop — RunBootstrap's pin, the Status exchange,
// the updates_by_range wire, DecodeMultiChunk and the processor —
// over two real in-process hosts. It is the regression pin for the
// PR #770 review's High finding: an ask that starts at storePeriod+1
// can never apply ANY update from a fresh bootstrap (the bootstrap
// carries no next committee; the store's OWN period is the only one
// it can verify, and that update is what delivers the next one). The
// old loop would period-gate all 13 chunks, round 25, and return
// "catch-up stalled" — log.Fatalf in main.
//
// The corpus checkpoint (period 1777) is older than this test's own
// wall period by design, and the wall is pinned INTO the bound:
// 1777 + 13 = 1790 exactly satisfies the weak-subjectivity checks
// (start gate and in-run), which is why Syncer.Now exists.
func TestCatchUpThroughCorpusOverLibp2p(t *testing.T) {
	c := *chain.ConsensusMainnet()
	dir := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")

	bootSSZ, err := os.ReadFile(filepath.Join(dir, "bootstrap.ssz"))
	if err != nil {
		t.Fatal(err)
	}
	boot, err := lc.DecodeBootstrap(bootSSZ)
	if err != nil {
		t.Fatal(err)
	}
	if boot.Header.Beacon.Slot/chain.SlotsPerSyncCommitteePeriod != 1777 {
		t.Fatalf("corpus moved? bootstrap period %d",
			boot.Header.Beacon.Slot/chain.SlotsPerSyncCommitteePeriod)
	}
	c.CheckpointRoot = common.Hash(boot.Header.Beacon.Root())
	c.CheckpointSlot = boot.Header.Beacon.Slot

	// Wall clock: period 1790 = checkpoint + 13, inside the bound.
	const wallPeriod = 1790
	wallSlot := uint64(wallPeriod*chain.SlotsPerSyncCommitteePeriod + 100)
	now := time.Unix(int64(c.GenesisTime+wallSlot*chain.SecondsPerSlot), 0)
	digest := clwire.CurrentForkDigest(&c, now.Unix())

	// Index the accepted chain by signature period (the ask is a
	// period range; a real server serves exactly the range it was asked
	// for and nothing else).
	byPeriod := map[uint64][]byte{}
	for i := 1; i <= 18; i++ {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%03d-update.ssz", i)))
		if err != nil {
			t.Fatal(err)
		}
		u, err := lc.DecodeUpdate(b)
		if err != nil {
			t.Fatal(err)
		}
		byPeriod[u.SignatureSlot/chain.SlotsPerSyncCommitteePeriod] = b
	}

	srv, err := NewListeningHostForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ServeInstall(srv, func() *clwire.StatusMessage {
		return (&Syncer{Consensus: &c, Now: func() time.Time { return now }}).LocalStatus()
	})
	srv.SetStreamHandler(protocol.ID(clwire.Bootstrap), func(s network.Stream) {
		defer s.Reset()
		_, _ = s.Write(clwire.EncodeSuccessResponse(bootSSZ, &digest))
		_ = s.Close()
	})
	srv.SetStreamHandler(protocol.ID(clwire.UpdatesByRange), func(s network.Stream) {
		defer s.Reset()
		raw, err := readAllCapped(s, 1<<20)
		if err != nil {
			return
		}
		body, err := clwire.ParseRequestSszExpecting(raw, 16)
		if err != nil || len(body) != 16 {
			_, _ = s.Write(clwire.EncodeErrorResponse(clwire.ResultInvalidRequest, "bad range"))
			_ = s.Close()
			return
		}
		start := binary.LittleEndian.Uint64(body[:8])
		count := binary.LittleEndian.Uint64(body[8:])
		var out []byte
		for p := start; p < start+count; p++ {
			if u, ok := byPeriod[p]; ok {
				out = append(out, clwire.EncodeSuccessResponse(u, &digest)...)
			}
		}
		_, _ = s.Write(out)
		_ = s.Close()
	})

	cli, err := NewHost()
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	s := &Syncer{
		Consensus: &c,
		H:         cli,
		Logf:      func(f string, a ...any) { t.Logf(f, a...) },
		Now:       func() time.Time { return now },
		peers:     map[peer.ID]*peerState{},
	}
	s.AddPeer(peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	store, err := s.RunBootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := store.Period(); got != 1777 {
		t.Fatalf("store period after bootstrap = %d, want 1777", got)
	}
	if store.NextCommittee != nil {
		t.Fatal("bootstrap unexpectedly carries a next committee")
	}

	if err := s.RunCatchUp(ctx, store); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	if got := store.Period(); got != wallPeriod {
		t.Fatalf("store period after catch-up = %d, want %d "+
			"(this is the start-period regression: an ask from +1 applies nothing)", got, wallPeriod)
	}
	if store.Finalized.Slot <= boot.Header.Beacon.Slot {
		t.Fatalf("finalized slot did not advance: %d → %d",
			boot.Header.Beacon.Slot, store.Finalized.Slot)
	}
}
