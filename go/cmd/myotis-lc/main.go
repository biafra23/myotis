// Command myotis-lc is the Go engine's beacon-chain light client: it
// bootstraps from the embedded mainnet checkpoint over libp2p
// req/resp, walks the sync-committee update chain to the wall-clock
// period, and polls finality updates — every header BLS-verified, the
// only trust inputs the two embedded anchors (docs/spec/01).
//
// Usage:
//
//	myotis-lc            # bootstrap, catch up, poll finality, print the anchor
//	myotis-lc -once      # exit after the first poll advances the anchor
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clsync"
	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/biafra23/myotis/go/internal/lc"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	once := flag.Bool("once", false, "exit after the first finality poll that advances the anchor")
	discPort := flag.Int("disc-port", 0, "if > 0, run discv5 CL discovery on this UDP port too")
	timeout := flag.Duration("timeout", 5*time.Minute, "overall budget")
	probeRange := flag.Int("probe-range", 0, "after catch-up, ask peers for the last N periods of updates (wire probe)")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.Ltime)
	logf := func(f string, a ...any) { logger.Printf(f, a...) }

	c := chain.ConsensusMainnet()
	h, err := clsync.NewHost()
	if err != nil {
		log.Fatalf("libp2p host: %v", err)
	}
	defer h.Close()

	syncer := clsync.NewSyncer(c, h, logf)
	// Our Status answers with the live store view once it exists.
	clsync.InstallGossipSubHold(h)
	var lcStore *lc.Store
	clsync.ServeInstall(h, func() *clwire.StatusMessage {
		wall := time.Now().Unix()
		slot := c.SlotAt(wall)
		m := &clwire.StatusMessage{
			ForkDigest: clwire.CurrentForkDigest(c, wall),
			HeadSlot:   slot,
		}
		if lcStore != nil {
			m.FinalizedEpoch = lcStore.Finalized.Slot / chain.SlotsPerEpoch
			m.FinalizedRoot = lcStore.Finalized.StateRoot
		}
		return m
	})

	if *discPort > 0 {
		peers := make(chan peer.AddrInfo, 64)
		stop, err := clsync.StartDiscV5(*discPort, func() [4]byte {
			return clwire.CurrentForkDigest(c, time.Now().Unix())
		}, peers)
		if err != nil {
			logf("discv5 unavailable (%v) — static pins only", err)
		} else {
			defer stop()
			go func() {
				for p := range peers {
					logf("discovered LC peer %s", p.ID)
					syncer.AddPeer(p)
				}
			}()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	st, err := syncer.RunBootstrap(ctx)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	lcStore = st

	if err := syncer.RunCatchUp(ctx, st); err != nil {
		log.Fatalf("catch-up: %v", err)
	}

	// -probe-range N exercises the updates_by_range wire against live
	// servers even when catch-up has nothing to do (a fresh checkpoint
	// lands inside the current period): ask for the last N periods and
	// report what decodes and what the processor's gates say. Updates
	// older than the store's period are EXPECTED to be rejected by the
	// #423 period gate — a clean rejection is the proof the path works.
	if *probeRange > 0 {
		syncer.ProbeUpdates(ctx, st, uint64(*probeRange))
	}

	// Finality poll: once per slot, the steady state of the Rust loop.
	for ctx.Err() == nil {
		outcome, err := syncer.PollFinality(ctx, st)
		if err != nil {
			logf("finality poll: %v", err)
		} else {
			logf("finality poll: outcome %v, finalized slot %d", outcome, st.Finalized.Slot)
			if outcome == lc.Advanced && *once {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(chain.SecondsPerSlot) * time.Second):
		}
	}

	fmt.Printf("finalized_slot=%d\nfinalized_exec_state_root=%s\n",
		st.Finalized.Slot, hex(st.FinalizedStateRoot()))
}

func hex(b [32]byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range b {
		out[2*i] = d[c>>4]
		out[2*i+1] = d[c&0xf]
	}
	return string(out)
}
