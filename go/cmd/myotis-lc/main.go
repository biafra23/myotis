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
	// Validate BEFORE any uint64 conversion: a negative would wrap to
	// ~1.8e19 and anything above the batch cap reads as a truncating
	// server instead of a wiring bug.
	if *probeRange < 0 || *probeRange > clwire.MaxUpdatesByRange {
		log.Fatalf("-probe-range must be in [0, %d], got %d", clwire.MaxUpdatesByRange, *probeRange)
	}

	logger := log.New(os.Stderr, "", log.Ltime)
	logf := func(f string, a ...any) { logger.Printf(f, a...) }

	c := chain.ConsensusMainnet()
	h, err := clsync.NewHost()
	if err != nil {
		log.Fatalf("libp2p host: %v", err)
	}
	defer h.Close()

	syncer := clsync.NewSyncer(c, h, logf)
	// The Syncer owns the store; ServeInstall answers inbound Status
	// through it (LocalStatus reads it under lock) so a poll
	// goroutine mutating the store can never tear what we announce.
	clsync.InstallGossipSubHold(h)
	clsync.ServeInstall(h, syncer.LocalStatus)

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

	// Steady state, one slot per cycle, shaped by the Rust outer loop
	// (sync.rs:2560-2592): EVERY cycle first re-runs catch-up (a no-op
	// while current), and the finality poll is skipped while the
	// committee is behind — the store's committee may go stale under
	// this loop when the wall clock crosses a period boundary, and a
	// finality update signed by the next committee cannot verify until
	// catch-up delivers it (docs/spec/01 §9.4: the poll loop must
	// re-fetch at every period crossing "or finality verifies fail
	// indefinitely").
	advanced := false
	for ctx.Err() == nil {
		if err := syncer.RunCatchUp(ctx, st); err != nil {
			logf("re-catch-up: %v", err)
		} else if chain.SyncCommitteePeriod(
			syncer.Consensus.SlotAt(time.Now().Unix())) > st.Period() {
			logf("committee behind wall clock after re-catch-up; skipping finality poll this cycle")
		} else {
			outcome, err := syncer.PollFinality(ctx, st)
			if err != nil {
				logf("finality poll: %v", err)
			} else {
				logf("finality poll: outcome %v, finalized slot %d", outcome, st.Finalized.Slot)
				if outcome == lc.Advanced {
					advanced = true
					if *once {
						break
					}
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(chain.SecondsPerSlot) * time.Second):
		}
	}

	fmt.Printf("finalized_slot=%d\nfinalized_exec_state_root=%s\n",
		st.Finalized.Slot, hex(st.FinalizedStateRoot()))

	// A budget that ran out without one Advanced is a failure, not a
	// quiet success: a smoke keying off the exit code must not pass
	// vacuously when every poll errored.
	if *once && !advanced {
		log.Fatalf("budget expired without a finality advance (finalized slot %d)", st.Finalized.Slot)
	}
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
