// Command myotis-go is the Go engine. As of this revision it does one thing:
// discover mainnet execution-layer peers (discv4 + EIP-1459) and report them.
// RLPx/eth, the consensus light client and verified snap reads land as the
// following parts on feature/go-engine.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/discovery"
	"github.com/biafra23/myotis/go/internal/nodekey"
)

func main() {
	defaultDir := "myotis-go-data"
	if cd, err := os.UserConfigDir(); err == nil {
		defaultDir = cd + "/myotis-go"
	}
	var (
		dataDir    = flag.String("datadir", defaultDir, "directory for the node key and peer database")
		listenPort = flag.Int("port", chain.Mainnet().ListenPort, "discv4 UDP port (0 = network default, -1 = ephemeral)")
		runFor     = flag.Duration("run-for", 0, "exit after this duration (0 = run until interrupted)")
		quiet      = flag.Bool("quiet", false, "log only new peers, not the periodic summary")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := run(*dataDir, *listenPort, *runFor, *quiet, log); err != nil {
		log.Error("myotis-go: " + err.Error())
		os.Exit(1)
	}
}

func run(dataDir string, listenPort int, runFor time.Duration, quiet bool, log *slog.Logger) error {
	netCfg := chain.Mainnet() // the one network for now

	key, err := nodekey.Load(dataDir)
	if err != nil {
		return err
	}
	log.Info("node identity",
		"nodeId", fmt.Sprintf("%x", nodekey.NodeID(&key.PublicKey)),
		"datadir", dataDir)

	disc, err := discovery.Start(discovery.Config{
		DataDir:    dataDir,
		Network:    netCfg,
		Key:        key,
		ListenPort: listenPort,
		Logger:     log,
		OnDiscovered: func(c discovery.Candidate) {
			log.Info("peer discovered",
				"id", c.ID.String(),
				"addr", fmt.Sprintf("%s:%d", c.Node.IP(), c.Node.TCP()),
				"via", c.Source)
		},
	})
	if err != nil {
		return err
	}
	defer disc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var deadline <-chan time.Time
	if runFor > 0 {
		t := time.NewTimer(runFor)
		defer t.Stop()
		deadline = t.C
	}

	summary := time.NewTicker(30 * time.Second)
	defer summary.Stop()
	for {
		select {
		case <-ctx.Done():
			report(disc, log)
			return nil
		case <-deadline:
			report(disc, log)
			return nil
		case <-summary.C:
			if !quiet {
				report(disc, log)
			}
		}
	}
}

func report(disc *discovery.Service, log *slog.Logger) {
	table, live, bySource := disc.Stats()
	peers := make([]any, 0, len(bySource))
	for src, n := range bySource {
		peers = append(peers, slog.Any(string(src), n))
	}
	log.Info("discovery summary",
		"tableNodes", table, "liveNodes", live, "dialablePeers", peers)
}
