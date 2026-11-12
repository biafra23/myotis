// Command myotis-go is the Go engine's CLI driver. The engine itself —
// discovery, RLPx dialing, the beacon light client, and the verified
// snap reads — lives in internal/engine (internal/engine), so the
// desktop host and the C ABI built on it drive the SAME machinery this
// CLI does. What remains here is the operator surface: flags, the
// human-readable log lines, and the exit codes.
//
// With -get-account the light client runs in parallel with EL
// discovery/dialing, and once both halves are up the CLI answers the
// account over snap — NONCE, BALANCE AND ROOTS PROVEN against the
// light client's anchored finalized execution state root, never taken
// from a peer's word.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/engine"
	"github.com/biafra23/myotis/go/internal/snapwire"
	"github.com/ethereum/go-ethereum/common"
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
		dialPeers  = flag.Bool("dial", true, "dial discovered peers over RLPx (false = discovery only)")
		maxDials   = flag.Int("max-concurrent-dials", 4, "concurrent outbound dials (min 1)")
		maxReady   = flag.Int("max-ready", 8, "cap on live READY sessions; waiting candidates are held in a backlog and dialed when a slot frees")
		logLevel   = flag.String("loglevel", "info", "log level: info|debug (debug lists each dial failure)")
		quiet      = flag.Bool("quiet", false, "log only new peers, not the periodic summary")
		getAccount = flag.String("get-account", "", "hex address: run the light client, wait for a snap peer, and print this account VERIFIED against the anchored finalized state root, then exit")
		slot       = flag.String("slot", "", "with -get-account: 32-byte hex storage slot to read too (two-hop, anchored at the PROVEN storageRoot)")
		jsonOut    = flag.Bool("json", false, "with -get-account: print the read in the engine-API result shape (eljson; one JSON line for the account, plus one for the slot with -slot) to stdout instead of log lines")
	)
	flag.Parse()
	if *slot != "" && *getAccount == "" {
		logFat := func(a ...any) { fmt.Fprintln(os.Stderr, a...); os.Exit(2) }
		logFat("-slot requires -get-account")
	}
	if *jsonOut && *getAccount == "" {
		logFat := func(a ...any) { fmt.Fprintln(os.Stderr, a...); os.Exit(2) }
		logFat("-json requires -get-account")
	}

	lvl := new(slog.LevelVar)
	if *logLevel == "debug" {
		lvl.Set(slog.LevelDebug)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	err := run(*dataDir, *listenPort, *runFor, *dialPeers, *maxDials, *maxReady, *quiet, log, *getAccount, *slot, *jsonOut)
	if err != nil {
		log.Error("myotis-go: " + err.Error())
		os.Exit(1)
	}
}

func run(dataDir string, listenPort int, runFor time.Duration, dialPeers bool, maxDials, maxReady int, quiet bool, log *slog.Logger, getAccount, slotHex string, jsonOut bool) error {
	var wantAddr common.Address
	if getAccount != "" {
		if !common.IsHexAddress(getAccount) {
			return fmt.Errorf("-get-account: %q is not a hex address", getAccount)
		}
		wantAddr = common.HexToAddress(getAccount)
	}
	var wantSlot [32]byte
	if slotHex != "" {
		// A slot INDEX (short or odd hex, e.g. "0") is left-padded to
		// the 32-byte key the trie uses — the Java CLI's
		// "get-storage <addr> <index>" ergonomics; anything wider than
		// a word stays an error.
		h := strings.TrimPrefix(slotHex, "0x")
		if len(h)%2 == 1 {
			h = "0" + h
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) > 32 {
			return fmt.Errorf("-slot: want ≤32 hex bytes, got %q (%v)", slotHex, err)
		}
		copy(wantSlot[32-len(b):], b)
	}

	e, err := engine.New(engine.Config{
		DataDir:     dataDir,
		ListenPort:  listenPort,
		DialPeers:   dialPeers,
		MaxDials:    maxDials,
		MaxReady:    maxReady,
		RequireSnap: getAccount != "", // read mode: only snap peers can serve it
		Logger:      log,
	})
	if err != nil {
		return err
	}
	defer e.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if runFor > 0 {
		tCtx, cancel := context.WithTimeout(ctx, runFor)
		defer cancel()
		ctx = tCtx
	}

	// The periodic summary (the 30 s ticker the old main loop carried).
	// It exits when ctx ends OR when the read settles (readDone, nil in
	// discovery mode so its arm never fires); the final report is always
	// printed by the paths below, matching the old loop exactly.
	readDone := make(chan struct{})
	sumDone := make(chan struct{})
	go func() {
		defer close(sumDone)
		if quiet {
			<-ctx.Done()
			return
		}
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-readDone:
				return
			case <-t.C:
				e.Report()
			}
		}
	}()

	if getAccount == "" {
		// Discovery/dial mode: run until the window or Ctrl-C.
		<-ctx.Done()
		close(readDone)
		<-sumDone
		e.Report()
		return nil
	}

	// A bounded window for the read mode: an honest failure beats
	// hanging until interrupted when no anchor or snap peer ever
	// arrives (the same honesty as myotis-lc -once's exit code). -run-for
	// IS the window when it was given (the old loop's deadline rule), so
	// the 10-minute cap only applies otherwise. The light client shares
	// the window: once the read settles, nothing needs the LC loop
	// anymore.
	readCtx := ctx
	if runFor == 0 {
		var cancelRead context.CancelFunc
		readCtx, cancelRead = context.WithTimeout(ctx, 10*time.Minute)
		defer cancelRead()
	}
	e.StartLC(readCtx)

	rd, err := e.Account(readCtx, wantAddr, wantSlot, slotHex != "")
	close(readDone)
	<-sumDone
	if err != nil {
		e.Report()
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			// The window named the cause when there was one, instead of
			// only the fact — kept from the old loop's wording.
			var re *engine.ReadError
			if errors.As(err, &re) && re.LastAttempt != nil {
				return fmt.Errorf("read window expired before %s could be served: last failure: %w", wantAddr.Hex(), re.LastAttempt)
			}
			return fmt.Errorf("read window expired before an anchor + snap peer could serve %s", wantAddr.Hex())
		}
		if ctx.Err() != nil {
			// Ctrl-C closes the race honestly: the read was aborted by
			// shutdown, not by a failure — the clean exit, as before.
			return nil
		}
		// The LC gave up (or the read otherwise failed for real): the
		// answer could never be VERIFIED, so the command cannot quietly
		// succeed.
		return err
	}

	if jsonOut {
		now := time.Now().Unix()
		line, err := rd.AccountJSON(now)
		if err != nil {
			return err
		}
		fmt.Println(line)
		if rd.Slot != nil {
			line, err := rd.StorageJSON(now)
			if err != nil {
				return err
			}
			fmt.Println(line)
		}
		return nil
	}
	printRead(log, rd)
	return nil
}

// printRead prints the verified read's human lines. Both lines print
// only once the WHOLE read is in hand (the engine handed back the
// account AND the slot hop together): logging the account line before
// a slot hop that then fails would make one run answer twice, the
// second time at a newer anchor. No line ever includes a peer's claim
// without saying so — every printed field comes from a proof leaf,
// verified against the anchor's root.
func printRead(log *slog.Logger, rd *engine.AccountRead) {
	addr := common.Address(rd.Address).Hex()
	attrs := []any{
		"account", addr,
		"verifiedAt", fmt.Sprintf("0x%x", rd.Anchor.StateRoot),
		"lcFinalizedSlot", rd.Anchor.BeaconSlot,
		"peers", rd.Peers,
	}
	switch rd.Outcome.State {
	case snapwire.AccountProvenAbsent:
		attrs = append(attrs, "accountState", "PROVEN ABSENT (empty account)")
		log.Info("verified account read", attrs...)
		if rd.Slot != nil {
			// Say so even though it needs no proof walk: an absent
			// account has no storage, so the slot the operator asked
			// for is provably zero. Silence here would leave "did it
			// read the slot?" unanswered.
			log.Info("verified storage read",
				"account", addr, "slot", fmt.Sprintf("0x%x", rd.Slot.Key),
				"value", "0x (provable: account is absent)",
				"verifyMethod", "provenAbsent→zero",
			)
		}
	case snapwire.AccountFound:
		l := rd.Outcome.Account
		attrs = append(attrs,
			"nonce", l.Nonce,
			"balanceWei", new(big.Int).SetBytes(l.Balance).String(),
			"storageRoot", fmt.Sprintf("0x%x", l.StorageRoot),
			"codeHash", fmt.Sprintf("0x%x", l.CodeHash),
			"verifyMethod", "snapProof→lcAnchor",
		)
		log.Info("verified account read", attrs...)
		if rd.Slot != nil {
			log.Info("verified storage read",
				"account", addr, "slot", fmt.Sprintf("0x%x", rd.Slot.Key),
				"value", fmt.Sprintf("0x%x", rd.Slot.Value),
				"anchoredAt", fmt.Sprintf("0x%x", l.StorageRoot), // the PROVEN one
				"verifyMethod", "snapProof→provenStorageRoot",
			)
		}
	}
}
