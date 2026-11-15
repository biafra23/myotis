package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/biafra23/myotis/go/internal/engine"
	"github.com/ethereum/go-ethereum/common"
)

// The exit-taxonomy table of classifyReadFailure. The point of these
// pins (PR #861 round-3 review) is that the decision NEVER reads
// LastAttempt's Is-matchability: what arrives there is a peer/transport
// error of the last attempt, and on Go >= 1.16 a socket-read deadline
// error matches os.ErrDeadlineExceeded but NOT context.DeadlineExceeded
// (only dial timeouts match the sentinel), so an errors.Is(err,
// DeadlineExceeded) classifier was right only by accident of which
// errors happened to arrive. The discriminating row is the cancelled
// read whose LastAttempt DOES Is-match the sentinel (a dial-timeout
// shape): the old errors.Is classifier turned it into "read window
// expired" (exit 1), this one exits clean — the rows are only a
// regression test if at least one separates the two classifiers
// (round-4 review: run the table against the removed switch and
// everything but this row agrees).

func TestClassifyReadFailure(t *testing.T) {
	addr := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	live, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	// A socket-read deadline error as net really returns it: wraps
	// os.ErrDeadlineExceeded, must NOT Is-match context.DeadlineExceeded
	// (premise pinned below).
	sockTimeout := fmt.Errorf("read tcp 10.0.0.5:41912->3.15.200.12:30303: %w", os.ErrDeadlineExceeded)
	if !errors.Is(sockTimeout, os.ErrDeadlineExceeded) || errors.Is(sockTimeout, context.DeadlineExceeded) {
		t.Fatal("fixture premise broken: a wrapped socket deadline must match os.ErrDeadlineExceeded only")
	}
	// A transport timeout on an established session (snapread's shape).
	transportTimeout := errors.New("transport: timed out awaiting GetAccountRange")
	// A dial timeout — the shape that DOES Is-match the sentinel, and
	// the only fixture here the removed errors.Is classifier got wrong.
	dialTimeout := fmt.Errorf("dial: %w", context.DeadlineExceeded)

	if errors.Is(os.ErrDeadlineExceeded, context.DeadlineExceeded) {
		t.Fatal("premise moved: a socket deadline now Is-matches context.DeadlineExceeded;" +
			" re-read classifyReadFailure's comment before touching this file")
	}

	tbl := []struct {
		name  string
		ctx   context.Context
		err   error
		match string // "" = the clean exit (nil), else the exact message
	}{
		{
			name: "cancelled read with a socket-timeout last attempt is the clean exit",
			ctx:  cancelled,
			err:  &engine.ReadError{Reason: context.Canceled, LastAttempt: sockTimeout},
		},
		{
			name: "cancelled read with a transport-timeout last attempt is the clean exit",
			ctx:  cancelled,
			err:  &engine.ReadError{Reason: context.Canceled, LastAttempt: transportTimeout},
		},
		{
			// THE discriminating row: old classifier (errors.Is through
			// Unwrap) said "read window expired" / exit 1 here; the
			// Reason-based one must exit clean.
			name: "cancelled read whose last attempt Is-matches the deadline sentinel is still the clean exit",
			ctx:  cancelled,
			err:  &engine.ReadError{Reason: context.Canceled, LastAttempt: dialTimeout},
		},
		{
			name:  "expired window names the last attempt",
			ctx:   live,
			err:   &engine.ReadError{Reason: context.DeadlineExceeded, LastAttempt: transportTimeout},
			match: "read window expired before 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 could be served: last failure: transport: timed out awaiting GetAccountRange",
		},
		{
			name:  "an LC death that wraps its own deadline is not a window expiry",
			ctx:   live,
			err:   &engine.LCError{Err: fmt.Errorf("bootstrap budget: %w", context.DeadlineExceeded)},
			match: "light client: bootstrap budget: context deadline exceeded",
		},
		{
			name: "a shutdown the engine never saw is still the clean exit",
			ctx:  cancelled,
			err:  errors.New("engine: closed"),
		},
		{
			name:  "a real failure with a live context passes through",
			ctx:   live,
			err:   errors.New("engine: \"zzz\" is not a hex address"),
			match: "engine: \"zzz\" is not a hex address",
		},
	}
	for _, c := range tbl {
		t.Run(c.name, func(t *testing.T) {
			got := classifyReadFailure(c.ctx, c.err, addr)
			if c.match == "" {
				// The clean-exit rows: a non-nil return MUST fail here
				// (round-4 review: the old `if c.want != nil || got ==
				// nil` shape let every nil-want row pass vacuously).
				if got != nil {
					t.Fatalf("classifyReadFailure = %v, want the clean exit (nil)", got)
				}
				return
			}
			if got == nil || got.Error() != c.match {
				t.Fatalf("classifyReadFailure = %v, want message %q", got, c.match)
			}
		})
	}

	// The LCError case must stay catchable as *engine.LCError by the
	// caller's own errors.As (the arm returns it unchanged).
	if _, ok := classifyReadFailure(live, &engine.LCError{Err: context.DeadlineExceeded}, addr).(*engine.LCError); !ok {
		t.Fatal("LCError must be returned unchanged (castable), for the caller's taxonomy")
	}
	// The expired-window message WRAPS the last attempt (errors.Is/As
	// across it), as the old arm's %w did.
	exp := classifyReadFailure(live, &engine.ReadError{Reason: context.DeadlineExceeded, LastAttempt: transportTimeout}, addr)
	if !errors.Is(exp, transportTimeout) {
		t.Fatal("the window-expired error must wrap the last attempt")
	}
}
