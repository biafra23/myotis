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
// errors happened to arrive. Every case below therefore carries a
// LastAttempt chosen to PROVOKE the old classifier in both directions.

func TestClassifyReadFailure(t *testing.T) {
	addr := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	live, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	// A socket-read deadline error: matches os.ErrDeadlineExceeded,
	// must NOT Is-match context.DeadlineExceeded (pinned below).
	sockTimeout := fmt.Errorf("read tcp 10.0.0.5:41912->3.15.200.12:30303: i/o timeout")
	// A transport timeout on an established session (snapread's shape).
	transportTimeout := errors.New("transport: timed out awaiting GetAccountRange")

	if errors.Is(os.ErrDeadlineExceeded, context.DeadlineExceeded) {
		t.Fatal("premise moved: a socket deadline now Is-matches context.DeadlineExceeded;" +
			" re-read classifyReadFailure's comment before touching this file")
	}

	tbl := []struct {
		name  string
		ctx   context.Context
		err   error
		want  error // nil = clean exit; errWant = returned unchanged
		match string
	}{
		{
			name: "cancelled read with a socket-timeout last attempt is the clean exit",
			ctx:  cancelled,
			err:  &engine.ReadError{Reason: context.Canceled, LastAttempt: sockTimeout},
			want: nil,
		},
		{
			name: "cancelled read with a transport-timeout last attempt is the clean exit",
			ctx:  cancelled,
			err:  &engine.ReadError{Reason: context.Canceled, LastAttempt: transportTimeout},
			want: nil,
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
			want: nil,
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
			if c.want != nil || got == nil {
				if !errors.Is(got, c.want) && got != c.want {
					t.Fatalf("classifyReadFailure = %v, want %v", got, c.want)
				}
			}
			if c.match != "" && (got == nil || got.Error() != c.match) {
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
