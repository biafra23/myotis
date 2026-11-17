package engine

// publish() is a close-and-replace broadcast, not a one-receiver
// nudge: with concurrent Account calls (permitted by the contract,
// required by the part 1b C ABI), every blocked reader must wake on a
// new anchor, not just whichever one happens to own the buffered
// token (PR #819 review).

import (
	"sync"
	"testing"
	"time"
)

func TestPublishWakesEveryWaiter(t *testing.T) {
	e := &Engine{anchorSig: make(chan struct{})}
	const waiters = 4
	var wg sync.WaitGroup
	woken := make([]<-chan struct{}, waiters)
	for i := 0; i < waiters; i++ {
		e.mu.Lock()
		sig := e.anchorSig // what Account captures per loop iteration
		e.mu.Unlock()
		done := make(chan struct{})
		woken[i] = done
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-sig
			close(done)
		}()
	}
	e.publish(Anchor{BeaconSlot: 7})
	got := make(chan struct{})
	go func() { wg.Wait(); close(got) }()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("publish woke fewer than all waiters — the nudge regressed to one-receiver")
	}
	if a, ok := e.Anchor(); !ok || a.BeaconSlot != 7 {
		t.Fatalf("Anchor() = %+v, %v after publish", a, ok)
	}
}
