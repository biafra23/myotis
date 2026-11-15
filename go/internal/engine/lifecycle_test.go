package engine

// Lifecycle regression tests (PR #827 review): the sync.Once reset in
// StartNetwork used to be a PROCESS-FATAL `unlock of unlocked mutex`
// on any discovery.Start failure (UDP bind, nodedb lock), and nothing
// in the suite took the failure path — so nothing caught it. These
// pin the failure path itself.

import (
	"net"
	"testing"
)

func TestStartNetworkBusyPortRetries(t *testing.T) {
	// Occupy a UDP port, point the engine at it, and expect an ERROR
	// (not a fatal, not a panic) — twice, because the whole point of
	// the mutex rewrite is that a failed attempt leaves retryable
	// state; then success once the port frees.
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := range 2 {
		if err := e.StartNetwork(); err == nil {
			sock.Close()
			t.Fatalf("StartNetwork #%d onto busy :%d returned nil, want a bind error", i+1, port)
		}
	}
	if err := sock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.StartNetwork(); err != nil {
		t.Fatalf("StartNetwork after freeing the port: %v", err)
	}
	if e.networkService() == nil {
		t.Fatal("successful StartNetwork must publish the service through networkService()")
	}
}

func TestStartNetworkAfterCloseRefused(t *testing.T) {
	// StartNetwork behind Close would start a discovery service
	// nothing ever closes (StartLC guards the same case).
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if err := e.StartNetwork(); err == nil {
		t.Fatal("StartNetwork after Close must error, not leak a service")
	}
}

func TestSetStaleAnchorPolicyWithdrawalMirrorsRust(t *testing.T) {
	// The ABI-59 remembered-answer semantics (PR #877 review), tested at
	// the layer that owns them: CONTINUE arms the same sticky consent the
	// one-shot accept uses (read by the syncer at every weak-subjectivity
	// gate), and REPLACING a CONTINUE with ASK withdraws it — exactly
	// host.rs's `set_stale_anchor_policy`, so a Settings flip from
	// "continue anyway" back to "ask me" makes a later park ask instead of
	// silently continuing on a consent the user revoked.
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.StaleAccepted() {
		t.Fatal("fresh engine must not have the consent armed")
	}
	if !e.SetStaleAnchorPolicy(2) { // CONTINUE
		t.Fatal("CONTINUE (2) must apply")
	}
	if !e.StaleAccepted() {
		t.Fatal("CONTINUE must arm the consent the gates read")
	}
	if !e.SetStaleAnchorPolicy(0) { // ASK
		t.Fatal("ASK (0) must apply")
	}
	if e.StaleAccepted() {
		t.Error("replacing CONTINUE with ASK must withdraw the consent CONTINUE armed")
	}
	// CHECKPOINT (1) is refused at this door too (the fetch is the engine-
	// parity gap; capabilities anchorRefresh:false) and a refused policy
	// must not disturb an armed consent (a one-shot accept stays armed).
	if !e.AcceptStale() {
		t.Fatal("AcceptStale (one-shot) must arm")
	}
	if e.SetStaleAnchorPolicy(1) {
		t.Error("CHECKPOINT (1) must be refused, not applied")
	}
	if !e.StaleAccepted() {
		t.Error("a REFUSED policy write must not withdraw an armed consent (apply-or-refuse)")
	}
}
