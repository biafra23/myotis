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
