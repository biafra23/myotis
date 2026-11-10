package discovery

import (
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func node(t *testing.T, ip string, tcp, udp int) *enode.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return enode.NewV4(&key.PublicKey, net.ParseIP(ip), tcp, udp)
}

func TestAddCandidateFiltersAndDedups(t *testing.T) {
	var mu sync.Mutex
	var fired []Candidate
	s := &Service{
		log:        slog.New(slog.DiscardHandler),
		candidates: map[enode.ID]Candidate{},
		cfg:        Config{OnDiscovered: func(c Candidate) { mu.Lock(); fired = append(fired, c); mu.Unlock() }},
	}

	good := node(t, "203.0.113.7", 30303, 30303)
	s.addCandidate(SourceDNS, good)
	s.addCandidate(SourceDiscv4, good) // dedup: same id, no second fire

	noTCP := node(t, "203.0.113.8", 0, 30303) // discovery-only record: not dialable
	s.addCandidate(SourceDNS, noTCP)

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 {
		t.Fatalf("OnDiscovered fired %d times, want 1", len(fired))
	}
	if fired[0].Source != SourceDNS || fired[0].ID != good.ID() {
		t.Errorf("fired with %+v", fired[0])
	}
	if c := s.candidates[good.ID()]; c.FirstSeen.IsZero() {
		t.Error("candidate not recorded")
	}
}

// A peer first seen with a stale DNS-tree endpoint must be updated (and the
// listener re-fired) when discv4 later proves a live address.
func TestAddCandidateUpdatesMovedEndpoint(t *testing.T) {
	var mu sync.Mutex
	var fired []Candidate
	s := &Service{
		log:        slog.New(slog.DiscardHandler),
		candidates: map[enode.ID]Candidate{},
		cfg:        Config{OnDiscovered: func(c Candidate) { mu.Lock(); fired = append(fired, c); mu.Unlock() }},
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	stale := enode.NewV4(&key.PublicKey, net.ParseIP("203.0.113.1"), 30303, 30303)
	moved := enode.NewV4(&key.PublicKey, net.ParseIP("203.0.113.2"), 30304, 30304)
	if stale.ID() != moved.ID() {
		t.Fatal("test nodes must share an id")
	}

	s.addCandidate(SourceDNS, stale)
	s.addCandidate(SourceDiscv4, moved) // same id, new endpoint → update + re-fire
	s.addCandidate(SourceDiscv4, moved) // unchanged → silent

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 2 {
		t.Fatalf("OnDiscovered fired %d times, want 2", len(fired))
	}
	if got := fired[1].Node.IP().String() + ":" + strconv.Itoa(fired[1].Node.TCP()); got != "203.0.113.2:30304" {
		t.Errorf("final endpoint = %s", got)
	}
	if fired[1].FirstSeen != fired[0].FirstSeen {
		t.Error("FirstSeen should survive the update")
	}
}

func TestCandidateDialEndpoint(t *testing.T) {
	n := node(t, "203.0.113.9", 30304, 30303)
	addr := net.JoinHostPort(n.IP().String(), strconv.Itoa(n.TCP()))
	if addr != "203.0.113.9:30304" {
		t.Errorf("dial endpoint = %s", addr)
	}
}
