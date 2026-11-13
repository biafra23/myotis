package discovery

import (
	"encoding/hex"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// TestDecodePubkeyRefusesOutOfRangePoint pins the exact discv4 crash path the
// go-ethereum v1.16.8 -> v1.16.9 bump (PR #838) closes: a Neighbors entry
// carrying a NON-CANONICAL pubkey — x = P+1, a re-encoding of the valid point
// (1, y) that satisfies y^2 = x^3+7 (mod P) but is not a field element. On
// v1.16.8 v4wire.DecodePubkey's IsOnCurve checked the equation mod P only
// (CVE-2026-26314) and accepted it, and the accepted point then panicked in
// enode.NewV4 on the discovery goroutine — killing this process. v1.16.9's
// range check makes DecodePubkey refuse it here, before NewV4 is reached.
// v4wire is a dependency already (discovery.go builds/reads v4 messages), so
// this costs no go.sum line. The vector arithmetic is verified in the rlpx
// package's TestEcdhXRefusesOutOfRangeCoordinate comment.
func TestDecodePubkeyRefusesOutOfRangePoint(t *testing.T) {
	x, _ := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30") // P+1
	y, _ := hex.DecodeString("4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee") // sqrt(8) mod P
	var pk v4wire.Pubkey
	copy(pk[:32], x)
	copy(pk[32:], y)
	if _, err := v4wire.DecodePubkey(crypto.S256(), pk); err == nil {
		t.Fatal("out-of-range Neighbors pubkey accepted by DecodePubkey " +
			"(go-ethereum pin backslid to <= v1.16.8; enode.NewV4 would panic on it)")
	}
}

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

// The reviewer's flap scenario: DNS (lagging) and the discv4 table (live
// proof) both re-deliver their copy of the same node forever. The proven
// endpoint must win permanently — the stale DNS sample must never overwrite
// it or re-fire.
func TestProvenEndpointSurvivesStaleDNSResampling(t *testing.T) {
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
	live := enode.NewV4(&key.PublicKey, net.ParseIP("203.0.113.2"), 30304, 30304)

	s.addCandidate(SourceDNS, stale)
	s.addCandidate(SourceDiscv4, live) // proven upgrade, fires
	for range 5 {
		s.addCandidate(SourceDNS, stale)   // stale sampler round: must not overwrite
		s.addCandidate(SourceDiscv4, live) // table tick: unchanged, silent
	}

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 2 {
		t.Fatalf("OnDiscovered fired %d times, want 2 (one update, then stable)", len(fired))
	}
	c := s.candidates[live.ID()]
	if c.Source != SourceDiscv4 || c.Node.TCP() != 30304 {
		t.Errorf("stored candidate = %s %s, want discv4 proven endpoint", c.Source, c.Node.IP())
	}
}

func TestCandidateDialEndpoint(t *testing.T) {
	n := node(t, "203.0.113.9", 30304, 30303)
	addr := net.JoinHostPort(n.IP().String(), strconv.Itoa(n.TCP()))
	if addr != "203.0.113.9:30304" {
		t.Errorf("dial endpoint = %s", addr)
	}
}
