package clsync

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// TestBootstrapENRsParseAndFilter walks the embedded discv5 seed list
// and asserts the ENR plumbing end-to-end on real records: every seed
// parses, carries secp256k1 + TCP, and yields a libp2p AddrInfo. The
// eth2 digest check runs against the CURRENT accepted digest — the
// seeds span fork eras, so at least the recent ones (roost's carries
// the BPO-folded digest the Rust test pins) must pass the filter.
func TestBootstrapENRsParseAndFilter(t *testing.T) {
	c := chain.ConsensusMainnet()
	want := clwire.CurrentForkDigest(c, 1794355200) // 2026-11-11, BPO2 live
	if want != [4]byte{0x8C, 0x9F, 0x62, 0xFE} {
		t.Fatalf("digest moved: %x", want)
	}
	parsed, dialable, accepted := 0, 0, 0
	for _, s := range MainnetBootstrapENRs {
		n, err := enode.Parse(enode.ValidSchemes, s)
		if err != nil {
			t.Errorf("bootstrap ENR unparseable: %v", err)
			continue
		}
		parsed++
		info, ok := enrPeerInfo(n)
		if !ok || info.ID == "" {
			continue
		}
		dialable++
		if acceptedForDial(n, want) {
			accepted++
		}
	}
	if parsed != len(MainnetBootstrapENRs) {
		t.Fatalf("only %d/%d ENRs parsed", parsed, len(MainnetBootstrapENRs))
	}
	// Seeds drive discv5 over UDP; only SOME carry a TCP endpoint (the
	// QUIC-era Prysm/Lighthouse/EF records do not — part 3c's QUIC
	// transport would double this count). What must hold: the records
	// that DO carry TCP convert, and at least one carries the CURRENT
	// digest (roost's does, the BPO-folded value) — the filter finds
	// its peers through the walk, not by dialing seeds.
	if dialable < 5 {
		t.Fatalf("only %d ENRs yielded libp2p TCP addrs, want >= 5 (Teku×2, Nimbus×2, roost)", dialable)
	}
	if accepted == 0 {
		t.Fatal("no bootstrap ENR carries the current fork digest — the eth2 filter would find zero peers")
	}
}

// TestStaticParsesEveryStaticPeer: the multiaddrs copied from
// MAINNET_STATIC_PEERS must survive multiaddr + peer-ID parsing (a typo
// here kills the loop before the first dial).
func TestStaticParsesEveryStaticPeer(t *testing.T) {
	for _, m := range MainnetStaticPeers {
		a, err := parseMultiaddr(m)
		if err != nil {
			t.Fatalf("static peer %s: %v", m, err)
		}
		info, err := peerAddrInfo(a)
		if err != nil || info.ID == "" {
			t.Fatalf("static peer %s: %v", m, err)
		}
	}
}

// TestStaleGateConsentWaiverIsLogged pins the audit trail PR #877
// round 3 asked for: waiving the weak-subjectivity bound on the host's
// consent is the one trust decision in this flow, so it must leave a
// line in the log the hosts drain — once per loop, naming what it
// waived — while a refusal keeps its error and stays silent here (the
// refusal is reported by the caller that parks on it).
func TestStaleGateConsentWaiverIsLogged(t *testing.T) {
	const bound = 13
	cases := []struct {
		name     string
		accepted bool
		stale    bool
		wantErr  bool
		wantLogs int
	}{
		{"consent waives a stale anchor, once per loop", true, true, false, 1},
		{"no consent refuses a stale anchor", false, true, true, 0},
		{"fresh anchor needs no consent", false, false, false, 0},
		{"fresh anchor ignores consent", true, false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			s := &Syncer{
				Logf:          func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) },
				WsBound:       func() uint64 { return bound },
				StaleAccepted: func() bool { return tc.accepted },
			}
			// Staleness is period-granular (wall - anchor > bound).
			anchor, wall := uint64(bound), uint64(bound)
			if tc.stale {
				anchor, wall = bound+1, 2*bound+2 // gap bound+1 > bound
			}
			err := s.staleGate(anchor, wall, "held committee")
			err = s.staleGate(anchor, wall, "held committee") // second pass: no repeat
			if tc.wantErr != (errors.Is(err, ErrStaleAnchor)) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if len(lines) != tc.wantLogs {
				t.Fatalf("logged %d lines %q, want %d", len(lines), lines, tc.wantLogs)
			}
			for _, l := range lines {
				for _, want := range []string{"STALE ANCHOR", "period 14", "wall period 28", "bound 13", "waives"} {
					if !strings.Contains(l, want) {
						t.Errorf("waiver line %q missing %q", l, want)
					}
				}
			}
		})
	}
}
