package clsync

import (
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
