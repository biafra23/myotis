package clsync

import (
	crand "crypto/rand"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p/core/peer"
)

// StartDiscV5 runs discv5 on udpPort seeded with MainnetBootstrapENRs
// and pushes every eth2-filtered peer onto the returned channel
// (geth's discover/v5; the sigp discv5 the Rust twin uses is the same
// protocol). The digest to filter on is re-read per candidate through
// digestFunc so the accepted set follows the fork schedule without a
// restart — Dynamic accepted digests, discovery.rs:47-68.
//
// A discv5 bind failure is NOT fatal to the loop: the static pins still
// drive bootstrap and finality (the Rust sync treats discovery spawn
// failure the same way). Callers should run this best-effort.
func StartDiscV5(udpPort int, digestFunc func() [4]byte, out chan<- peer.AddrInfo) (func(), error) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: udpPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	key, err := crypto.GenerateKey() // ephemeral: our CL identity is throwaway (Rust does the same)
	if err != nil {
		conn.Close()
		return nil, err
	}
	db, err := enode.OpenDB("") // in-memory only
	if err != nil {
		conn.Close()
		return nil, err
	}
	local := enode.NewLocalNode(db, key)
	// Declare the endpoint through the fallback setters, not Set: geth's
	// doc on LocalNode.Set says IP/UDP go through Set*IP / SetFallbackUDP
	// "otherwise they'll be overwritten by the endpoint predictor" — a
	// plain Set(enr.IPv4(...)) is re-derived away by the first endpoint
	// statement (PR #770 review). Same posture as part 1's discv4 node
	// (internal/discovery), and honest about what it is: a loopback
	// placeholder for an outbound-only client with no public address.
	local.SetFallbackIP(net.IPv4(127, 0, 0, 1))
	local.SetFallbackUDP(udpPort)
	var bootnodes []*enode.Node
	for _, s := range MainnetBootstrapENRs {
		if n, err := enode.Parse(enode.ValidSchemes, s); err == nil {
			bootnodes = append(bootnodes, n)
		}
	}
	// Config.PrivateKey is the codec's handshake-signing key — without
	// it geth nil-derefs in makeIDSignature the first time a peer
	// WHOAREYOUs us (live-verified panic). This is the single root cause
	// of the crashes originally logged as two "landmines": geth signs
	// the ID signature with THIS key, and both panics sat behind it
	// (the endpoint setters above are hygiene, not the fix — PR #770
	// review pointed this out, and part 1's discv4 setup passing the
	// key with only SetFallbackUDP was the working precedent).
	disc, err := discover.ListenV5(conn, local, discover.Config{
		PrivateKey: key,
		Bootnodes:  bootnodes,
	})
	if err != nil {
		conn.Close()
		db.Close()
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		// Keyed by the digest the record was last evaluated against, not
		// a plain bool (the Rust twin rotates its seen set on digest
		// change, discovery.rs:82-95): an ENR pruning at yesterday's
		// fork digest must become a candidate again once ours moves — a
		// blanket seen=true would drop it forever. Marking only on
		// acceptance has the same effect for refusals, which is fine:
		// they get re-checked every tick until they pass.
		seen := make(map[enode.ID][4]byte)
		// Steady 15 s lookup cadence (discovery.rs:26 LOOKUP_INTERVAL);
		// hunt-mode 2 s is a 3c refinement.
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		// First lookup after a short seed window — NOT after the first
		// tick (a select-first loop would wait the full 15 s before any
		// lookup existed; PR #770 review). RunBootstrap snapshots the
		// pool early, so a first lookup at 2 s can still feed it.
		seeded := make(chan struct{})
		go func() {
			time.Sleep(2 * time.Second)
			close(seeded)
		}()
		first := true
		for {
			if first {
				select {
				case <-stop:
					return
				case <-seeded:
				}
				first = false
			} else {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
			}
			digest := digestFunc()
			for _, n := range disc.Lookup(randomID()) {
				if seen[n.ID()] == digest {
					continue
				}
				if !acceptedForDial(n, digest) {
					continue
				}
				seen[n.ID()] = digest
				if info, ok := enrPeerInfo(n); ok {
					select {
					case out <- info:
					case <-stop:
						return
					}
				}
			}
		}
	}()
	return func() { close(stop); disc.Close(); db.Close() }, nil
}

var randomID = func() enode.ID {
	var id enode.ID
	_, _ = crand.Read(id[:])
	return id
}
