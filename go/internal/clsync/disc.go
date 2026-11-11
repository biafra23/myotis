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
	var bootnodes []*enode.Node
	for _, s := range MainnetBootstrapENRs {
		if n, err := enode.Parse(enode.ValidSchemes, s); err == nil {
			bootnodes = append(bootnodes, n)
		}
	}
	disc, err := discover.ListenV5(conn, local, discover.Config{Bootnodes: bootnodes})
	if err != nil {
		conn.Close()
		db.Close()
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		seen := make(map[enode.ID]bool)
		// Steady 15 s lookup cadence (discovery.rs:26 LOOKUP_INTERVAL);
		// hunt-mode 2 s is a 3c refinement.
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		// First lookup as soon as the table has a chance to seed.
		time.Sleep(2 * time.Second)
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			for _, n := range disc.Lookup(randomID()) {
				if seen[n.ID()] {
					continue
				}
				seen[n.ID()] = true
				if !acceptedForDial(n, digestFunc()) {
					continue
				}
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
