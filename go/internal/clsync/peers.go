// Package clsync is the Go engine's beacon-chain client: a libp2p host
// that speaks the eth2 light-client req/resp protocols (clwire) over
// TCP+Noise+yamux, finds CL peers by discv5 filtered on the eth2
// fork-digest ENR field, and runs the light client of docs/spec/01:
// checkpoint-pinned bootstrap → BLS-verified catch-up (lc.Store) →
// finality poll. Trust stays where the spec puts it: the embedded
// checkpoint and genesis validators root, nothing else.
package clsync

import (
	"fmt"
	"io"
	"net"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Static CL peers for mainnet — the multiaddr literals from
// rust/myotis-net/src/sync.rs MAINNET_STATIC_PEERS (roost + four
// Lighthouse pins). These seed the loop before discovery fills in, and
// are never evicted.
var MainnetStaticPeers = []string{
	"/ip4/188.68.32.16/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
	"/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ",
	"/ip4/57.129.130.18/tcp/9000/p2p/16Uiu2HAkwmBd7zSRAiBkGar6ghHYfKCKTpGbGL1igrD6mC4W99T9",
	"/ip4/84.112.35.112/tcp/9000/p2p/16Uiu2HAm6YkLaGLMH1Q9caGi4A2WctHPhENumfQMJXVCMVpc7GQY",
	"/ip4/91.189.182.90/tcp/9000/p2p/16Uiu2HAmJJUAs17wxW1i4HM5Fce1zYPCvvavxsYorWr4EQVx1Ui8",
}

// MainnetBootstrapENRs are the discv5 seeds (MAINNET_BOOTSTRAP_ENRS,
// rust sync.rs:1237): Teku, Prysm, Sigma Prime, EF, Nimbus and Lodestar
// bootstrap nodes plus roost's published record.
var MainnetBootstrapENRs = []string{
	// Teku
	"enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
	"enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
	// Prysm
	"enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
	"enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
	"enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
	// Sigma Prime (Lighthouse)
	"enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
	"enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
	"enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
	"enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",
	// Ethereum Foundation
	"enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
	"enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
	"enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
	"enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
	// Nimbus
	"enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
	"enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
	// Lodestar
	"enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
	"enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA",
	// roost mainnet (this project's dedicated LC server), snapshot 2026-09-06
	"enr:-KG4QKUnChEU8InNkAxOj6e_KZzebsvUQYJ850DJaEQAygKJb_8Y2Mv5IxDEOacUs0pkVctDN1f8CjrCfG7Vf2leulkIhGV0aDKQjJ9i_gYAAAD__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaEC41NP_bzrL7-rq6KmsQIeTl2Nw9yvIlgEvz-Pjz2dwTmDdGNwgiOVg3VkcIIjlQ",
}

// enrEth2Digest extracts the eth2 ENR field's fork digest (first 4
// bytes of the ENRForkID: digest(4) || next_fork_version(4) ||
// next_fork_epoch(8)) through geth's entry mechanism — eth2 is not a
// key geth's schema knows, but Load matches any ENRKey, so a local
// entry type reaches it (the same bytes the Rust filter_candidate reads
// via get_raw_rlp(b"eth2")).
type eth2Entry struct{ Value []byte }

func (e *eth2Entry) ENRKey() string { return "eth2" }

func (e *eth2Entry) EncodeRLP(w io.Writer) error { return rlp.Encode(w, e.Value) }

func (e *eth2Entry) DecodeRLP(s *rlp.Stream) error {
	b, err := s.Bytes()
	if err != nil {
		return err
	}
	e.Value = b
	return nil
}

func enrEth2Digest(r *enr.Record) ([4]byte, bool) {
	var zero [4]byte
	var e eth2Entry
	if err := r.Load(&e); err != nil || len(e.Value) < 4 {
		return zero, false
	}
	return [4]byte{e.Value[0], e.Value[1], e.Value[2], e.Value[3]}, true
}

// enrPeerInfo converts a discv5 node into a dialable libp2p peer: the
// secp256k1 pubkey becomes the PeerId, the ENR's IP+TCP become the
// address (the ENR→multiaddr step of the Rust filter_candidate).
func enrPeerInfo(n *enode.Node) (peer.AddrInfo, bool) {
	var zero peer.AddrInfo
	pub, err := crypto.UnmarshalSecp256k1PublicKey(gethcrypto.FromECDSAPub(n.Pubkey()))
	if err != nil {
		return zero, false
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return zero, false
	}
	r := n.Record()
	var ip enr.IPv4
	var tcp enr.TCP
	if err := r.Load(&ip); err != nil {
		return zero, false
	}
	if err := r.Load(&tcp); err != nil {
		return zero, false
	}
	addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", net.IP(ip).String(), uint16(tcp), id))
	if err != nil {
		return zero, false
	}
	return peer.AddrInfo{ID: id, Addrs: []ma.Multiaddr{addr}}, true
}

// acceptedForDial is the filter_candidate contract: the peer must carry
// eth2, match the CURRENT fork digest, and offer an IPv4+TCP endpoint.
func acceptedForDial(n *enode.Node, want [4]byte) bool {
	got, ok := enrEth2Digest(n.Record())
	if !ok || got != want {
		return false
	}
	_, ok = enrPeerInfo(n)
	return ok
}

// parseMultiaddr / peerAddrInfo are the single multiaddr→peer parse
// path: NewSyncer seeds the static peers through them and the
// "every static peer parses" test covers that same code, so no
// hand-rolled parsing (or second seam) exists beside it.
func parseMultiaddr(s string) (ma.Multiaddr, error) { return ma.NewMultiaddr(s) }

func peerAddrInfo(a ma.Multiaddr) (peer.AddrInfo, error) {
	pi, err := peer.AddrInfoFromP2pAddr(a)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	return *pi, nil
}
