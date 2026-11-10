// Package chain pins the per-network constants the Go engine needs, one
// definition per network. Mainnet only for now.
//
// The constants mirror the Rust engine's ElConfig::mainnet
// (rust/myotis-net/src/el/reader.rs) and geth's params/bootnodes.go; the pin
// test keeps the three in lockstep the way the repo's twin tests do elsewhere.
package chain

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// Network is one chain's pinned configuration.
type Network struct {
	Name      string
	NetworkID uint64
	// GenesisHash is the anchor the eth Status handshake compares against.
	GenesisHash common.Hash
	// ForkIDHash/ForkNext is the EIP-2124 fork id the Status must present so
	// peers don't disconnect us. Pinned, like both other engines; a real
	// CRC32 fork schedule can replace it later (docs/spec/02 §8).
	ForkIDHash [4]byte
	ForkNext   uint64
	// Bootnodes seeds discv4: NodeOps ENRs (discovery-only, no TCP port)
	// followed by the legacy EF enodes, in geth's order.
	Bootnodes []string
	// ENRTreeURL is the EIP-1459 list the EF publishes for the EL.
	ENRTreeURL string
	// ListenPort is the conventional per-network UDP/TCP port.
	ListenPort int
}

// Mainnet returns the pinned mainnet configuration.
func Mainnet() *Network {
	return &Network{
		Name:        "mainnet",
		NetworkID:   1,
		GenesisHash: common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
		// Pinned 2026-11 from the Rust engine's ElConfig::mainnet; valid for
		// every fork from [07c9462e]'s first block until the next fork block.
		ForkIDHash: [4]byte{0x07, 0xc9, 0x46, 0x2e},
		ForkNext:   0,
		// go-ethereum params/bootnodes.go MainnetBootnodes as of 2026-11-10
		// (master), i.e. after ethereum/go-ethereum#35682 replaced the EF fleet
		// with the NodeOps ones. Mirror any change into Rust ElConfig::mainnet
		// and Java NetworkConfig.MAINNET, and update the pin test.
		Bootnodes: []string{
			// EF NodeOps bootnodes (ENRs: ip + udp only, discovery seeds).
			"enr:-KG4QCF1Mj32xpKHjinNb6ocCtMZG6IR_tyF5dkio5Hkek7zVbT6MM5eJwhjJFdiksQl51T33IRgryE0XLXiy1QOqsUBgmlkgnY0gmlwhNRj2kKDaXA2kCoAHKALAA0CAAAAAAAAAF6Jc2VjcDI1NmsxoQLKlnQYuhZRBTA8-7cz37kr_KuA1lAJ1eXxWMjp5fLJB4N1ZHCCTreEdWRwNoJOtw", // nodeops-bootnode-dcl1-01
			"enr:-KG4QMHihBfLI_tpXLWmfTi28HItJa4wDADDAaVjkfSELAb0BajqVWXM2GEMds5J63SCkpDRlqct5E8ftfQi4U93pigBgmlkgnY0gmlwhIHUpj2DaXA2kCYEqIAABAHQAAAAA2GdUACJc2VjcDI1NmsxoQLeQmW8OMuoUIoUImNW-r9IC4jaiAwZ2knfV4BqWyQvKoN1ZHCCdl-EdWRwNoJ2Xw", // nodeops-bootnode-sfo3-01
			"enr:-KG4QKsHcKQvIX8UPbJgw2cIEP_9EislF1srNGdYom4dcSsobt-92iEDNkHTt9dcdKXHaDMVbCM8QQ4V1RP8HcExLDsBgmlkgnY0gmlwhJB-_BiDaXA2kCQAYYABAADQAAAAAYEgYAGJc2VjcDI1NmsxoQILdc6UClD5s_N8-hYhIGQtFqRYR3Qxf9qgLQ7sj4qvEYN1ZHCCdl-EdWRwNoJ2Xw", // nodeops-bootnode-blr1-01
			"enr:-KG4QFplptv1jVEhFeNNxRN7qe5p9rAGGlMeNnmGvUJV23W4Kr8hmiSzdWjZZHFqwi7nOuQrM32VO6uHBORXOdLG98gBgmlkgnY0gmlwhLKc14yDaXA2kCoBBP8A9DxKAAAAAAAAAAGJc2VjcDI1NmsxoQMBRycp4yiHbGzOqZPPMmuKGslp1NpOrFf_predLYM4-oN1ZHCCdl-EdWRwNoJ2Xw", // nodeops-bootnode-ash-01
			"enr:-KG4QGY74qTrst5NbQDAMIF8B7jEC8CMBSo6C5Ljea5I4PxYV1VSYdsGUqqIBlOYRBfwhl6YpEyvvvZOqNCa4dvmSXgBgmlkgnY0gmlwhAXfXlGDaXA2kCoBBP8C8BytAAAAAAAAAAGJc2VjcDI1NmsxoQIMlJp7yNcblauYicEeSBpHQzFAk9Wg3lhx3ie9gpTohIN1ZHCCdl-EdWRwNoJ2Xw", // nodeops-bootnode-sin-01
			// Legacy EF bootnodes, being phased out in favour of the ones above.
			"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303", // bootnode-aws-ap-southeast-1-001
			"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",   // bootnode-aws-us-east-1-001
			"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303", // bootnode-hetzner-hel
			"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303", // bootnode-hetzner-fsn
		},
		// The EF's canonical EIP-1459 list (geth params.KnownDNSNetwork).
		ENRTreeURL: "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net",
		ListenPort: 30303,
	}
}

// ParseBootnode turns one Bootnodes entry ("enr:…" or "enode://…") into a node.
func ParseBootnode(raw string) (*enode.Node, error) {
	if rest, ok := strings.CutPrefix(raw, "enr:"); ok {
		rawRec, err := base64.RawURLEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("decode ENR %q: %w", raw, err)
		}
		var rec enr.Record
		if err := rlp.DecodeBytes(rawRec, &rec); err != nil {
			return nil, fmt.Errorf("decode ENR %q: %w", raw, err)
		}
		n, err := enode.New(enode.V4ID{}, &rec)
		if err != nil {
			return nil, fmt.Errorf("build node from ENR %q: %w", raw, err)
		}
		return n, nil
	}
	n, err := enode.ParseV4(raw)
	if err != nil {
		return nil, fmt.Errorf("parse bootnode %q: %w", raw, err)
	}
	return n, nil
}

// SeedEndpoint formats a seed node the way the engines' pin tests compare
// them: "ip:port" where the port is the TCP one when the record names it, and
// the UDP one otherwise (discv4 pings the UDP port; the NodeOps records carry
// no TCP port at all).
func SeedEndpoint(n *enode.Node) string {
	port := n.TCP()
	if port == 0 {
		port = n.UDP()
	}
	return net.JoinHostPort(n.IP().String(), fmt.Sprint(port))
}
