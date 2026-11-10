package chain

import "testing"

// TestMainnetPins pins the mainnet constants as strings, the way the Rust
// engine's mainnet_config_pins_known_values and the Java
// NetworkConfigGnosisTest#elBootnodesMatchGoEthereum do: a partial re-sync of
// the bootnode list fails right here rather than silently in the field. The
// endpoints are the same nine the Rust ElConfig::mainnet pins (five EF NodeOps
// ip:udp, then the four legacy EF enodes).
func TestMainnetPins(t *testing.T) {
	m := Mainnet()

	if m.NetworkID != 1 {
		t.Errorf("NetworkID = %d, want 1", m.NetworkID)
	}
	if got := m.GenesisHash.Hex(); got != "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" {
		t.Errorf("GenesisHash = %s", got)
	}
	if m.ForkIDHash != [4]byte{0x07, 0xc9, 0x46, 0x2e} || m.ForkNext != 0 {
		t.Errorf("fork id = %x/%d, want 07c9462e/0", m.ForkIDHash, m.ForkNext)
	}
	const wantTree = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
	if m.ENRTreeURL != wantTree {
		t.Errorf("ENRTreeURL = %s, want %s", m.ENRTreeURL, wantTree)
	}

	want := []string{
		"212.99.218.66:20151",   // nodeops-bootnode-dcl1-01
		"129.212.166.61:30303",  // nodeops-bootnode-sfo3-01
		"144.126.252.24:30303",  // nodeops-bootnode-blr1-01
		"178.156.215.140:30303", // nodeops-bootnode-ash-01
		"5.223.94.81:30303",     // nodeops-bootnode-sin-01
		"18.138.108.67:30303",
		"3.209.45.79:30303",
		"65.108.70.101:30303",
		"157.90.35.166:30303",
	}
	if len(m.Bootnodes) != len(want) {
		t.Fatalf("got %d bootnodes, want %d", len(m.Bootnodes), len(want))
	}
	for i, raw := range m.Bootnodes {
		n, err := ParseBootnode(raw)
		if err != nil {
			t.Fatalf("bootnode %d (%s): %v", i, raw, err)
		}
		if got := SeedEndpoint(n); got != want[i] {
			t.Errorf("bootnode %d endpoint = %s, want %s", i, got, want[i])
		}
	}
}

// TestParseBootnodeIdentities checks the two wire forms land on distinct,
// pubkey-derived node IDs (the ENRs carry no id themselves; the id is the
// keccak of the record's secp256k1 key).
func TestParseBootnodeIdentities(t *testing.T) {
	m := Mainnet()
	seen := map[string]bool{}
	for _, raw := range m.Bootnodes {
		n, err := ParseBootnode(raw)
		if err != nil {
			t.Fatal(err)
		}
		id := n.ID().String()
		if id == "" || seen[id] {
			t.Errorf("duplicate or empty node id for %s: %q", SeedEndpoint(n), id)
		}
		seen[id] = true
	}
}
