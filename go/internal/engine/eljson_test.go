package engine

// These tests pin the result shapes the JVM (myotis-engine-rust
// RustVerifiedReadJsonTest) and iOS (EngineDecodingTest) sides consume.
// The KEYS and value encodings are the cross-language contract (the key
// lists below are rust/myotis-engine/src/eljson.rs's account_json /
// storage_json — cite stays with each list); the emission ORDER is
// this engine's own business (serde_json sorts its Map on the wire, so
// order was never the contract, and these structs emit declaration
// order). The golden byte strings are regression pins for what the Go
// engine emits, not claims about Rust's byte order.

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/snapwire"
	"github.com/ethereum/go-ethereum/common"
)

// A fixed wall clock (2027-01-15) so every derived slot/period in the
// goldens is constant forever: mainnet's beacon constants are pinned.
const testNow = 1_800_000_100

func testAnchor() Anchor {
	wall := chain.ConsensusMainnet().SlotAt(testNow)
	return Anchor{
		BeaconSlot:       wall - 10, // inside the 5-epoch slack → beaconSynced true
		StateRoot:        fill(0x11),
		ExecNumber:       23_456_789,
		ExecTimestamp:    testNow - 24,
		ExecBlockHash:    fill(0xab),
		OptimisticSlot:   wall + 2,
		OptimisticExecNo: 23_456_801,
	}
}

func fill(b byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = b
	}
	return a
}

func foundRead(t *testing.T) *AccountRead {
	t.Helper()
	bal := new(big.Int)
	if _, ok := bal.SetString("12345678901234567890123", 10); !ok {
		t.Fatal("bad test balance")
	}
	return &AccountRead{
		Address: common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
		// The caller's checksummed form: the shapes echo it EXACTLY as
		// supplied (eljson.rs address_echo, host.rs:1682) — a test
		// that passed lowercase would pin the wrong half of the
		// contract (PR #819 review).
		AddressHex: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Anchor:     testAnchor(),
		Peers:      3,
		Outcome: snapwire.AccountOutcome{
			State: snapwire.AccountFound,
			Account: &mpt.AccountLeaf{
				Nonce:       42,
				Balance:     bal.Bytes(), // minimal BE, like the proof decoder yields
				StorageRoot: fill(0x22),
				CodeHash:    fill(0x33),
			},
		},
	}
}

func TestAccountJSONGoldenFound(t *testing.T) {
	got, err := foundRead(t).AccountJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"address":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","exists":true,"nonce":42,"balanceWei":"12345678901234567890123","storageRootHex":"0x2222222222222222222222222222222222222222222222222222222222222222","codeHashHex":"0x3333333333333333333333333333333333333333333333333333333333333333","blockNumber":23456789,"blockTimestamp":1800000076,"blockHash":"0xabababababababababababababababababababababababababababababababab","peerStateRootHex":"0x1111111111111111111111111111111111111111111111111111111111111111","peerProofValid":true,"beaconChainVerified":true,"blsVerified":true,"matchedBeaconSlot":16097996,"verifyMethod":"stateRootMatch","failReason":null,"accountHashHex":"0x06e120c2c3547c60ee47f712d32e5acf38b35d1cc62e23b055a69bb88284c281","proofNodesHex":[],"beaconSynced":true,"finalizedPeriod":1965,"wallClockPeriod":1965,"finalizedBlockNumber":23456789,"optimisticBlockNumber":23456801,"anchor":"finalized"}`
	if got != want {
		t.Errorf("account JSON drifted:\n got %s\nwant %s", got, want)
	}
}

func TestAccountJSONGoldenAbsent(t *testing.T) {
	r := foundRead(t)
	r.Outcome = snapwire.AccountOutcome{State: snapwire.AccountProvenAbsent}
	got, err := r.AccountJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	// The convention for a proven-absent account: exists false, nonce
	// -1, balance null (Java's VerifiedAccountQuery), and the roots the
	// Rust twin reports — EMPTY_TRIE_ROOT / EMPTY_CODE_HASH
	// (reader.rs:6643-6644). Not zeros: 0x00…00 is not the root of any
	// trie (PR #819 review).
	const want = `{"address":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","exists":false,"nonce":-1,"balanceWei":null,"storageRootHex":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHashHex":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","blockNumber":23456789,"blockTimestamp":1800000076,"blockHash":"0xabababababababababababababababababababababababababababababababab","peerStateRootHex":"0x1111111111111111111111111111111111111111111111111111111111111111","peerProofValid":true,"beaconChainVerified":true,"blsVerified":true,"matchedBeaconSlot":16097996,"verifyMethod":"stateRootMatch","failReason":null,"accountHashHex":"0x06e120c2c3547c60ee47f712d32e5acf38b35d1cc62e23b055a69bb88284c281","proofNodesHex":[],"beaconSynced":true,"finalizedPeriod":1965,"wallClockPeriod":1965,"finalizedBlockNumber":23456789,"optimisticBlockNumber":23456801,"anchor":"finalized"}`
	if got != want {
		t.Errorf("absent-account JSON drifted:\n got %s\nwant %s", got, want)
	}
}

func TestAccountJSONUnverifiedOutcomeRefused(t *testing.T) {
	r := foundRead(t)
	r.Outcome = snapwire.AccountOutcome{} // AccountInvalid: nothing proven
	if _, err := r.AccountJSON(testNow); err == nil {
		t.Fatal("an unverified outcome must never emit exists=false as if proven")
	}
}

func TestStorageJSONGolden(t *testing.T) {
	r := foundRead(t)
	var key [32]byte
	key[31] = 7
	r.Slot = &SlotRead{Key: key, Value: []byte{0x2a}, StorageRoot: fill(0x22)}
	got, err := r.StorageJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"addressHex":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","slot":7,"holderHex":null,"storageKeyHex":"0x0000000000000000000000000000000000000000000000000000000000000007","storageKeyHashHex":"0xa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c688","exists":true,"valueHex":"0x2a","valueDecimal":"42","slotsReturned":1,"storageRootHex":"0x2222222222222222222222222222222222222222222222222222222222222222","proofNodesHex":[],"storageProofValid":true,"beaconSynced":true,"beaconChainVerified":true,"blsVerified":true,"matchedBeaconSlot":16097996,"verifyMethod":"stateRootMatch","failReason":null,"peerBlockNumber":23456789,"finalizedBlockNumber":23456789,"optimisticBlockNumber":23456801,"finalizedSlot":16097996,"optimisticSlot":16098008,"maxHeaderChainGap":8192,"anchor":"finalized"}`
	if got != want {
		t.Errorf("storage JSON drifted:\n got %s\nwant %s", got, want)
	}
}

func TestStorageJSONGoldenProvenZero(t *testing.T) {
	r := foundRead(t)
	r.Outcome = snapwire.AccountOutcome{State: snapwire.AccountProvenAbsent}
	var key [32]byte
	key[31] = 7
	r.Slot = &SlotRead{Key: key} // no walk needed: provably zero
	got, err := r.StorageJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["exists"] != false || m["valueHex"] != nil || m["valueDecimal"] != nil || m["slotsReturned"].(float64) != 0 {
		t.Errorf("proven-zero slot must be exists=false with null values, got %s", got)
	}
	if m["verifyMethod"] != "stateRootMatch" {
		t.Errorf("a proven-zero slot is still a verified answer, got %v", m["verifyMethod"])
	}
}

// TestAccountJSONKeySet pins the KEY SET against rust/myotis-engine/src/
// eljson.rs account_json (address, exists, nonce, balanceWei,
// storageRootHex, codeHashHex, blockNumber, blockTimestamp, blockHash,
// peerStateRootHex, peerProofValid, beaconChainVerified, blsVerified,
// matchedBeaconSlot, verifyMethod, failReason, accountHashHex,
// proofNodesHex, beaconSynced, finalizedPeriod, wallClockPeriod,
// finalizedBlockNumber, optimisticBlockNumber) plus anchor
// (eljson.rs anchor_name). A host decoding by key must find every one.
func TestAccountJSONKeySet(t *testing.T) {
	got, err := foundRead(t).AccountJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"address", "exists", "nonce", "balanceWei", "storageRootHex", "codeHashHex",
		"blockNumber", "blockTimestamp", "blockHash", "peerStateRootHex", "peerProofValid",
		"beaconChainVerified", "blsVerified", "matchedBeaconSlot", "verifyMethod",
		"failReason", "accountHashHex", "proofNodesHex", "beaconSynced", "finalizedPeriod",
		"wallClockPeriod", "finalizedBlockNumber", "optimisticBlockNumber", "anchor",
	}
	if len(m) != len(want) {
		t.Fatalf("account JSON has %d keys, eljson.rs account_json has %d", len(m), len(want))
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("account JSON misses key %q (eljson.rs account_json carries it)", k)
		}
	}
}

// TestStorageJSONKeySet is the storage_json counterpart
// (eljson.rs storage_json: addressHex, slot, holderHex, storageKeyHex,
// storageKeyHashHex, exists, valueHex, valueDecimal, slotsReturned,
// storageRootHex, proofNodesHex, storageProofValid, beaconSynced,
// beaconChainVerified, blsVerified, matchedBeaconSlot, verifyMethod,
// failReason, peerBlockNumber, finalizedBlockNumber,
// optimisticBlockNumber, finalizedSlot, optimisticSlot,
// maxHeaderChainGap) plus anchor.
func TestStorageJSONUnverifiedOutcomeRefused(t *testing.T) {
	r := foundRead(t)
	r.Outcome = snapwire.AccountOutcome{} // AccountInvalid
	r.Slot = &SlotRead{Key: [32]byte{31: 1}}
	if _, err := r.StorageJSON(testNow); err == nil {
		t.Fatal("an unverified outcome must not render verifyMethod=stateRootMatch (PR #819 review)")
	}
}

func TestStorageJSONEmptyValueIsNotExists(t *testing.T) {
	// reader.rs:7044 found rule is !value.is_empty(): an RLP-empty-
	// string leaf (zero-length, non-nil — what DecodeStorageLeaf
	// yields) reads as unset, and nil-vs-empty must not leak into the
	// cross-engine shape.
	r := foundRead(t)
	r.Slot = &SlotRead{Key: [32]byte{31: 2}, Value: []byte{}, StorageRoot: fill(0x22)}
	got, err := r.StorageJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if string(m["exists"]) != "false" || string(m["slotsReturned"]) != "0" {
		t.Errorf("empty value must read as unset (reader.rs:7044), got %s", got)
	}
}

func TestStorageJSONKeySet(t *testing.T) {
	r := foundRead(t)
	r.Slot = &SlotRead{Key: [32]byte{}, Value: []byte{1}, StorageRoot: fill(0x22)}
	got, err := r.StorageJSON(testNow)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"addressHex", "slot", "holderHex", "storageKeyHex", "storageKeyHashHex", "exists",
		"valueHex", "valueDecimal", "slotsReturned", "storageRootHex", "proofNodesHex",
		"storageProofValid", "beaconSynced", "beaconChainVerified", "blsVerified",
		"matchedBeaconSlot", "verifyMethod", "failReason", "peerBlockNumber",
		"finalizedBlockNumber", "optimisticBlockNumber", "finalizedSlot", "optimisticSlot",
		"maxHeaderChainGap", "anchor",
	}
	if len(m) != len(want) {
		t.Fatalf("storage JSON has %d keys, eljson.rs storage_json has %d", len(m), len(want))
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("storage JSON misses key %q (eljson.rs storage_json carries it)", k)
		}
	}
}

// TestBeaconSyncedRustParity pins the gate to sync.rs:4293 —
// finalized + slack ≥ wall, NO lower bound. The lower bound a
// previous cut added would report beaconSynced=false where Rust and
// Java report true for the identical anchor (host clock a hair behind
// its own LC), and a cross-engine shape may not diverge on a key.
func TestBeaconSyncedRustParity(t *testing.T) {
	wall := chain.ConsensusMainnet().SlotAt(testNow)
	for _, tc := range []struct {
		name string
		slot uint64
		want bool
	}{
		{"fresh", wall - 4, true},
		{"exactly at the slack", wall - SyncedSlackSlots, true},
		{"one slot past the slack", wall - SyncedSlackSlots - 1, false},
		{"anchor ahead of the wall clock", wall + 5, true},
	} {
		if got := beaconSynced(tc.slot, testNow); got != tc.want {
			t.Errorf("%s: beaconSynced(%d @ wall %d) = %v, want %v", tc.name, tc.slot, wall, got, tc.want)
		}
	}
}

func TestBeToDecimal(t *testing.T) {
	for in, want := range map[string]string{
		"":         "0", // empty = zero, like eljson.rs be_to_decimal
		"00":       "0", // leading zeros stripped
		"02":       "2",
		"0100":     "256",
		"ffffffff": "4294967295",
	} {
		var b []byte
		for i := 0; i < len(in); i += 2 {
			var v int
			for j := i; j < i+2 && j < len(in); j++ {
				c := in[j]
				v *= 16
				switch {
				case c >= '0' && c <= '9':
					v += int(c - '0')
				default:
					v += int(c-'a') + 10
				}
			}
			b = append(b, byte(v))
		}
		if got := beToDecimal(b); got != want {
			t.Errorf("beToDecimal(%q) = %s, want %s", in, got, want)
		}
	}
}
