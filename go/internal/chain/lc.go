// Consensus-layer pins, one definition per network, twin of the Rust
// engine's ChainConfig::mainnet (rust/myotis-net/src/sync.rs). Like the EL
// pins these move only with the release checklist. NOTE: ./gradlew
// refreshCheckpoint rewrites the JAVA and RUST marker regions only — it
// does not write this file. The checkpoint pin here is kept honest by
// TestCheckpointMatchesRustEngine (lc_drift_test.go), which compares it
// against sync.rs's @checkpoint:mainnet region, so a release refresh
// turns the Go build red until this pin moves with the others.
package chain

import "github.com/ethereum/go-ethereum/common"

// Beacon timing + the weak-subjectivity bound. Mainnet preset; gnosis would
// differ in all three and its bound is 3 (periods of 11.4 h).
const (
	SecondsPerSlot               = 12
	SlotsPerEpoch                = 32
	EpochsPerSyncCommitteePeriod = 256
	// SlotsPerSyncCommitteePeriod = 8192 slots = one period of
	// 256 epochs = 27.3 h on mainnet.
	SlotsPerSyncCommitteePeriod = SlotsPerEpoch * EpochsPerSyncCommitteePeriod
	// WsBoundPeriods is mainnet's weak-subjectivity bound: 13 periods
	// (~14.7 days). The spec's plateau (3532 epochs / 256 = 13.8) floors
	// to 13; the bound is applied at PERIOD granularity — an anchor is
	// stale only once the wall clock ENTERS period anchor+14, never
	// mid-period (ws_anchor_stale is "wall - anchor > bound", strictly
	// greater).
	WsBoundPeriods = 13
)

// ForkAt pins one beacon fork: the version active from Epoch on. The
// signing domain for a sync aggregate depends on the signature slot's fork
// (docs/spec/01: one constant is NOT enough, #295), so the whole schedule
// is a pin, not just the head.
type ForkAt struct {
	Epoch   uint64
	Version [4]byte
}

// Consensus returns mainnet's pinned beacon-chain configuration: the trust
// anchors for the light client (genesis validators root + checkpoint) and
// the fork schedule that selects signing domains. Mirrors sync.rs
// (refresh anchors in BOTH engines together).
func ConsensusMainnet() *Consensus {
	return &Consensus{
		GenesisTime:           1606824023,
		GenesisValidatorsRoot: common.HexToHash("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
		// @checkpoint:mainnet — slot 15599168 (period 1904), taken
		// 2026-11-07, the same anchor both other engines ship.
		CheckpointRoot: common.HexToHash("0x935911763d6fcca100fd42f951f1407a9967414bf38ee85992c00e5e003ca373"),
		CheckpointSlot: 15599168,
		// Epoch → version (EIP-7801 names aside, these are the fork
		// versions mainnet actually activates; Fulu epoch 411392 is the
		// head). Mainnet has NO scheduled Gloas epoch — the shape switch
		// stays pre-Gloas until one is pinned (Sepolia's is epoch 353024,
		// version 90000076, in the Rust config as the example).
		Forks: []ForkAt{
			{Epoch: 0, Version: [4]byte{0x00, 0x00, 0x00, 0x00}},
			{Epoch: 74240, Version: [4]byte{0x01, 0x00, 0x00, 0x00}},
			{Epoch: 144896, Version: [4]byte{0x02, 0x00, 0x00, 0x00}},
			{Epoch: 194048, Version: [4]byte{0x03, 0x00, 0x00, 0x00}}, // Capella
			{Epoch: 269568, Version: [4]byte{0x04, 0x00, 0x00, 0x00}}, // Deneb
			{Epoch: 364032, Version: [4]byte{0x05, 0x00, 0x00, 0x00}}, // Electra
			{Epoch: 411392, Version: [4]byte{0x06, 0x00, 0x00, 0x00}}, // Fulu
		},
	}
}

type Consensus struct {
	GenesisTime           uint64
	GenesisValidatorsRoot common.Hash
	CheckpointRoot        common.Hash
	CheckpointSlot        uint64
	Forks                 []ForkAt
}

// SlotAt returns the current slot from the wall clock (unix seconds).
func (c *Consensus) SlotAt(unixSec int64) uint64 {
	if unixSec < int64(c.GenesisTime) {
		return 0
	}
	return uint64((unixSec - int64(c.GenesisTime)) / SecondsPerSlot)
}

// SyncCommitteePeriod maps a slot to its sync-committee period.
func SyncCommitteePeriod(slot uint64) uint64 {
	return slot / SlotsPerSyncCommitteePeriod
}

// WsAnchorStale is the weak-subjectivity predicate, period-granular and
// strictly-greater, exactly as both shipped engines apply it: an anchor
// whose age EQUALS the bound is still fresh, and a wall clock behind the
// anchor (skew, or a restored snapshot) is fresh — it saturates.
func WsAnchorStale(anchorPeriod, wallPeriod, boundPeriods uint64) bool {
	if wallPeriod <= anchorPeriod {
		return false
	}
	return wallPeriod-anchorPeriod > boundPeriods
}
