package engine

// The pinned cross-language result shapes: the same JSON objects the Rust
// engine emits (rust/myotis-engine/src/eljson.rs account_json /
// storage_json) and the JVM (myotis-engine-rust RustVerifiedReadJsonTest)
// and iOS (EngineDecodingTest) sides decode BY KEY. Key order is not the
// contract (serde_json's Map sorts; these structs emit declaration order —
// consumers are key-based); the KEYS, value encodings and null-vs-number
// discipline ARE. Every field's provenance is stated below: state values
// come only from proof-verified leaves and attested headers, diagnostics
// are echoed or derived arithmetic, and nothing is fabricated.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/snapwire"
	"github.com/ethereum/go-ethereum/crypto"
)

// anchor is one snapshot of the light client's trust position, extended
// with the PROVEN exec coordinates the result shapes report: the
// finalized anchor's block number/timestamp/hash are fields of the
// attested execution payload header whose root the LC's execution branch
// verified (lc.lcHeader.Exec*), so they carry the same proof as the state
// root the read ran against — not peer claims.
type anchor struct {
	BeaconSlot       uint64
	StateRoot        [32]byte
	ExecNumber       uint64
	ExecTimestamp    uint64
	ExecBlockHash    [32]byte
	OptimisticSlot   uint64
	OptimisticExecNo uint64
}

// SlotRead is one proven storage-slot outcome. Value nil means PROVEN
// zero — either the account is absent or its storageRoot is the empty
// trie, so no leaf walk was needed (or possible); both are proofs, not
// gaps, and the JSON says exists=false with a null value.
type SlotRead struct {
	Key         [32]byte
	Value       []byte
	StorageRoot [32]byte // the PROVEN storageRoot the hop anchored at
}

// AccountRead is one verified account read: the proof-verified outcome at
// an LC-anchored state root, plus the optional storage hop anchored at
// the PROVEN storageRoot of the same read (one disclosure budget, never
// 3+3 peers — see snapread.SlotAt).
type AccountRead struct {
	// Address is the 20 bytes the proof ran against (the parse of the
	// caller's string) — the honest source for accountHashHex, so the
	// JSON never re-parses a string that already fed the proof.
	Address [20]byte
	Anchor  anchor
	Peers   int // snap peers contacted by the attempt that served it
	// Outcome is the proof-verified verdict: AccountFound carries the
	// decoded leaf, AccountProvenAbsent proves the key is not in the
	// trie. AccountInvalid never reaches here (the read fails instead).
	Outcome snapwire.AccountOutcome
	Slot    *SlotRead // nil unless requested
}

// accountVerifyMethod: the read's proof was verified against the
// beacon-finalized execution state root — eljson's "stateRootMatch"
// verdict family (verify.rs:68). This is the value hosts gate on: a
// non-null verifyMethod is the verified mark.
const accountVerifyMethod = "stateRootMatch"

// SyncedSlackSlots is the finality-freshness bar for the beaconSynced
// diagnostic: 5 epochs, the same SYNCED_SLOT_SLACK_EPOCHS the Rust and
// Java engines' status gates use (docs: withholding shows as not-synced,
// not as a read error).
const SyncedSlackSlots = 5 * chain.SlotsPerEpoch

// --- the account_json shape ---

type accountJSON struct {
	// Fields are declared in eljson.rs's key set; Go marshals struct
	// fields in declaration order, which is order-INDEPENDENT for the
	// key-based consumers this shape has (JVM record mapper, iOS dict).
	Address              string   `json:"address"`
	Exists               bool     `json:"exists"`
	Nonce                int64    `json:"nonce"`
	BalanceWei           *string  `json:"balanceWei"` // null when absent (Java convention)
	StorageRootHex       string   `json:"storageRootHex"`
	CodeHashHex          string   `json:"codeHashHex"`
	BlockNumber          uint64   `json:"blockNumber"`          // the anchor block (proven, see anchor)
	BlockTimestamp       uint64   `json:"blockTimestamp"`       // proven: from the attested payload header
	BlockHash            string   `json:"blockHash"`            // proven: likewise
	PeerStateRootHex     string   `json:"peerStateRootHex"`     // the root the proof verified against
	PeerProofValid       bool     `json:"peerProofValid"`       // true: a verdict exists only past proof verification
	BeaconChainVerified  bool     `json:"beaconChainVerified"`  // anchor: poll-verified finality, never the bootstrap checkpoint
	BlsVerified          bool     `json:"blsVerified"`          // ditto — the BLS path ran this cycle
	MatchedBeaconSlot    int64    `json:"matchedBeaconSlot"`    // the anchor slot the root is committed in
	VerifyMethod         *string  `json:"verifyMethod"`         // "stateRootMatch"
	FailReason           *string  `json:"failReason"`           // null on served reads; failures leave as Go errors
	AccountHashHex       string   `json:"accountHashHex"`       // keccak256(address), the snap trie key
	ProofNodesHex        []string `json:"proofNodesHex"`        // empty echo, as the Rust twin (diagnostic only)
	BeaconSynced         bool     `json:"beaconSynced"`         // derived: finalized within SyncedSlackSlots of wall
	FinalizedPeriod      uint64   `json:"finalizedPeriod"`      // slot arithmetic
	WallClockPeriod      uint64   `json:"wallClockPeriod"`      // slot arithmetic
	FinalizedBlockNumber uint64   `json:"finalizedBlockNumber"` // proven anchor exec number
	OptimisticBlockNum   uint64   `json:"optimisticBlockNumber"`
	Anchor               string   `json:"anchor"` // "finalized": the Go engine reads finalized anchors only
}

// AccountJSON renders the verified read in the pinned account_json shape
// (rust/myotis-engine/src/eljson.rs). nowUnix feeds only the diagnostic
// wall-clock arithmetic.
func (r *AccountRead) AccountJSON(nowUnix int64) (string, error) {
	b, err := r.buildAccount(nowUnix)
	if err != nil {
		return "", err
	}
	return marshal(b)
}

func (r *AccountRead) buildAccount(nowUnix int64) (accountJSON, error) {
	a := r.Anchor
	c := accountJSON{
		// Re-encoded from the proof's address bytes, lowercase — the
		// Rust twin hexes the bytes it read, it does not echo the
		// caller's string (eljson.rs hex0x_var).
		Address:              hex0x(r.Address[:]),
		PeerStateRootHex:     hexHash(a.StateRoot),
		PeerProofValid:       true,
		BeaconChainVerified:  true,
		BlsVerified:          true,
		MatchedBeaconSlot:    int64(a.BeaconSlot),
		VerifyMethod:         strPtr(accountVerifyMethod),
		ProofNodesHex:        []string{},
		BeaconSynced:         beaconSynced(a.BeaconSlot, nowUnix),
		FinalizedPeriod:      chain.SyncCommitteePeriod(a.BeaconSlot),
		WallClockPeriod:      chain.SyncCommitteePeriod(chain.ConsensusMainnet().SlotAt(nowUnix)),
		FinalizedBlockNumber: a.ExecNumber,
		OptimisticBlockNum:   a.OptimisticExecNo,
		BlockNumber:          a.ExecNumber,
		BlockTimestamp:       a.ExecTimestamp,
		BlockHash:            hexHash(a.ExecBlockHash),
		Anchor:               "finalized",
	}
	switch r.Outcome.State {
	case snapwire.AccountFound:
		l := r.Outcome.Account
		c.Exists = true
		c.Nonce = int64(l.Nonce)
		c.BalanceWei = strPtr(beToDecimal(l.Balance))
		c.StorageRootHex = hexHash(l.StorageRoot)
		c.CodeHashHex = hexHash(l.CodeHash)
	case snapwire.AccountProvenAbsent:
		// Proven absent: nonce -1 / balance null (Java convention), roots
		// the zero value the proof's empty slot committed to.
		c.Exists = false
		c.Nonce = -1
		c.StorageRootHex = hexHash([32]byte{})
		c.CodeHashHex = hexHash([32]byte{})
	default:
		// AccountInvalid must not reach the emitter (the read fails
		// before assembling an AccountRead); belt-and-braces so a future
		// caller cannot emit exists=false as if it were proven absence.
		return accountJSON{}, fmt.Errorf(
			"engine: refusing to emit account result for unverified outcome state %d", r.Outcome.State)
	}
	c.AccountHashHex = hexKeccak(r.Address[:])
	return c, nil
}

// --- the storage_json shape ---

type storageJSON struct {
	AddressHex           string   `json:"addressHex"`
	Slot                 uint64   `json:"slot"`
	HolderHex            *string  `json:"holderHex"` // no account-abstraction here: null
	StorageKeyHex        string   `json:"storageKeyHex"`
	StorageKeyHashHex    string   `json:"storageKeyHashHex"`
	Exists               bool     `json:"exists"`
	ValueHex             *string  `json:"valueHex"`     // null when the slot is proven zero
	ValueDecimal         *string  `json:"valueDecimal"` // null when proven zero
	SlotsReturned        int64    `json:"slotsReturned"`
	StorageRootHex       string   `json:"storageRootHex"` // the PROVEN storageRoot the hop anchored at
	ProofNodesHex        []string `json:"proofNodesHex"`  // empty echo, as the Rust twin
	StorageProofValid    bool     `json:"storageProofValid"`
	BeaconSynced         bool     `json:"beaconSynced"`
	BeaconChainVerified  bool     `json:"beaconChainVerified"`
	BlsVerified          bool     `json:"blsVerified"`
	MatchedBeaconSlot    int64    `json:"matchedBeaconSlot"`
	VerifyMethod         *string  `json:"verifyMethod"`
	FailReason           *string  `json:"failReason"`
	PeerBlockNumber      uint64   `json:"peerBlockNumber"`
	FinalizedBlockNumber uint64   `json:"finalizedBlockNumber"`
	OptimisticBlockNum   uint64   `json:"optimisticBlockNumber"`
	FinalizedSlot        uint64   `json:"finalizedSlot"`
	OptimisticSlot       uint64   `json:"optimisticSlot"`
	MaxHeaderChainGap    int64    `json:"maxHeaderChainGap"` // echoed constant, as the Rust twin (8192)
	Anchor               string   `json:"anchor"`
}

// StorageJSON renders the verified slot hop in the pinned storage_json
// shape. It addresses the SAME read as AccountJSON (same anchor, same
// proven storageRoot) — the shapes describe one logical read's two hops.
func (r *AccountRead) StorageJSON(nowUnix int64) (string, error) {
	if r.Slot == nil {
		return "", fmt.Errorf("engine: no slot read to render (address %s)", hex0x(r.Address[:]))
	}
	a := r.Anchor
	s := r.Slot
	out := storageJSON{
		AddressHex:           hex0x(r.Address[:]),
		HolderHex:            nil,
		StorageKeyHex:        hexHash(s.Key),
		StorageKeyHashHex:    hexKeccak(s.Key[:]),
		SlotsReturned:        0,
		StorageRootHex:       hexHash(s.StorageRoot),
		ProofNodesHex:        []string{},
		StorageProofValid:    true,
		BeaconSynced:         beaconSynced(a.BeaconSlot, nowUnix),
		BeaconChainVerified:  true,
		BlsVerified:          true,
		MatchedBeaconSlot:    int64(a.BeaconSlot),
		VerifyMethod:         strPtr(accountVerifyMethod),
		PeerBlockNumber:      a.ExecNumber,
		FinalizedBlockNumber: a.ExecNumber,
		OptimisticBlockNum:   a.OptimisticExecNo,
		FinalizedSlot:        a.BeaconSlot,
		OptimisticSlot:       a.OptimisticSlot,
		MaxHeaderChainGap:    8192,
		Anchor:               "finalized",
	}
	// The slot INDEX the RPC carries (the shape's "slot" is the numeric
	// selector; the 32-byte key's high bits must be zero for it to
	// round-trip — a wider key keeps 0 and the key hex carries the truth,
	// same as the Rust twin's numeric-slot API).
	if isUint64Key(s.Key) {
		var n uint64
		for _, b := range s.Key[24:] {
			n = n<<8 | uint64(b)
		}
		out.Slot = n
	}
	if s.Value != nil {
		out.Exists = true
		out.SlotsReturned = 1
		out.ValueHex = strPtr(hex0x(s.Value))
		out.ValueDecimal = strPtr(beToDecimal(s.Value))
	}
	return marshal(out)
}

// --- encodings, ported from eljson.rs so both engines emit identical
// value forms ---

// hex0x / hexHash / hexKeccak: 0x-prefixed lowercase hex (hex0x /
// hex0x_var), and keccak256 fed straight into the same encoding.
func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }
func hexHash(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}
func hexKeccak(b []byte) string { return hex0x(crypto.Keccak256(b)) }

// beToDecimal: big-endian bytes → decimal string, empty/zero → "0"
// (eljson.rs be_to_decimal; balances exceed int64, so strings).
func beToDecimal(b []byte) string {
	return new(big.Int).SetBytes(b).String()
}

func strPtr(s string) *string { return &s }

func beaconSynced(finalizedSlot uint64, nowUnix int64) bool {
	wall := chain.ConsensusMainnet().SlotAt(nowUnix)
	return wall >= finalizedSlot && wall-finalizedSlot <= SyncedSlackSlots
}

func isUint64Key(k [32]byte) bool {
	for _, b := range k[:24] {
		if b != 0 {
			return false
		}
	}
	return true
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("engine: result marshal: %w", err)
	}
	return string(b), nil
}
