package lc

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/biafra23/myotis/go/internal/chain"
)

// ErrShape is returned when bytes match none of the decodable wire shapes —
// the Go twin of the Rust decoders' fork-sniff exhaustion (types.rs).
var ErrShape = errors.New("lc: bytes match no known container shape")

// branchGeom is the merkle proof geometry per beacon fork: branch lengths
// and the gindex of each proven state field. Deneb's state is a 32-wide
// tree (depth 5: sync-committee fields at gindex 54/55, finalized root at
// ((1<<4)+20)*2+1 = 105); Electra/Fulu widened it (depth 6: 86/87, 169);
// Gloas carries fixed constants (735/2945/2946/2856, spec.rs:25-36). The
// execution branch inside a pre-Gloas LightClientHeader is 4 nodes at
// gindex 25 in every fork (EXECUTION_PAYLOAD_GINDEX).
type branchGeom struct {
	FinalizedGindex, FinalizedLen uint64
	SyncGindex, SyncLen           uint64
	NextGindex, NextLen           uint64
	ExecGindex, ExecLen           uint64
}

var (
	geomDeneb = branchGeom{105, 6, 54, 5, 55, 5, 25, 4}
	// Fulu speaks Electra geometry (the widened state); with no Gloas epoch
	// pinned for mainnet, this is the head geometry. Gloas's fixed
	// geometry (735/9, 2945/11, 2946/11, 2856/11 — spec.rs:25-36) gets a
	// var here the day a Gloas epoch is pinned in chain/lc.go; until then
	// the numbers live only in this comment, so no unselected geometry
	// masquerades as a live gate (PR #769 review).
	geomElectra = branchGeom{169, 7, 86, 6, 87, 6, 25, 4}
)

// ForkSchedule serves the per-slot fork version the signing domain needs.
// The off-by-one is load-bearing and pinned by the Rust tests
// (fork.rs:191-194): the domain for a signature slot uses the version at
// epoch (slot-1)/32. The wire-shape switch has NO such off-by-one.
type ForkSchedule struct{ c *chain.Consensus }

func NewForkSchedule(c *chain.Consensus) *ForkSchedule { return &ForkSchedule{c} }

func (f *ForkSchedule) VersionAtEpoch(epoch uint64) [4]byte {
	v := f.c.Forks[0].Version
	for _, fa := range f.c.Forks {
		if epoch >= fa.Epoch {
			v = fa.Version
		}
	}
	return v
}

func (f *ForkSchedule) VersionForSignatureSlot(slot uint64) [4]byte {
	return f.VersionAtEpoch((max(slot, 1) - 1) / chain.SlotsPerEpoch)
}

func (f *ForkSchedule) geomAtSlot(slot uint64) branchGeom {
	if slot/chain.SlotsPerEpoch >= f.epochOfVersion(0x05) {
		return geomElectra // Electra and Fulu
	}
	return geomDeneb
	// NO Gloas tier on purpose: this build has no Gloas geometry and
	// DecodeUpdate refuses a Gloas-shaped update (see its switch), so
	// pinning a Gloas epoch on an UNCHANGED build refuses updates
	// loudly instead of misparsing them. Gloas support (a geomGloas
	// row here, the 9+11 decode family, and the already-ported
	// verifyNormalizedMerkleBranch) is one documented increment —
	// go/README §"deliberate cuts" — not a variable flip.
}

func (f *ForkSchedule) epochOfVersion(head byte) uint64 {
	for _, fa := range f.c.Forks {
		if fa.Version[0] == head {
			return fa.Epoch
		}
	}
	return ^uint64(0)
}

// ---- fixed containers ----

type BeaconBlockHeader struct {
	Slot, ProposerIndex uint64
	ParentRoot          hash32
	StateRoot           hash32
	BodyRoot            hash32
}

func (h *BeaconBlockHeader) Root() hash32 {
	return containerRoot(
		uint64Root(h.Slot), uint64Root(h.ProposerIndex),
		h.ParentRoot, h.StateRoot, h.BodyRoot)
}

func decodeBeaconBlockHeader(b []byte) (*BeaconBlockHeader, error) {
	if len(b) != 112 {
		return nil, fmt.Errorf("lc: beacon header: want 112 bytes, got %d", len(b))
	}
	h := &BeaconBlockHeader{
		Slot:          binary.LittleEndian.Uint64(b[0:8]),
		ProposerIndex: binary.LittleEndian.Uint64(b[8:16]),
	}
	copy(h.ParentRoot[:], b[16:48])
	copy(h.StateRoot[:], b[48:80])
	copy(h.BodyRoot[:], b[80:112])
	return h, nil
}

const syncCommitteeSizeBytes = SyncCommitteeSize*48 + 48 // 24624

type SyncCommittee struct {
	Pubkeys   [][48]byte
	Aggregate [48]byte
}

// Root merkleizes the 512-pubkey vector (two chunks each) and the
// aggregate: spec SyncCommittee container.
func (s *SyncCommittee) Root() hash32 {
	chunks := make([]hash32, 0, SyncCommitteeSize*2)
	for _, pk := range s.Pubkeys {
		chunks = append(chunks, chunkBytes(pk[:])...)
	}
	return containerRoot(merkleize(chunks, uint64(len(chunks))), vectorRoot(s.Aggregate[:]))
}

func decodeSyncCommittee(b []byte) (*SyncCommittee, error) {
	if len(b) != syncCommitteeSizeBytes {
		return nil, fmt.Errorf("lc: sync committee: want %d bytes, got %d", syncCommitteeSizeBytes, len(b))
	}
	s := &SyncCommittee{}
	for i := 0; i < SyncCommitteeSize; i++ {
		var pk [48]byte
		copy(pk[:], b[i*48:(i+1)*48])
		s.Pubkeys = append(s.Pubkeys, pk)
	}
	copy(s.Aggregate[:], b[syncCommitteeSizeBytes-48:])
	return s, nil
}

type SyncAggregate struct {
	Participation [64]byte
	Signature     [96]byte
}

func (a *SyncAggregate) Participants() int {
	n := 0
	for _, b := range a.Participation {
		for b != 0 {
			n += int(b & 1)
			b >>= 1
		}
	}
	return n
}

func (a *SyncAggregate) Active(i int) bool {
	return a.Participation[i/8]&(1<<(uint(i)%8)) != 0
}

func decodeSyncAggregate(b []byte) (*SyncAggregate, error) {
	if len(b) != 160 {
		return nil, fmt.Errorf("lc: sync aggregate: want 160 bytes, got %d", len(b))
	}
	a := &SyncAggregate{}
	copy(a.Participation[:], b[:64])
	copy(a.Signature[:], b[64:160])
	return a, nil
}

// ---- execution payload header ----
//
// Fixed-section layout per the Rust decoder (types.rs:197-272). The extra
// data offset at 436 doubles as the Electra discriminator (>= 680):
//
//	0 parent | 32 fee_recipient(20) | 52 state | 84 receipts | 116 bloom(256)
//	372 randao | 404 number | 412 gas_limit | 420 gas_used | 428 timestamp
//	436 extra_data OFFSET | 440 base_fee(32) | 472 block_hash
//	504 transactions_root | 536 withdrawals_root | 568 blob_gas_used
//	576 excess_blob_gas | = 584 (Deneb fixed); Electra appends the request
//	roots at 584/616/648 → fixed 680 — parsed but EXCLUDED from the root:
//	the htr is the 17 Deneb leaves in every pre-Gloas fork (Java parity).

const (
	execFixedDeneb    = 584
	execFixedElectra  = 680
	execExtraOffsetAt = 436
	logsBloomChunks   = 8
)

// execHeaderRoot roots one ExecutionPayloadHeader from its full encoding
// (fixed section + the extra_data bytes at its tail). The out-of-range
// offset fallback is Java-parity behaviour of the Rust decoder: empty
// extra, not an error — a forged offset fails the execution-branch check
// downstream.
func execHeaderRoot(eph []byte) (hash32, error) {
	if len(eph) < execFixedDeneb {
		return hash32{}, ErrShape
	}
	off := int(binary.LittleEndian.Uint32(eph[execExtraOffsetAt:]))
	isElectra := off >= execFixedElectra
	fixed := execFixedDeneb
	if isElectra {
		fixed = execFixedElectra
		if len(eph) < fixed {
			return hash32{}, errors.New("lc: execution header: Electra offset but short buffer")
		}
	}
	var extra []byte
	if off >= fixed && off <= len(eph) {
		extra = eph[off:]
	}
	// extra_data is ByteList[32] and this region runs to the end of
	// whatever the peer sent (bootstrap/finalized headers own the buffer
	// tail): an oversized one must be REJECTED here — listRoot panics on
	// it, and this is the one length taken from the buffer rather than
	// sniffed from an offset (PR #769 review). The Rust twin does not
	// panic here either: merkleize widens the limit and the
	// execution-branch check rejects downstream.
	if len(extra) > 32 {
		return hash32{}, fmt.Errorf("%w: extra_data is %d bytes (max 32)", ErrShape, len(extra))
	}
	at := func(i, n int) []byte { return eph[i : i+n] }
	u64 := func(i int) hash32 { return uint64Root(binary.LittleEndian.Uint64(eph[i : i+8])) }
	push := func(b []byte) hash32 { var h hash32; copy(h[:], b); return h }

	return containerRoot(
		push(at(0, 32)),          // parent_hash
		vectorRoot(at(32, 20)),   // fee_recipient
		push(at(52, 32)),         // state_root ← part 4's read anchor
		push(at(84, 32)),         // receipts_root
		vectorRoot(at(116, 256)), // logs_bloom: FIXED 256 B — bytes-vector
		// root, NO mix-in-length (byte_vector_root in the Rust twin;
		// listRoot here is the classic off-the-spec root).
		push(at(372, 32)),                      // prev_randao
		u64(404), u64(412), u64(420), u64(428), // number, gas_limit, gas_used, timestamp
		listRoot(extra, 1), // extra_data (List, ≤32 B)
		push(at(440, 32)),  // base_fee_per_gas (uint256 LE)
		push(at(472, 32)),  // block_hash
		push(at(504, 32)),  // transactions_root
		push(at(536, 32)),  // withdrawals_root
		u64(568), u64(576), // blob_gas_used, excess_blob_gas
	), nil
}

// ---- LightClientHeader (pre-Gloas wire shape) ----
//
// Container [beacon(112) | exec OFFSET(4, always 244) |
// execution_branch(4×32) | execution payload header]. The header's own
// branch proves the payload header against the beacon BODY root (gindex
// 25, 4 nodes) — a different proof family from the update's finality and
// next-committee branches, which point into the attested STATE.

const lcHeaderFixedSize = 244

type lcHeader struct {
	Beacon *BeaconBlockHeader
	Exec   hash32 // htr of the execution payload header
	// ExecStateRoot is the payload's own state_root field — what part 4's
	// snap reads verify against (the conformance key final.finalizedExecStateRoot
	// records this field, not the EPH root).
	ExecStateRoot hash32
	Branch        []hash32
}

// parseLCHeader parses a LightClientHeader from its BOUNDED region (the
// caller carves it with the container's stored offsets):
// [beacon(112) | exec OFFSET(4) | execution_branch(4×32) | EPH…].
func parseLCHeader(region []byte) (*lcHeader, error) {
	if len(region) < lcHeaderFixedSize {
		return nil, ErrShape
	}
	off := int(binary.LittleEndian.Uint32(region[112:116]))
	if off < lcHeaderFixedSize || off > len(region) {
		return nil, ErrShape
	}
	beacon, err := decodeBeaconBlockHeader(region[:112])
	if err != nil {
		return nil, err
	}
	branch := make([]hash32, 4)
	for i := 0; i < 4; i++ {
		copy(branch[i][:], region[116+i*32:])
	}
	exec, err := execHeaderRoot(region[off:])
	if err != nil {
		return nil, err
	}
	var execState hash32
	if len(region)-off >= 84 {
		copy(execState[:], region[off+52:])
	}
	return &lcHeader{Beacon: beacon, Exec: exec, ExecStateRoot: execState, Branch: branch}, nil
}

// ---- LightClientBootstrap ----
//
// SSZ fixed/variable split puts the (variable) header at a stored offset
// behind the fixed section: [off_hdr:4 | committee:24624 | branch:k×32 |
// header…]. The offset IS the branch-length oracle (mirror of the Rust
// decoder, types.rs:485-523), and reads past the sniffed region must
// reject, not panic.

type Bootstrap struct {
	Header          *lcHeader
	SyncCommittee   *SyncCommittee
	CommitteeBranch []hash32
}

func DecodeBootstrap(b []byte) (*Bootstrap, error) {
	if len(b) < 4+syncCommitteeSizeBytes+5*32 {
		return nil, ErrShape
	}
	hdrOff := int(binary.LittleEndian.Uint32(b[0:4]))
	branchBytes := hdrOff - (4 + syncCommitteeSizeBytes)
	if branchBytes < 5*32 || branchBytes > 6*32 || branchBytes%32 != 0 || hdrOff > len(b) {
		return nil, fmt.Errorf("%w: bootstrap branch region %d bytes", ErrShape, branchBytes)
	}
	k := branchBytes / 32
	sc, err := decodeSyncCommittee(b[4 : 4+syncCommitteeSizeBytes])
	if err != nil {
		return nil, err
	}
	branch, err := readRoots(b, 4+syncCommitteeSizeBytes, k)
	if err != nil {
		return nil, err
	}
	hdr, err := parseLCHeader(b[hdrOff:])
	if err != nil {
		return nil, err
	}
	return &Bootstrap{Header: hdr, SyncCommittee: sc, CommitteeBranch: branch}, nil
}

// ---- LightClientUpdate ----
//
// [off_att:4 | next_committee:24624 | next_branch:sc·32 | off_fin:4 |
// finality_branch:fin·32 | aggregate:160 | signature_slot:8 | attested |
// finalized]. The branch family is sniffed from the (attacker-controlled)
// attested offset: exactly 6+7 nodes selects Electra geometry, anything
// else falls back to the pre-Electra 5+6 — Java-observed tolerance,
// pinned by the Rust twin's comment at types.rs:608-612.

type Update struct {
	Attested       *lcHeader
	NextCommittee  *SyncCommittee
	NextBranch     []hash32
	Finalized      *lcHeader
	FinalityBranch []hash32
	Aggregate      *SyncAggregate
	SignatureSlot  uint64
}

func DecodeUpdate(b []byte) (*Update, error) {
	if len(b) < 4+syncCommitteeSizeBytes+4+5*32+6*32+160+8 {
		return nil, ErrShape
	}
	attOff := int(binary.LittleEndian.Uint32(b[0:4]))
	totalBranch := attOff - (4 + syncCommitteeSizeBytes + 4 + 160 + 8)
	// Only the geometries this build decodes (the geomAtSlot families:
	// Deneb 5+6, Electra/Fulu 6+7). Anything else — a Gloas-era 9+11
	// above all — is REFUSED, not defaulted to 5+6: silently reading a
	// Gloas update's next-committee branch as the finality branch
	// would misparse the object into plausible wrong values (a review
	// finding; go/README lists Gloas geometry as a deliberate cut —
	// mainnet pins no Gloas epoch, so refusing is unreachable today
	// and honest the day one is pinned).
	scNodes, finNodes := 5, 6
	switch totalBranch {
	case 5*32 + 6*32:
	case 6*32 + 7*32:
		scNodes, finNodes = 6, 7
	default:
		return nil, fmt.Errorf("lc: update branch geometry %d bytes matches no geometry this build decodes (Gloas 9+11 is a documented cut)", totalBranch)
	}
	pos := 4
	next, err := decodeSyncCommittee(b[pos : pos+syncCommitteeSizeBytes])
	if err != nil {
		return nil, err
	}
	pos += syncCommitteeSizeBytes
	nextBranch, err := readRoots(b, pos, scNodes)
	if err != nil {
		return nil, err
	}
	pos += scNodes * 32
	if pos+4 > len(b) {
		return nil, ErrShape
	}
	finOff := int(binary.LittleEndian.Uint32(b[pos : pos+4]))
	pos += 4
	finBranch, err := readRoots(b, pos, finNodes)
	if err != nil {
		return nil, err
	}
	pos += finNodes * 32
	if pos+168 > len(b) {
		return nil, ErrShape
	}
	agg, err := decodeSyncAggregate(b[pos : pos+160])
	if err != nil {
		return nil, err
	}
	slot := binary.LittleEndian.Uint64(b[pos+160 : pos+168])
	// Both stored offsets must sit at or past the end of the fixed part
	// just read (the Rust finality decoder's actual_fixed bound,
	// types.rs:759-764): on a 32-bit int, int(uint32) goes negative for
	// offsets ≥ 2³¹ and a bare `attOff > finOff` check would let a
	// negative slice index through.
	if attOff < pos+168 || attOff > finOff || finOff < pos+168 || finOff > len(b) {
		return nil, ErrShape
	}
	attested, err := parseLCHeader(b[attOff:finOff])
	if err != nil {
		return nil, err
	}
	finalized, err := parseLCHeader(b[finOff:])
	if err != nil {
		return nil, err
	}
	return &Update{
		Attested: attested, NextCommittee: next, NextBranch: nextBranch,
		Finalized: finalized, FinalityBranch: finBranch,
		Aggregate: agg, SignatureSlot: slot,
	}, nil
}

// ---- LightClientFinalityUpdate ----
//
// [off_att:4 | off_fin:4 | finality_branch:6or7×32 | aggregate:160 |
// signature_slot:8 | attested | finalized].

type FinalityUpdate struct {
	Attested       *lcHeader
	Finalized      *lcHeader
	FinalityBranch []hash32
	Aggregate      *SyncAggregate
	SignatureSlot  uint64
}

func DecodeFinalityUpdate(b []byte) (*FinalityUpdate, error) {
	if len(b) < 8+6*32+160+8 {
		return nil, ErrShape
	}
	attOff := int(binary.LittleEndian.Uint32(b[0:4]))
	finOff := int(binary.LittleEndian.Uint32(b[4:8]))
	branchBytes := attOff - (4 + 4 + 160 + 8)
	if branchBytes%32 != 0 {
		return nil, ErrShape
	}
	k := branchBytes / 32
	if k != 6 && k != 7 {
		return nil, fmt.Errorf("%w: finality branch nodes %d (want 6 or 7)", ErrShape, k)
	}
	fb, err := readRoots(b, 8, k)
	if err != nil {
		return nil, err
	}
	pos := 8 + k*32
	if pos+168 > len(b) {
		return nil, ErrShape
	}
	agg, err := decodeSyncAggregate(b[pos : pos+160])
	if err != nil {
		return nil, err
	}
	slot := binary.LittleEndian.Uint64(b[pos+160 : pos+168])
	// Same fixed-part lower bound as DecodeUpdate (types.rs:759-764).
	if attOff < pos+168 || attOff > finOff || finOff < pos+168 || finOff > len(b) {
		return nil, ErrShape
	}
	attested, err := parseLCHeader(b[attOff:finOff])
	if err != nil {
		return nil, err
	}
	finalized, err := parseLCHeader(b[finOff:])
	if err != nil {
		return nil, err
	}
	return &FinalityUpdate{
		Attested: attested, Finalized: finalized, FinalityBranch: fb,
		Aggregate: agg, SignatureSlot: slot,
	}, nil
}

func readRoots(b []byte, off, n int) ([]hash32, error) {
	if off < 0 || off+n*32 > len(b) {
		return nil, ErrShape
	}
	out := make([]hash32, n)
	for i := 0; i < n; i++ {
		copy(out[i][:], b[off+i*32:])
	}
	return out, nil
}

// finalityShapeOk is the store's shape gate shared by both processor
// paths (update_shape_ok / headers_in_attested_forks_shape): both
// headers' execution-branch family and the finality-branch length must
// agree with the fork the attester lived in.
func finalityShapeOk(attested, finalized *lcHeader, geom branchGeom, finalityLen int) bool {
	return len(attested.Branch) == int(geom.ExecLen) &&
		len(finalized.Branch) == int(geom.ExecLen) &&
		finalityLen == int(geom.FinalizedLen)
}

// shapeOk adds the update path's next-committee branch to
// finalityShapeOk. Both are wired: ProcessUpdate calls shapeOk,
// ProcessFinalityUpdate calls finalityShapeOk.
func shapeOk(attested, finalized *lcHeader, geom branchGeom, finalityLen, nextLen int) bool {
	return finalityShapeOk(attested, finalized, geom, finalityLen) &&
		nextLen == int(geom.NextLen)
}
