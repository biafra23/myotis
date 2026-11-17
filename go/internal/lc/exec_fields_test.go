package lc

// parseLCHeader's ExecNumber/ExecTimestamp/ExecBlockHash wiring, pinned
// against the layout table with DISJOINT markers per field. The table
// itself needs no pin here: execHeaderRoot's merkleization is replayed
// against real attestations by the corpus tests, and a table with a
// wrong block_hash leaf would match nothing — what that corpus cannot
// catch is the PARSE diverging from the table (PR #819 review: the
// first cut read 440, base_fee, as block_hash, and shipped green
// because the engine goldens hand-build their anchors).

import (
	"encoding/binary"
	"testing"
)

func TestParseLCHeaderExecFieldOffsets(t *testing.T) {
	const beaconLen = 112
	const offLen = 4
	const branchLen = 4 * 32
	ephOff := beaconLen + offLen + branchLen // == lcHeaderFixedSize

	eph := make([]byte, execFixedDeneb) // Deneb fixed section, no extra
	binary.LittleEndian.PutUint32(eph[execExtraOffsetAt:], execFixedDeneb)
	var (
		stateRoot = fill32(0x53)
		baseFee   = fill32(0xBB) // the field the #819 review caught being
		blockHash = fill32(0xCC) // mistaken for block_hash: distinct bytes
	)
	copy(eph[52:], stateRoot[:])
	copy(eph[440:], baseFee[:])
	copy(eph[472:], blockHash[:])
	const number = uint64(0x0102030405060708)
	const timestamp = uint64(0x0807060504030201)
	binary.LittleEndian.PutUint64(eph[404:], number)
	binary.LittleEndian.PutUint64(eph[428:], timestamp)

	region := make([]byte, ephOff+len(eph))
	binary.LittleEndian.PutUint32(region[beaconLen:], uint32(ephOff))
	copy(region[ephOff:], eph)

	h, err := parseLCHeader(region)
	if err != nil {
		t.Fatalf("parseLCHeader: %v", err)
	}
	if h.ExecNumber != number {
		t.Errorf("ExecNumber = %#x, want %#x (offset 404)", h.ExecNumber, number)
	}
	if h.ExecTimestamp != timestamp {
		t.Errorf("ExecTimestamp = %#x, want %#x (offset 428)", h.ExecTimestamp, timestamp)
	}
	if h.ExecBlockHash != blockHash {
		t.Errorf("ExecBlockHash = %x, want %x — 472 is block_hash; %x at 440 is base_fee_per_gas",
			h.ExecBlockHash[:1], blockHash[:1], baseFee[:1])
	}
	if h.ExecStateRoot != stateRoot {
		t.Errorf("ExecStateRoot = %x, want %x (offset 52)", h.ExecStateRoot[:1], stateRoot[:1])
	}
}

func fill32(b byte) hash32 {
	var h hash32
	for i := range h {
		h[i] = b
	}
	return h
}
