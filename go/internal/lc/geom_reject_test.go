package lc

// The geometry refusal (review finding): an update whose branch family
// this build does not decode must be REFUSED loudly, never defaulted to
// the Deneb family and misparsed into plausible wrong values.

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeUpdateRefusesUnknownGeometry(t *testing.T) {
	offsets := 4 + syncCommitteeSizeBytes + 4 + 160 + 8
	// A Gloas-shaped candidate: next branch 9 roots + finality branch
	// 11 roots (the geometry the real fork would carry).
	b := make([]byte, offsets+640+200)
	binary.LittleEndian.PutUint32(b[0:4], uint32(offsets+9*32+11*32))
	_, err := DecodeUpdate(b)
	if err == nil || !strings.Contains(err.Error(), "documented cut") {
		t.Fatalf("Gloas geometry must be refused by name, got %v", err)
	}

	// A garbage offset (neither family, not even Gloas): same refusal,
	// not a silent 5+6 fallback with a doomed walk.
	binary.LittleEndian.PutUint32(b[0:4], uint32(offsets+13))
	if _, err := DecodeUpdate(b); err == nil ||
		!strings.Contains(err.Error(), "no geometry") {
		t.Fatalf("unknown geometry must be refused, got %v", err)
	}

	// The two known families still reach the committee decode (they
	// fail later only because this fixture is not a real committee —
	// proving the switch let them through).
	for _, tb := range []int{5*32 + 6*32, 6*32 + 7*32} {
		binary.LittleEndian.PutUint32(b[0:4], uint32(offsets+tb))
		if _, err := DecodeUpdate(b); err != nil &&
			strings.Contains(err.Error(), "no geometry") {
			t.Fatalf("known geometry %d was refused: %v", tb, err)
		}
	}
}
