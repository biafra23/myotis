package clwire

import (
	"encoding/binary"
	"fmt"
)

// StatusMessage is the eth2 Status container (status.rs:11-19). v2 (92
// bytes, post-Electra) adds earliest_available_slot; v1 (84) is the same
// layout without it. The mandatory first exchange on every connection:
// a peer whose digest differs from ours is a wrong-fork peer and gets
// dropped before any LC request.
type StatusMessage struct {
	ForkDigest            [4]byte
	FinalizedRoot         [32]byte
	FinalizedEpoch        uint64
	HeadRoot              [32]byte
	HeadSlot              uint64
	EarliestAvailableSlot uint64
}

const (
	StatusSizeV2 = 92
	StatusSizeV1 = 84
)

func (s *StatusMessage) Encode() []byte {
	out := make([]byte, 0, StatusSizeV2)
	out = append(out, s.ForkDigest[:]...)
	out = append(out, s.FinalizedRoot[:]...)
	out = binary.LittleEndian.AppendUint64(out, s.FinalizedEpoch)
	out = append(out, s.HeadRoot[:]...)
	out = binary.LittleEndian.AppendUint64(out, s.HeadSlot)
	out = binary.LittleEndian.AppendUint64(out, s.EarliestAvailableSlot)
	return out
}

// EncodeV1 drops earliest_available_slot (the v1 wire shape).
func (s *StatusMessage) EncodeV1() []byte { return s.Encode()[:StatusSizeV1] }

func DecodeStatus(b []byte) (StatusMessage, error) {
	var s StatusMessage
	if len(b) < StatusSizeV2 {
		return s, fmt.Errorf("%w: Status requires %d bytes, got %d", ErrCodec, StatusSizeV2, len(b))
	}
	copy(s.ForkDigest[:], b[0:4])
	copy(s.FinalizedRoot[:], b[4:36])
	s.FinalizedEpoch = binary.LittleEndian.Uint64(b[36:44])
	copy(s.HeadRoot[:], b[44:76])
	s.HeadSlot = binary.LittleEndian.Uint64(b[76:84])
	s.EarliestAvailableSlot = binary.LittleEndian.Uint64(b[84:92])
	return s, nil
}

// DecodeStatusV1 accepts the 84-byte shape; EarliestAvailableSlot stays 0
// (meaning "unknown" to the caller — the skip-on-earliest-slot heuristic
// only runs when it is non-zero).
func DecodeStatusV1(b []byte) (StatusMessage, error) {
	var s StatusMessage
	if len(b) < StatusSizeV1 {
		return s, fmt.Errorf("%w: Status v1 requires %d bytes, got %d", ErrCodec, StatusSizeV1, len(b))
	}
	copy(s.ForkDigest[:], b[0:4])
	copy(s.FinalizedRoot[:], b[4:36])
	s.FinalizedEpoch = binary.LittleEndian.Uint64(b[36:44])
	copy(s.HeadRoot[:], b[44:76])
	s.HeadSlot = binary.LittleEndian.Uint64(b[76:84])
	return s, nil
}

// MetadataV2LightClient is the canonical answer of a pure light client:
// seq 0, no attnets, no syncnets (status.rs:79-85). Seq stays 0 on
// purpose — our metadata never changes, and ping echoes it.
func MetadataV2LightClient() []byte { return make([]byte, 17) }
