package transport

// The snap half of a READY session: GetAccountRange / GetStorageRanges /
// GetByteCodes as single-flight requests, twin of myotis-net's
// EthSession snap methods. These return DECODED snapwire responses
// (the range proofs arrive whole, unlike headers); the verification
// against a trusted root is the CALLER's — snapwire.VerifyAccount &co,
// never these methods (they cannot know the trusted root, and a
// session method that "verified" against the peer's own claim would be
// the trap docs/spec/03 §1 warns about).

import (
	"fmt"

	"github.com/biafra23/myotis/go/internal/snapwire"
)

// snapCodes derives the dynamic code table from what this session
// negotiated. A session with no agreed snap version (Snap == nil) is
// a programming error at this layer, not a network condition: the
// caller must have checked HasSnap before requesting.
func (s *Session) snapCodes() (snapwire.Codes, error) {
	if s.Snap == nil {
		return snapwire.Codes{}, fmt.Errorf(
			"transport: peer %s has no usable snap capability", s.PeerID)
	}
	return snapwire.NegotiatedCodes(s.EthVersion, *s.Snap), nil
}

// HasSnap reports whether the session negotiated a usable snap
// capability — the gate a read pool filters peers with.
func (s *Session) HasSnap() bool { return s.Snap != nil }

// ID names the peer for reporting (satisfies snapread.Peer).
func (s *Session) ID() string { return s.PeerID.String() }

// GetAccountRange requests the account range [startingHash, limitHash)
// at stateRoot (single-key lookups: starting = keccak(address),
// limit = 0xff…ff) and returns the decoded response. The proof inside
// is the verified source of truth; response.Accounts is the peer's
// slim claim, kept for diagnostics only.
func (s *Session) GetAccountRange(stateRoot, startingHash, limitHash [32]byte, responseBytes uint64) (*snapwire.AccountRange, error) {
	codes, err := s.snapCodes()
	if err != nil {
		return nil, err
	}
	id := s.requestID.Add(1)
	req := snapwire.EncodeGetAccountRange(id, stateRoot, startingHash, limitHash, responseBytes)
	payload, err := s.requestFrame(id, codes.GetAccountRange, req, codes.AccountRange,
		fmt.Sprintf("account range at %x", stateRoot[:4]))
	if err != nil {
		return nil, err
	}
	ar, err := snapwire.DecodeAccountRange(payload)
	if err != nil {
		return nil, err
	}
	if ar.RequestID != id {
		return nil, fmt.Errorf("transport: account range response id %d ≠ requested %d", ar.RequestID, id)
	}
	return ar, nil
}

// GetStorageRanges requests one account's storage range at stateRoot
// (starting = keccak(slot32)). The value is verified under the
// account's PROVEN storageRoot afterwards, not here.
func (s *Session) GetStorageRanges(stateRoot, accountHash, startingHash, limitHash [32]byte, responseBytes uint64) (*snapwire.StorageRanges, error) {
	codes, err := s.snapCodes()
	if err != nil {
		return nil, err
	}
	id := s.requestID.Add(1)
	req := snapwire.EncodeGetStorageRanges(id, stateRoot, accountHash, startingHash, limitHash, responseBytes)
	payload, err := s.requestFrame(id, codes.GetStorageRange, req, codes.StorageRanges,
		fmt.Sprintf("storage ranges for account %x at %x", accountHash[:4], stateRoot[:4]))
	if err != nil {
		return nil, err
	}
	sr, err := snapwire.DecodeStorageRanges(payload)
	if err != nil {
		return nil, err
	}
	if sr.RequestID != id {
		return nil, fmt.Errorf("transport: storage ranges response id %d ≠ requested %d", sr.RequestID, id)
	}
	return sr, nil
}

// GetByteCodes requests code hashes and returns the codes the peer
// served. Match each against its hash with snapwire.VerifyBytecode;
// these bytes are unverified until that runs.
func (s *Session) GetByteCodes(hashes [][32]byte, responseBytes uint64) ([][]byte, error) {
	codes, err := s.snapCodes()
	if err != nil {
		return nil, err
	}
	id := s.requestID.Add(1)
	req := snapwire.EncodeGetByteCodes(id, hashes, responseBytes)
	payload, err := s.requestFrame(id, codes.GetByteCodes, req, codes.ByteCodes, "byte codes")
	if err != nil {
		return nil, err
	}
	idBack, served, err := snapwire.DecodeByteCodes(payload, len(hashes))
	if err != nil {
		return nil, err
	}
	if idBack != id {
		return nil, fmt.Errorf("transport: byte codes response id %d ≠ requested %d", idBack, id)
	}
	return served, nil
}
