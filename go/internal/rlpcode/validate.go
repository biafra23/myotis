package rlpcode

// Whole-item validation, ported rule-for-rule from
// rust/myotis-core/src/rlp.rs's decode_item/skip_item: the same
// canonical-form, bounds and depth checks, so an acceptance divergence
// between the engines cannot hide behind a library's leniency. The
// internal/trie verifier and the snap decoders share this ONE
// definition — the snap side must check a dropped range entry exactly
// as a kept one (#454), and the MPT side refuses a node whose
// never-visited slot is malformed (corpus vector 084).
//
// Error strings keep the Rust "RLP: " prefix: the MPT verifier embeds
// them in proof-failure reasons whose substrings the snap reader's
// PrunedRoot-vs-BadProof classification reads.

import (
	"errors"
	"fmt"
)

// MaxDepth is rlp.rs's MAX_DEPTH: real EL payloads nest ≤ 5 deep (ENR
// `eth` field: list-in-list-in-record); 32 leaves huge headroom while
// keeping a hostile deep-nest node from touching the real stack.
const MaxDepth = 32

// ValidateNode is the Go twin of rlp.rs's decode + validate: the input
// must be EXACTLY one well-formed item — minimal length prefixes,
// bounded length-of-length, list elements that never overrun their
// container, and nesting capped at MaxDepth. Rust builds the item
// tree there and Go checks the same rules building nothing (same
// decisions, same error strings); a node failing it is a malformed
// node in every caller, whatever the walk would otherwise have found —
// corpus vector 084 pins exactly this eagerness.
func ValidateNode(data []byte) error {
	used, err := validateItem(data, 0, 0)
	if err != nil {
		return err
	}
	if used != len(data) {
		return fmt.Errorf("RLP: %d trailing bytes after top-level item", len(data)-used)
	}
	return nil
}

// validateItem walks one item from pos and returns the end position.
func validateItem(data []byte, pos, depth int) (int, error) {
	if depth > MaxDepth {
		return 0, errors.New("RLP: nesting too deep")
	}
	if pos >= len(data) {
		return 0, errors.New("RLP: truncated (empty input)")
	}
	first := data[pos]
	switch {
	// Single byte, value 0x00..=0x7f: the byte is its own encoding.
	case first <= 0x7f:
		return pos + 1, nil
	// Short string: 0-55 bytes.
	case first <= 0xb7:
		n := int(first - 0x80)
		if pos+1+n > len(data) {
			return 0, errors.New("RLP: truncated (input shorter than declared)")
		}
		if n == 1 && data[pos+1] < 0x80 {
			return 0, errors.New("RLP: non-canonical single byte (should be encoded as itself)")
		}
		return pos + 1 + n, nil
	// Long string: length-of-length 1-8.
	case first <= 0xbf:
		n, header, err := readLongLength(data, pos, int(first-0xb7))
		if err != nil {
			return 0, err
		}
		if pos+header+n > len(data) {
			return 0, errors.New("RLP: truncated (input shorter than declared)")
		}
		return pos + header + n, nil
	// Short list: total payload 0-55 bytes (0xf7 = 55 is the max SHORT
	// list — the form corpus vector 001 legitimately uses).
	case first <= 0xf7:
		return validateListPayload(data, pos+1, int(first-0xc0), depth)
	// Long list.
	default:
		n, header, err := readLongLength(data, pos, int(first-0xf7))
		if err != nil {
			return 0, err
		}
		return validateListPayload(data, pos+header, n, depth)
	}
}

// readLongLength reads a canonical long-form length: 1-8 big-endian
// bytes, no leading zero, value > 55 (else the short form applied), and
// within the input. Returns (payloadLen, headerLen). Accumulating in
// uint64 before the bounds check keeps a hostile 8-byte length from
// overflowing int on 32-bit targets — same guard, same reason, as
// rlp.rs:433-443.
func readLongLength(data []byte, pos, lenOfLen int) (int, int, error) {
	if pos+1+lenOfLen > len(data) {
		return 0, 0, errors.New("RLP: truncated (input shorter than declared)")
	}
	lenBytes := data[pos+1 : pos+1+lenOfLen]
	if lenBytes[0] == 0 {
		return 0, 0, errors.New("RLP: length has leading zero byte")
	}
	var n uint64
	for _, b := range lenBytes {
		n = n<<8 | uint64(b)
	}
	if n <= 55 {
		return 0, 0, errors.New("RLP: non-canonical long-form length <= 55")
	}
	if n > uint64(len(data)) {
		return 0, 0, errors.New("RLP: truncated (declared length exceeds input)")
	}
	return int(n), 1 + lenOfLen, nil
}

func validateListPayload(data []byte, start, length, depth int) (int, error) {
	end := start + length
	if end < start || end > len(data) {
		return 0, errors.New("RLP: truncated list payload")
	}
	pos := start
	for pos < end {
		next, err := validateItem(data, pos, depth+1)
		if err != nil {
			return 0, err
		}
		if next > end {
			return 0, errors.New("RLP: list element overruns list payload")
		}
		pos = next
	}
	return end, nil
}

func toNibbles(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, x>>4, x&0x0f)
	}
	return out
}

// hexPrefixDecode decodes a compact-encoded path into (isLeaf,
// nibbles) — trie.rs:322-341 verbatim, including the flag>3 refusal
// (flag nibbles 4..7 are unspecified in Appendix C; honest tries never
// emit them).
func hexPrefixDecode(encoded []byte) (bool, []byte, error) {
	if len(encoded) == 0 {
		return false, nil, errors.New("empty hex-prefix path")
	}
	flag := encoded[0] >> 4
	if flag > 3 {
		return false, nil, fmt.Errorf("invalid hex-prefix flag nibble: %d", flag)
	}
	leaf := flag&0x02 != 0
	odd := flag&0x01 != 0
	nibbles := make([]byte, 0, len(encoded)*2)
	if odd {
		nibbles = append(nibbles, encoded[0]&0x0f)
	}
	for _, b := range encoded[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return leaf, nibbles, nil
}

// hexPrefixEncode is the round-trip partner, used by tests (trie.rs:344).
func hexPrefixEncode(nibbles []byte, leaf bool) []byte {
	odd := len(nibbles)%2 == 1
	var flag byte
	if leaf {
		flag |= 2
	}
	if odd {
		flag |= 1
	}
	out := make([]byte, 0, 1+len(nibbles)/2)
	rest := nibbles
	if odd {
		out = append(out, flag<<4|nibbles[0]&0x0f)
		rest = nibbles[1:]
	} else {
		out = append(out, flag<<4)
	}
	for i := 0; i+1 < len(rest); i += 2 {
		out = append(out, rest[i]<<4|rest[i+1]&0x0f)
	}
	return out
}
