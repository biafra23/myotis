// Package rlpcode is the small RLP toolkit shared by the rlpx and ethwire
// packages: canonical minimal-integer encodings, list assembly, and a
// tolerant item walker for decoding peer-produced messages. Encoding leans
// on go-ethereum's canonical rlp package (docs/spec/07 decision: settled
// plumbing from geth); the walker exists because control messages arrive as
// raw RLP we must inspect field by field. geth's rlp.Split already
// distinguishes Byte/String/List and hands back content, so the walker is
// thin on purpose.
package rlpcode

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
)

// Uint returns v as a canonical minimal big-endian RLP integer item, ready to
// embed in a List.
func Uint(v uint64) rlp.RawValue {
	return rlp.RawValue(rlp.AppendUint64(nil, v))
}

// Bytes returns b as an RLP byte-string item, ready to embed in a List.
func Bytes(b []byte) rlp.RawValue {
	enc, err := rlp.EncodeToBytes(b)
	if err != nil {
		panic("rlpcode: EncodeToBytes([]byte) failed: " + err.Error())
	}
	return rlp.RawValue(enc)
}

// String returns s as an RLP byte-string item.
func String(s string) rlp.RawValue {
	return Bytes([]byte(s))
}

// List assembles pre-encoded items into an RLP list item.
func List(items ...rlp.RawValue) rlp.RawValue {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	out := make([]byte, 0, len(content)+9)
	if len(content) < 56 {
		out = append(out, byte(0xc0+len(content)))
	} else {
		lenBE := beBytes(uint64(len(content)))
		out = append(out, byte(0xf7+len(lenBE)))
		out = append(out, lenBE...)
	}
	return rlp.RawValue(append(out, content...))
}

func beBytes(v uint64) []byte {
	var buf [8]byte
	i := 8
	for v > 0 {
		i--
		buf[i] = byte(v)
		v >>= 8
	}
	return buf[i:]
}

// SplitItem splits one RLP item off the front of b, returning its complete
// encoded bytes (header included) and the remainder.
func SplitItem(b []byte) (item, rest []byte, err error) {
	_, _, rest, err = rlp.Split(b)
	if err != nil {
		return nil, nil, err
	}
	consumed := len(b) - len(rest)
	return b[:consumed], rest, nil
}

// Items decodes b as an RLP list and returns its items (each still fully
// encoded). A non-list input or trailing bytes after the list are errors —
// a message frame body must not carry a second top-level item.
func Items(b []byte) ([][]byte, error) {
	kind, content, rest, err := rlp.Split(b)
	if err != nil {
		return nil, err
	}
	if kind != rlp.List {
		return nil, fmt.Errorf("rlpcode: expected list, got %v", kind)
	}
	if len(rest) != 0 {
		return nil, errors.New("rlpcode: trailing bytes after list")
	}
	items := make([][]byte, 0, 8)
	for len(content) > 0 {
		it, next, err := SplitItem(content)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
		content = next
	}
	return items, nil
}

// LeafBytes returns the content of a byte-string item (empty string → empty,
// never a list), rejecting trailing bytes.
func LeafBytes(item []byte) ([]byte, error) {
	kind, content, rest, err := rlp.Split(item)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("rlpcode: trailing bytes in leaf item")
	}
	if kind == rlp.List {
		return nil, errors.New("rlpcode: expected bytes, got list")
	}
	return content, nil
}

// FixedBytes returns the content of a byte-string item of exactly n bytes.
func FixedBytes(item []byte, n int) ([]byte, error) {
	b, err := LeafBytes(item)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("rlpcode: expected %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// U64 decodes an integer item (empty → 0, ≤8 bytes, canonical
// no-leading-zero).
func U64(item []byte) (uint64, error) {
	kind, content, rest, err := rlp.Split(item)
	if err != nil {
		return 0, err
	}
	if len(rest) != 0 {
		return 0, errors.New("rlpcode: trailing bytes in integer item")
	}
	if kind == rlp.List {
		return 0, errors.New("rlpcode: expected integer, got list")
	}
	switch len(content) {
	case 0:
		return 0, nil
	case 1:
		return uint64(content[0]), nil
	default:
		if len(content) > 8 {
			return 0, errors.New("rlpcode: integer over 8 bytes")
		}
		if content[0] == 0 {
			return 0, errors.New("rlpcode: non-canonical integer (leading zero)")
		}
		var v uint64
		for _, b := range content {
			v = v<<8 | uint64(b)
		}
		return v, nil
	}
}

// Bool decodes an integer item as a boolean (0 or 1).
func Bool(item []byte) (bool, error) {
	v, err := U64(item)
	if err != nil {
		return false, err
	}
	if v > 1 {
		return false, errors.New("rlpcode: boolean item > 1")
	}
	return v == 1, nil
}
