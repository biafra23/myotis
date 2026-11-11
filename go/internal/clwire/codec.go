package clwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/golang/snappy"
)

// Protocol IDs — exactly the eth2 req/resp identities (protocols.rs:7-51).
// The /ssz_snappy suffix is part of the negotiation name, not a hint.
const (
	StatusV2         = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	StatusV1         = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	Bootstrap        = "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy"
	UpdatesByRange   = "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy"
	FinalityUpdate   = "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy"
	OptimisticUpdate = "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy"
	Ping             = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	MetadataV2       = "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
	MetadataV3       = "/eth2/beacon_chain/req/metadata/3/ssz_snappy"
	Goodbye          = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
)

// HasContextBytes reports whether a protocol's responses carry the 4
// fork-digest context bytes between the result byte and the length
// varint: true for the fork-dependent light_client_* types, false for
// the fixed ones (protocols.rs:57-68).
func HasContextBytes(protocol string) bool {
	switch protocol {
	case Bootstrap, UpdatesByRange, FinalityUpdate, OptimisticUpdate:
		return true
	default:
		return false
	}
}

// Req/resp result codes (codec.rs:22-25).
const (
	ResultSuccess             = 0
	ResultInvalidRequest      = 1
	ResultServerError         = 2
	ResultResourceUnavailable = 3
)

// MaxUncompressedPayload is the spec's MAX_PAYLOAD_SIZE; the declared
// length varint is checked against it BEFORE allocating (the OOM vector
// a 16 MiB max-ratio snappy frame buys an attacker).
const MaxUncompressedPayload = 10 * 1024 * 1024

// MaxUpdatesByRange is MAX_REQUEST_LIGHT_CLIENT_UPDATES: the batch cap
// servers honor on updates_by_range. One definition, used by the
// catch-up loop's per-ask cap and the CLI's probe-range validation —
// a spec bump must move both together or a truncating server reads as
// a wiring bug.
const MaxUpdatesByRange = 128

var ErrCodec = errors.New("clwire: codec error")

// WriteVarint appends a protobuf-style unsigned varint; 0 is one 0x00
// byte.
func WriteVarint(out []byte, v uint64) []byte {
	for {
		if v&^0x7F == 0 {
			return append(out, byte(v))
		}
		out = append(out, byte(v&0x7F)|0x80)
		v >>= 7
	}
}

// ReadVarint returns (value, nextPos). The 5-byte guard (shift ≥ 35) is
// ported from the Rust twin deliberately: wire lengths fit in an i32, so
// a longer varint is attacker noise, not a big payload.
func ReadVarint(data []byte, pos int) (uint64, int, error) {
	var result uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		pos++
		result |= uint64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			return result, pos, nil
		}
		if shift >= 35 {
			return 0, pos, fmt.Errorf("%w: varint too long (overflow at shift %d)", ErrCodec, shift)
		}
	}
	return 0, pos, fmt.Errorf("%w: truncated varint at %d", ErrCodec, pos)
}

// EncodeRequest frames an SSZ payload as varint(len) || snappy-framed(ssz)
// (xerial framing: stream identifier + chunks — the same format the Rust
// codec and the Java ReqRespCodec emit). An empty payload is the single
// byte 0x00.
func EncodeRequest(ssz []byte) []byte {
	if len(ssz) == 0 {
		return []byte{0x00}
	}
	out := WriteVarint(nil, uint64(len(ssz)))
	var buf bytes.Buffer
	w := snappy.NewBufferedWriter(&buf)
	_, _ = w.Write(ssz)
	_ = w.Close()
	return append(out, buf.Bytes()...)
}

// EncodeUpdatesByRangeRequest: (start_period, count) as two LE u64s,
// framed (codec.rs:142-147).
func EncodeUpdatesByRangeRequest(startPeriod, count uint64) []byte {
	var ssz [16]byte
	binary.LittleEndian.PutUint64(ssz[:8], startPeriod)
	binary.LittleEndian.PutUint64(ssz[8:], count)
	return EncodeRequest(ssz[:])
}

// EncodeBootstrapRequest is the 32-byte checkpoint root framed — the
// whole bootstrap request.
func EncodeBootstrapRequest(root [32]byte) []byte { return EncodeRequest(root[:]) }

// DecompressFramed decompresses a framed stream bounded by the declared
// uncompressed length: reads at most declared+1 bytes and rejects any
// mismatch, so a forged length cannot force an unbounded allocation
// (codec.rs:94-119).
// The declared length is peer-chosen (up to 35 bits through the varint
// guard) and is BOUNDED AT U64 WIDTH before any narrowing: on a 32-bit
// target int(declared) goes negative for 2^31..2^32 and would reach the
// make() below as a negative size — a remote panic from one response
// chunk (the lc package guards the same class, and codec.rs:178-181
// names android armv7 as the target in mind).
func DecompressFramed(input []byte, declared uint64) ([]byte, error) {
	if declared == 0 || declared > MaxUncompressedPayload {
		return nil, fmt.Errorf("%w: declared uncompressed length %d outside (0, %d]",
			ErrCodec, declared, MaxUncompressedPayload)
	}
	r := snappy.NewReader(bytes.NewReader(input))
	buf := make([]byte, int(declared)+1)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("%w: snappy decompress failed: %v", ErrCodec, err)
	}
	if n != int(declared) { // narrowing is safe: the bound above proved it
		return nil, fmt.Errorf("%w: snappy output %d bytes != declared %d", ErrCodec, n, declared)
	}
	return buf[:n], nil
}

// DecodeResult is one decoded response chunk.
type DecodeResult struct {
	ResultCode uint8
	// ForkDigest is the 4 context bytes when the protocol carries them,
	// nil otherwise.
	ForkDigest []byte
	Payload    []byte
}

// DecodeResponse decodes a single-chunk response
// (result || [digest] || varint || snappy). A non-zero result code is an
// error carrying the type name and the best-effort UTF-8 message —
// treated by the caller exactly like a transport failure (move to the
// next peer).
func DecodeResponse(raw []byte, hasContext bool) (DecodeResult, error) {
	if len(raw) == 0 {
		return DecodeResult{}, fmt.Errorf("%w: response too short: no result byte", ErrCodec)
	}
	res := DecodeResult{ResultCode: raw[0]}
	pos := 1
	if res.ResultCode != ResultSuccess {
		// Error chunks carry NO context bytes: result || varint(len) ||
		// snappy(msg). Reading them raw would surface "\x0eÿ\x06\x00\x00sNaPpY…"
		// where the server plainly said "Database error" — and telling
		// "answered ServerError: Database error" apart from "sent bytes
		// that do not decode" is the whole point of asking (codec.rs:380-407).
		msg := decodeErrorChunkMessage(raw, pos)
		var kind string
		switch res.ResultCode {
		case ResultInvalidRequest:
			kind = "InvalidRequest"
		case ResultServerError:
			kind = "ServerError"
		case ResultResourceUnavailable:
			kind = "ResourceUnavailable"
		default:
			kind = fmt.Sprintf("Unknown(%d)", res.ResultCode)
		}
		if msg != "" {
			return res, fmt.Errorf("%w: peer returned error: %s — %s", ErrCodec, kind, msg)
		}
		return res, fmt.Errorf("%w: peer returned error: %s", ErrCodec, kind)
	}
	if hasContext {
		if len(raw) < pos+4 {
			return res, fmt.Errorf("%w: response too short: missing fork digest", ErrCodec)
		}
		res.ForkDigest = raw[pos : pos+4]
		pos += 4
	}
	declared, next, err := ReadVarint(raw, pos)
	if err != nil {
		return res, err
	}
	pos = next
	if declared == 0 {
		return res, nil
	}
	if pos >= len(raw) {
		return res, fmt.Errorf("%w: response truncated: no compressed data after header", ErrCodec)
	}
	payload, err := DecompressFramed(raw[pos:], declared)
	if err != nil {
		return res, err
	}
	res.Payload = payload
	return res, nil
}

// ParseRequestSsz decodes an inbound request body: varint(len) ||
// snappy_frames → ssz bytes. Library-side on purpose (mirrors
// parse_request_ssz, codec.rs:156): this is the exact code the live
// responder runs, so the Java golden vectors pin it, not a test-local
// copy. The Rust twin rejects the bare 0x00 (codec.rs:730) — with the
// expected-size table below, an empty-body protocol is never parsed at
// all, so no accepted path depends on 0x00 leniency.
func ParseRequestSsz(raw []byte) ([]byte, error) {
	return ParseRequestSszExpecting(raw, 0)
}

// ParseRequestSszExpecting is ParseRequestSsz refusing a declared
// length that does not match what the protocol's request is defined to
// be, BEFORE decompressing (parse_request_ssz_expecting, codec.rs:169):
// without it a 1 KB frame declaring 10 MiB buys a 10 MiB allocation
// per request — free amplification against a public responder. The
// comparison happens at u64 width, before any narrowing. expected==0
// means "no pin".
func ParseRequestSszExpecting(raw []byte, expected uint64) ([]byte, error) {
	if len(raw) < 2 {
		return nil, ErrCodec
	}
	declared, snappyStart, err := ReadVarint(raw, 0)
	if err != nil || declared == 0 || snappyStart >= len(raw) {
		return nil, ErrCodec
	}
	if expected != 0 && declared != expected {
		return nil, ErrCodec
	}
	return DecompressFramed(raw[snappyStart:], declared)
}

// ExpectedRequestSize is the exact request-body size per served
// protocol (expected_request_size, protocols.rs:84-93 — the same table
// the Java registerBinding calls pin): 0 means the body is not parsed
// at all, either because the request has none (metadata) or the answer
// does not depend on it.
func ExpectedRequestSize(proto string) uint64 {
	switch proto {
	case StatusV2:
		return 92
	case StatusV1:
		return 84
	case Ping, Goodbye:
		return 8
	case Bootstrap:
		return 32
	case UpdatesByRange:
		return 16
	default: // metadata, finality_update, optimistic_update
		return 0
	}
}

// decodeErrorChunkMessage best-effort decodes an error chunk's message
// at raw[start:]: varint(len) || snappy(msg), falling back to raw UTF-8
// when the snappy frame is missing or corrupt. The eth2 spec caps error
// strings at 256 bytes, so the declared length is trusted only up to
// that ceiling (decode_error_chunk_message, codec.rs:390-407).
func decodeErrorChunkMessage(raw []byte, start int) string {
	if start >= len(raw) {
		return ""
	}
	declared, msgStart, err := ReadVarint(raw, start)
	if err != nil || msgStart >= len(raw) {
		return ""
	}
	bound := min(declared, 256) // u64 width; DecompressFramed re-bounds
	if bound > 0 {
		if msg, err := DecompressFramed(raw[msgStart:], bound); err == nil {
			return strings.TrimSpace(string(msg))
		}
	}
	// The [raw] fallback fires for corrupt framing AND for a declared
	// 0 with leftover bytes — Rust surfaces "ServerError — [raw] …"
	// there too, and "answered ServerError" vs "sent bytes that do not
	// decode" is the census-grade distinction this function exists for.
	return "[raw] " + strings.TrimSpace(string(raw[msgStart:]))
}

// EncodeErrorResponse builds an error response chunk: result ||
// varint(len) || snappy(msg), no context bytes (error chunks never
// carry them). Mirrors encode_error_response (codec.rs).
func EncodeErrorResponse(result uint8, msg string) []byte {
	return append([]byte{result}, EncodeRequest([]byte(msg))...)
}

// EncodeSuccessResponse builds a response chunk (the responder half —
// used by tests and any later serving path).
func EncodeSuccessResponse(ssz []byte, digest *[4]byte) []byte {
	out := []byte{ResultSuccess}
	if digest != nil {
		out = append(out, digest[:]...)
	}
	return append(out, EncodeRequest(ssz)...)
}

// skipSnappyFrames returns the offset just past the snappy-framed frames
// covering uncompressedLen uncompressed bytes (framing_format.txt types:
// 0x00 compressed, 0x01 uncompressed, 0xff stream id; anything else —
// e.g. the NEXT chunk's result byte — stops the scan). Ported from
// skip_snappy_frames (codec.rs), including the truncated-frame behaviour
// (consume to end) the multi-chunk salvage depends on.
func skipSnappyFrames(data []byte, start int, uncompressedLen uint64) int {
	pos := start
	var decompressed uint64
	for pos < len(data) {
		chunkType := data[pos]
		if chunkType != 0xFF && chunkType != 0x00 && chunkType != 0x01 {
			break // next response chunk's result code
		}
		if pos+4 > len(data) {
			break
		}
		frameLen := int(data[pos+1]) | int(data[pos+2])<<8 | int(data[pos+3])<<16
		if pos+4+frameLen > len(data) {
			return len(data) // truncated frame — consume remaining
		}
		if frameLen > 4 {
			switch chunkType {
			case 0x01:
				decompressed += uint64(frameLen - 4)
			case 0x00:
				if v, _, err := ReadVarint(data, pos+8); err == nil {
					decompressed += v
				} else {
					return pos // not a real snappy frame
				}
			}
		}
		pos += 4 + frameLen
		if uncompressedLen > 0 && decompressed >= uncompressedLen {
			break
		}
	}
	return pos
}

// ContextChunk is one multi-chunk item: its context digest (the fork
// digest of THAT object's epoch — a range response can span a fork, so
// the digest is per chunk) and its SSZ payload.
type ContextChunk struct {
	ForkDigest [4]byte
	Payload    []byte
}

// DecodeMultiChunk decodes an updates_by_range-style response: repeated
// `result || digest || varint || snappy` chunks, stopping at the first
// error chunk and keeping the whole chunks before it (the Java salvage
// behaviour). A truncated TAIL consistent with the reader's budget
// cutting the stream keeps prior chunks; corruption with data still
// ahead is an error (codec.rs:290-375).
func DecodeMultiChunk(raw []byte, expectedCount int) ([]ContextChunk, error) {
	var items []ContextChunk
	pos := 0
	for pos < len(raw) && len(items) < expectedCount {
		if raw[pos] != ResultSuccess {
			break // error chunk: stop, keep prior items (caller logs)
		}
		pos++
		if pos+4 > len(raw) {
			break
		}
		var digest [4]byte
		copy(digest[:], raw[pos:pos+4])
		pos += 4
		declared, next, err := ReadVarint(raw, pos)
		if err != nil {
			if len(items) > 0 && len(raw)-pos < 10 {
				break // varint itself was cut off — salvage
			}
			return nil, err
		}
		pos = next
		if declared == 0 {
			items = append(items, ContextChunk{ForkDigest: digest})
			continue
		}
		start := pos
		pos = skipSnappyFrames(raw, pos, declared)
		if pos <= start {
			break
		}
		payload, err := DecompressFramed(raw[start:pos], declared)
		if err != nil {
			if len(items) > 0 && len(raw)-pos < 4 {
				break // tail cut mid-snappy — salvage
			}
			return nil, err
		}
		if len(payload) == 0 {
			break
		}
		items = append(items, ContextChunk{ForkDigest: digest, Payload: payload})
	}
	return items, nil
}
