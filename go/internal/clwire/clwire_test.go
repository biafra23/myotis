package clwire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestJavaGoldenRequestVectors replays the cross-language vectors the
// Rust codec pins (codec.rs java_golden_request_vectors — captured from
// the Java ReqRespCodec). DECODE-equality is the interop-critical half:
// the Java side's compressor and Go's differ on which frames they emit
// for compressible input, so our own encoder is pinned to round-trip,
// not to byte-equality (the Rust twin makes exactly this split).
func TestJavaGoldenRequestVectors(t *testing.T) {
	// The vectors run through ParseRequestSszExpecting — the PRODUCTION
	// responder decoder (host.go ServeInstall runs the same function),
	// exactly as the Rust golden runs parse_request_ssz. A test-local
	// copy would let the pinned decoder and the live one drift.
	root := bytes.Repeat([]byte{0x11}, 32)
	got, err := ParseRequestSszExpecting(mustHex(t, "20ff060000734e61507059000a00000eb49f4d2000117a0100"), 32)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("32x0x11 root frame: %x, %v", got, err)
	}

	rangeSSZ := append(le64(1777), le64(16)...)
	got, err = ParseRequestSszExpecting(mustHex(t, "10ff060000734e6150705901140000de50a893f1060000000000001000000000000000"), 16)
	if err != nil || !bytes.Equal(got, rangeSSZ) {
		t.Fatalf("updates_by_range(1777,16) frame: %x, %v", got, err)
	}

	statusSSZ := make([]byte, 92)
	for i := range statusSSZ {
		statusSSZ[i] = byte(i)
	}
	javaStatus := append(mustHex(t, "5cff060000734e6150705901600000cf4ded1a"), statusSSZ...)
	got, err = ParseRequestSszExpecting(javaStatus, 92)
	if err != nil || !bytes.Equal(got, statusSSZ) {
		t.Fatalf("92-byte status frame: %x, %v", got, err)
	}

	// Our own encoder: round-trips through the Java-decodable framing.
	for _, payload := range [][]byte{root, rangeSSZ, statusSSZ, bytes.Repeat([]byte{0xAB}, 25000)} {
		back, err := ParseRequestSszExpecting(EncodeRequest(payload), uint64(len(payload)))
		if err != nil || !bytes.Equal(back, payload) {
			t.Fatalf("round-trip %d bytes: %v", len(payload), err)
		}
	}
	// Empty request is the single byte 0x00, like the Java twin — and
	// the decoder REJECTS it (codec.rs:730 pins the same): a protocol
	// with no request body is answered without parsing at all (see
	// ExpectedRequestSize), so no accepted path relies on 0x00 leniency.
	if enc := EncodeRequest(nil); len(enc) != 1 || enc[0] != 0x00 {
		t.Fatalf("empty request = %x, want 00", enc)
	}
	if _, err := ParseRequestSsz(nil); err == nil {
		t.Fatal("empty raw request must be refused")
	}
	if _, err := ParseRequestSsz([]byte{0x00}); err == nil {
		t.Fatal("bare 0x00 must be refused by the decoder, like the Rust twin")
	}
	// A declared length that does not match the protocol's request is
	// refused BEFORE decompression (the anti-amplification pre-check).
	if _, err := ParseRequestSszExpecting(EncodeRequest(root), 16); err == nil {
		t.Fatal("wrong declared length accepted despite expected-size pin")
	}
}

// TestExpectedRequestSizeTable pins the per-protocol request sizes the
// responder pre-checks (expected_request_size, protocols.rs:84-93 —
// the same table the Java registerBinding calls pin).
func TestExpectedRequestSizeTable(t *testing.T) {
	want := map[string]uint64{
		StatusV2: 92, StatusV1: 84, Ping: 8, Goodbye: 8,
		Bootstrap: 32, UpdatesByRange: 16,
		MetadataV2: 0, MetadataV3: 0, FinalityUpdate: 0, OptimisticUpdate: 0,
	}
	for proto, w := range want {
		if got := ExpectedRequestSize(proto); got != w {
			t.Fatalf("ExpectedRequestSize(%s) = %d, want %d", proto, got, w)
		}
	}
}

// TestErrorResponseRoundTrip pins that a response we produce as a
// server decodes, on the client side, as the same error class and
// message a real peer's chunk surfaces (the census distinction the
// decoder exists for).
func TestErrorResponseRoundTrip(t *testing.T) {
	wire := EncodeErrorResponse(ResultInvalidRequest, "InvalidRequest: unparseable body")
	_, err := DecodeResponse(wire, false)
	if err == nil || !strings.Contains(err.Error(), "InvalidRequest") ||
		!strings.Contains(err.Error(), "unparseable body") {
		t.Fatalf("error response round-trip: %v", err)
	}
}

func le64(v uint64) []byte {
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
	return b[:]
}

// TestForkDigestGolden pins the Fulu (pre-fold) and BPO2-folded mainnet
// digests the Rust twin asserts against the Java's computed values
// (status.rs mainnet_fork_digest_matches_java): version 0x06000000,
// GVR 4b36…, BPO2 epoch 419072 / 21 blobs.
func TestForkDigestGolden(t *testing.T) {
	c := chain.ConsensusMainnet()
	gvr := c.GenesisValidatorsRoot
	var fulu [4]byte
	copy(fulu[:], []byte{0x06, 0, 0, 0})
	if got := ForkDigest(fulu, gvr); got != [4]byte{0x82, 0xFA, 0xE5, 0x41} {
		t.Fatalf("base Fulu digest = %x, want 82fae541", got)
	}
	if got := ForkDigestBPO(fulu, gvr, 419072, 21); got != [4]byte{0x8C, 0x9F, 0x62, 0xFE} {
		t.Fatalf("BPO-folded digest = %x, want 8c9f62fe", got)
	}
	// epoch 0 → the base formula.
	if got := ForkDigestBPO(fulu, gvr, 0, 0); got != ForkDigest(fulu, gvr) {
		t.Fatalf("epoch-0 fold changed the digest: %x", got)
	}
	// At today's mainnet wall clock the BPO fold is live (BPO2 passed
	// 2026-09), so CurrentForkDigest must be the folded one.
	// 2026-11-11: epoch ≈ 498k > 419072.
	if got := CurrentForkDigest(c, 1794355200); got != [4]byte{0x8C, 0x9F, 0x62, 0xFE} {
		t.Fatalf("CurrentForkDigest post-BPO2 = %x, want 8c9f62fe", got)
	}
}

func TestKnownForkDigestsCoversEveryPinnableAnswer(t *testing.T) {
	c := chain.ConsensusMainnet()
	known := KnownForkDigests(c)
	// The current-wall-clock digest must be in the set — otherwise the
	// chunk gate would refuse the network we are actually on.
	if !known[CurrentForkDigest(c, 1794355200)] {
		t.Fatal("current digest missing from KnownForkDigests")
	}
	// Every pinned fork's plain digest too (a response about a
	// pre-BPO period carries the unfolded form).
	for _, f := range c.Forks {
		if !known[ForkDigest(f.Version, c.GenesisValidatorsRoot)] {
			t.Fatalf("pinned fork %x plain digest missing", f.Version)
		}
	}
	// And a digest from a fork NO pinned schedule produces is refused —
	// the misdecode this gate exists to prevent.
	bogus := [4]byte{0xde, 0xad, 0xbe, 0xef}
	if known[bogus] {
		t.Fatal("bogus digest accepted")
	}
}

func TestStatusRoundTripBothVersions(t *testing.T) {
	s := StatusMessage{
		ForkDigest:            [4]byte{0x8C, 0x9F, 0x62, 0xFE},
		FinalizedRoot:         [32]byte{7},
		FinalizedEpoch:        455_000,
		HeadRoot:              [32]byte{9},
		HeadSlot:              14_560_000,
		EarliestAvailableSlot: 42,
	}
	v2 := s.Encode()
	if len(v2) != StatusSizeV2 {
		t.Fatalf("v2 len %d", len(v2))
	}
	back, err := DecodeStatus(v2)
	if err != nil || back != s {
		t.Fatalf("v2 round trip: %v %+v", err, back)
	}
	v1 := s.EncodeV1()
	if len(v1) != StatusSizeV1 {
		t.Fatalf("v1 len %d", len(v1))
	}
	back, err = DecodeStatusV1(v1)
	if err != nil || back.EarliestAvailableSlot != 0 || back.HeadSlot != s.HeadSlot {
		t.Fatalf("v1 round trip: %v %+v", err, back)
	}
}

// TestResponseChunks pins the result/context/varint framing against the
// Rust codec's round-trip tests, including the real-server ServerError
// chunk a Lighthouse node answered on Sepolia (codec.rs
// leading_error_reads_a_real_server_error).
func TestResponseChunks(t *testing.T) {
	digest := [4]byte{1, 2, 3, 4}
	ssz := bytes.Repeat([]byte{0xAB}, 100)
	res, err := DecodeResponse(EncodeSuccessResponse(ssz, &digest), true)
	if err != nil || !bytes.Equal(res.Payload, ssz) || !bytes.Equal(res.ForkDigest, digest[:]) {
		t.Fatalf("success with context: %v", err)
	}
	res, err = DecodeResponse(EncodeSuccessResponse(ssz, nil), false)
	if err != nil || !bytes.Equal(res.Payload, ssz) || res.ForkDigest != nil {
		t.Fatalf("success without context: %v", err)
	}

	// The byte-for-byte Lighthouse ServerError chunk from the Rust test.
	// The MESSAGE must surface decoded ("…ServerError — Database error"),
	// not the raw varint+snappy bytes — "answered ServerError: Database
	// error" vs "sent bytes that do not decode" is the distinction a
	// census depends on.
	wire := mustHex(t, "020eff060000734e6150705901120000d0fe5d49")
	wire = append(wire, []byte("Database error")...)
	_, err = DecodeResponse(wire, true)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("ServerError")) {
		t.Fatalf("real server error not surfaced: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("Database error")) {
		t.Fatalf("error message not decompressed, surfaced raw: %v", err)
	}

	// Corrupt error framing still surfaces, marked raw, never lost.
	_, err = DecodeResponse(append([]byte{0x02, 0x05}, []byte("plain")...), false)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("[raw] plain")) {
		t.Fatalf("raw fallback for corrupt error frame: %v", err)
	}

	// Multi-chunk: chunks of distinct sizes back to back, per-chunk
	// digests kept (a response can span a fork).
	w1 := EncodeSuccessResponse([]byte{0x01}, &[4]byte{0x74, 0xD0, 0x14, 0x59})
	w2 := EncodeSuccessResponse([]byte{0x02, 0x03}, &[4]byte{0x66, 0x9E, 0x6C, 0x11})
	items, err := DecodeMultiChunk(append(append([]byte{}, w1...), w2...), 8)
	if err != nil || len(items) != 2 {
		t.Fatalf("multi-chunk decode: %v", err)
	}
	if items[0].ForkDigest != [4]byte{0x74, 0xD0, 0x14, 0x59} || items[0].Payload[0] != 0x01 {
		t.Fatalf("chunk 0: %+v", items[0])
	}
	if items[1].ForkDigest != [4]byte{0x66, 0x9E, 0x6C, 0x11} || len(items[1].Payload) != 2 {
		t.Fatalf("chunk 1: %+v", items[1])
	}

	// An error chunk stops the scan and keeps the whole chunks before it.
	items, err = DecodeMultiChunk(append(append([]byte{}, w1...), 0x03), 8)
	if err != nil || len(items) != 1 {
		t.Fatalf("error-chunk salvage: %v, %d items", err, len(items))
	}
}

// TestVarintGuard pins the 5-byte overflow guard ported from the Rust
// twin (shift >= 35 refuses before an attacker's 10-byte varint shifts
// past the i32 world the wire lives in).
func TestVarintGuard(t *testing.T) {
	if _, _, err := ReadVarint([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 0); err == nil {
		t.Fatal("6-byte varint accepted")
	}
	v, n, err := ReadVarint([]byte{0xFF, 0x7F}, 0)
	if err != nil || v != 16383 || n != 2 {
		t.Fatalf("2-byte varint: %d %d %v", v, n, err)
	}
}
