package rlpx

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func mustKey(t *testing.T, label string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.ToECDSA(crypto.Keccak256([]byte(label)))
	if err != nil {
		t.Fatalf("derive key %s: %v", label, err)
	}
	return k
}

func pub64(k *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSAPub(&k.PublicKey)[1:]
}

func TestECIESRoundTripWithAndWithoutAAD(t *testing.T) {
	recipient := mustKey(t, "ecies:recipient")
	eph := crypto.Keccak256([]byte("ecies:ephemeral"))
	iv := crypto.Keccak256([]byte("ecies:iv"))[:16]
	msg := []byte("Hello, World! This is a test message.")

	enc, err := eciesEncrypt(msg, pub64(recipient), eph, iv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 0x04 {
		t.Fatalf("want 0x04 marker, got 0x%02x", enc[0])
	}
	got, err := EciesDecrypt(enc, recipient, nil)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("no-AAD round trip: %v, %x", err, got)
	}

	aad := []byte{0x01, 0xb3}
	enc, err = eciesEncrypt(msg, pub64(recipient), eph, iv, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err = EciesDecrypt(enc, recipient, aad)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("AAD round trip: %v", err)
	}
	if _, err := EciesDecrypt(enc, recipient, []byte{0x02, 0x00}); err == nil {
		t.Fatal("wrong AAD must fail the MAC")
	}
}

func TestECIESRejectsTruncated(t *testing.T) {
	r := mustKey(t, "r")
	if _, err := EciesDecrypt(bytes.Repeat([]byte{0x04}, 50), r, nil); err == nil {
		t.Fatal("truncated message must fail")
	}
}

func TestConcatKDFOrdering(t *testing.T) {
	// SHA256(be32(1) ‖ Z) for Z = 0x01×32, pinned to a value computed with
	// an independent tool. The wrong order (SHA256(Z ‖ counter)) — the
	// classic BouncyCastle-KDF2 mixup docs/spec/02 §9.1 warns about — would
	// yield 4791e320…; asserting the digest pins which one we mean.
	z := bytes.Repeat([]byte{0x01}, 32)
	out := concatKDF(z, 32)
	const want = "f03fb92fb76fce8fd8b2d7e4d48c466f3ba15408db67b40992c22d0a74e73927"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("KDF digest = %s, want %s", got, want)
	}
}

func TestMsgIDCodec(t *testing.T) {
	cases := []struct {
		enc  []byte
		code uint64
		used int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x80}, 0, 1},
		{[]byte{0x42}, 0x42, 1},
		{[]byte{0x81, 0xff}, 0xff, 2},
		{minimalInt(0x10), 0x10, 1},
		{minimalInt(0x100), 0x100, 3}, // 0x82 ‖ 2-byte big-endian
	}
	for _, c := range cases {
		code, used, err := decodeMsgID(append(append([]byte{}, c.enc...), 0xaa, 0xbb))
		if err != nil || code != c.code || used != c.used {
			t.Errorf("decodeMsgID(%x) = (%x, %d, %v), want (%x, %d, nil)", c.enc, code, used, err, c.code, c.used)
		}
	}
	if _, _, err := decodeMsgID([]byte{0x84, 0x01}); err == nil {
		t.Error("truncated msg-id must fail")
	}
	if _, _, err := decodeMsgID([]byte{0xc0}); err == nil {
		t.Error("list-encoded msg-id must fail")
	}
}

// testPair builds two frame codecs that understand each other from fixed
// material, mirroring the Rust SessionSecrets::test_pair (responder swaps the
// nonce and auth/ack-wire roles).
func testPair(t *testing.T) (*FrameCodec, *FrameCodec) {
	t.Helper()
	aa := [32]byte{}
	am := [32]byte{}
	aN := [32]byte{}
	bN := [32]byte{}
	copy(aa[:], crypto.Keccak256([]byte("frame:aes")))
	copy(am[:], crypto.Keccak256([]byte("frame:mac")))
	copy(aN[:], crypto.Keccak256([]byte("frame:A-nonce")))
	copy(bN[:], crypto.Keccak256([]byte("frame:B-nonce")))
	initiator := &SessionSecrets{AESSecret: aa, MACSecret: am, EgressNonce: aN, IngressNonce: bN,
		AuthWire: []byte("AUTH-wire-bytes-opaque"), AckWire: []byte("ACK-wire-bytes-opaque")}
	responder := &SessionSecrets{AESSecret: aa, MACSecret: am, EgressNonce: bN, IngressNonce: aN,
		AuthWire: []byte("ACK-wire-bytes-opaque"), AckWire: []byte("AUTH-wire-bytes-opaque")}
	ic, err := NewFrameCodec(initiator)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewFrameCodec(responder)
	if err != nil {
		t.Fatal(err)
	}
	return ic, rc
}

func splitFrame(f []byte) (head, headMac, body, bodyMac []byte) {
	bodyEnd := len(f) - 16
	return f[:16], f[16:32], f[32:bodyEnd], f[bodyEnd:]
}

func decodeFrame(t *testing.T, c *FrameCodec, f []byte) *DecodedFrame {
	t.Helper()
	head, headMac, body, bodyMac := splitFrame(f)
	n, err := c.DecodeHeader(head, headMac)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	d, err := c.DecodeBody(body, bodyMac, n)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return d
}

func TestHelloFrameRoundTripUncompressed(t *testing.T) {
	a, b := testPair(t)
	f := a.EncodeFrame(0x00, []byte{0xc0})
	d := decodeFrame(t, b, f)
	if d.MessageCode != 0 || !bytes.Equal(d.Payload, []byte{0xc0}) {
		t.Fatalf("decoded (%d, %x)", d.MessageCode, d.Payload)
	}
}

func TestCompressedFramesShareOneKeystreamAndMACChain(t *testing.T) {
	a, b := testPair(t)
	p1 := make([]byte, 300)
	for i := range p1 {
		p1[i] = byte(i)
	}
	p2 := []byte("second")
	f1 := a.EncodeFrame(0x10, p1)
	f2 := a.EncodeFrame(0x11, p2)

	d := decodeFrame(t, b, f1)
	if d.MessageCode != 0x10 || !bytes.Equal(d.Payload, p1) {
		t.Fatal("frame 1 mismatch")
	}
	d = decodeFrame(t, b, f2)
	if d.MessageCode != 0x11 || !bytes.Equal(d.Payload, p2) {
		t.Fatal("frame 2 mismatch")
	}
}

func TestTamperedHeaderMACRejected(t *testing.T) {
	a, b := testPair(t)
	f := a.EncodeFrame(0x00, []byte{0xc0})
	f[20] ^= 0x01
	head, headMac, _, _ := splitFrame(f)
	if _, err := b.DecodeHeader(head, headMac); err == nil {
		t.Fatal("tampered header MAC must be rejected")
	}
}

func TestSnappyLengthBombFallsBackToRaw(t *testing.T) {
	// A snappy header claiming ~4 GiB decoded length from 6 bytes must not
	// allocate that up front (Rust pins the same guard against the
	// panic=abort process kill). We just check we fall back to raw bytes.
	bomb := []byte{0xff, 0xff, 0xff, 0xff, 0x0f, 0x00}
	if n, ok := snappyLen(bomb); !ok || n <= MaxFrameBodySize {
		t.Fatalf("expected a >cap declared length, got %d ok=%v", n, ok)
	}
	a, b := testPair(t)
	f := a.EncodeFrame(0x10, bomb) // encoder re-compresses it
	d := decodeFrame(t, b, f)
	// It round-trips correctly (real snappy), which is the other half of the
	// guard working: only DECLARED sizes over the cap take the raw path.
	if !bytes.Equal(d.Payload, bomb) {
		t.Fatalf("payload mismatch: %x", d.Payload)
	}
}

func TestHandshakeRoundTripMatchesBothSides(t *testing.T) {
	aStatic := mustKey(t, "hs:A-static")
	bStatic := mustKey(t, "hs:B-static")
	aEph := crypto.Keccak256([]byte("hs:A-eph"))
	var aNonce, bNonce [32]byte
	copy(aNonce[:], crypto.Keccak256([]byte("hs:A-nonce")))
	copy(bNonce[:], crypto.Keccak256([]byte("hs:B-nonce")))

	initiator, err := NewInitiator(aStatic, pub64(bStatic), aEph, aNonce)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := initiator.BuildAuth(crypto.Keccak256([]byte("hs:ecies-eph")), bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{0xab}, 120))
	if err != nil {
		t.Fatal(err)
	}

	ack, err := AckWire(pub64(aStatic), crypto.Keccak256([]byte("hs:ack-eph")), bytes.Repeat([]byte{9}, 16), bNonce[:])
	if err != nil {
		t.Fatal(err)
	}

	secrets, err := initiator.ProcessAck(ack)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.AESSecret == secrets.MACSecret || secrets.AESSecret == [32]byte{} {
		t.Fatal("aes/mac secrets must differ and be non-zero")
	}
	if secrets.EgressNonce != aNonce || secrets.IngressNonce != bNonce {
		t.Fatal("nonce roles mixed up")
	}
	if !bytes.Equal(secrets.AuthWire, auth) || !bytes.Equal(secrets.AckWire, ack) {
		t.Fatal("wire bytes must be the ones that went on the wire")
	}

	// The responder derives the SAME aes/mac secrets: ECDH is symmetric and
	// the nonce hash keeps the fixed initiator-order pairing. The ack's
	// ephemeral is hs:ack-eph (what AckWire was built with), not hs:B-eph.
	ephShared, err := EcdhX(mustKey(t, "hs:ack-eph"), mustEphPub(t, aEph))
	if err != nil {
		t.Fatal(err)
	}
	nonceHash := crypto.Keccak256(bNonce[:], aNonce[:]) // remote‖local in the initiator's fixed order
	shared := crypto.Keccak256(ephShared[:], nonceHash)
	aesS := crypto.Keccak256(ephShared[:], shared)
	macS := crypto.Keccak256(ephShared[:], aesS)
	if !bytes.Equal(aesS, secrets.AESSecret[:]) || !bytes.Equal(macS, secrets.MACSecret[:]) {
		t.Fatal("responder-side derivation diverged")
	}
}

// TestPaddedAckAccepted pins the regression from the first live mainnet
// smoke: peers append EIP-8 random padding as RAW BYTES after the ack's
// body list. A strict "no trailing bytes" decode rejected every real ack.
func TestPaddedAckAccepted(t *testing.T) {
	aStatic := mustKey(t, "pad:A-static")
	bStatic := mustKey(t, "pad:B-static")
	aEph := crypto.Keccak256([]byte("pad:A-eph"))
	var aNonce, bNonce [32]byte
	copy(aNonce[:], crypto.Keccak256([]byte("pad:A-nonce")))
	copy(bNonce[:], crypto.Keccak256([]byte("pad:B-nonce")))

	initiator, err := NewInitiator(aStatic, pub64(bStatic), aEph, aNonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.BuildAuth(crypto.Keccak256([]byte("pad:ecies-eph")), bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{0xab}, 120)); err != nil {
		t.Fatal(err)
	}
	ack, err := AckWirePadded(pub64(aStatic), crypto.Keccak256([]byte("pad:ack-eph")),
		bytes.Repeat([]byte{9}, 16), bNonce[:], bytes.Repeat([]byte{0x5a}, 173))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := initiator.ProcessAck(ack)
	if err != nil {
		t.Fatalf("padded ack rejected: %v", err)
	}
	if secrets.AESSecret == [32]byte{} {
		t.Fatal("empty aes secret")
	}
}

func mustEphPub(t *testing.T, secret []byte) []byte {
	t.Helper()
	k, err := crypto.ToECDSA(secret)
	if err != nil {
		t.Fatal(err)
	}
	return pub64(k)
}
