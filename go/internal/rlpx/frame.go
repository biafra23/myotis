package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"

	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"
)

// Frame geometry, twin of myotis-wire/src/rlpx/frame.rs:
//
//	header(16) ‖ header-mac(16) ‖ body(padded to 16) ‖ body-mac(16)
//
// The header is size(3 BE) ‖ rlp([0,0]) = c2 80 80 ‖ zeros, encrypted. The
// c28080 matters: Nethermind's FrameHeaderReader throws on an empty list (0xc0)
// and kills the session on our first frame (#291, fatal on gnosis).
//
// Two AES-256-CTR ciphers keyed with aesSecret (egress/ingress), zero IV and
// ONE CONTINUOUS keystream per direction; the MAC is a streaming Keccak-256
// chain per direction fed by a separate AES-256-ECB cipher keyed macSecret.
// Payloads are Snappy-compressed except Hello (code 0x00), with a raw
// fallback on decode (some peers send Disconnect/Ping/Pong uncompressed).
const (
	// MaxFrameBodySize is the 10 MiB frame-body cap (Java/Rust
	// MAX_FRAME_BODY_SIZE).
	MaxFrameBodySize = 10 * 1024 * 1024
	// MaxControlMsgSize bounds messages decoded into a tree (Hello,
	// Disconnect, Status, …): geth refuses a first handshake message over
	// 2 KiB; an owned decode costs ~50 B/byte, so a 10 MiB frame could cost
	// ~0.5 GB (#454). Keep the cap at 16 KiB — real control messages are a
	// few hundred bytes.
	MaxControlMsgSize = 16 * 1024
)

// DecodedFrame is one decrypted message: the p2p/eth message code and its
// (decompressed) payload.
type DecodedFrame struct {
	MessageCode uint64
	Payload     []byte
}

// FrameCodec is the stateful EIP-8 codec. NOT safe for concurrent use — the
// ciphers and MAC chains are position-dependent, so all sends and receives
// on one channel must be serialized (the transport enforces this).
type FrameCodec struct {
	enc *frameEncoder
	dec *frameDecoder
}

type frameEncoder struct {
	encrypt   cipher.Stream
	egressMAC *keccakMac
}

type frameDecoder struct {
	decrypt    cipher.Stream
	ingressMAC *keccakMac
}

// NewFrameCodec builds the initiator-side codec. A responder passes secrets
// with the nonce and auth/ack-wire roles swapped (see test pair helpers).
func NewFrameCodec(s *SessionSecrets) (*FrameCodec, error) {
	egressSeed := xor32(s.MACSecret, s.IngressNonce)
	ingressSeed := xor32(s.MACSecret, s.EgressNonce)
	enc, err := newEncoder(&egressSeed, s)
	if err != nil {
		return nil, err
	}
	dec, err := newDecoder(&ingressSeed, s)
	if err != nil {
		return nil, err
	}
	return &FrameCodec{enc: enc, dec: dec}, nil
}

func newEncoder(seed *[32]byte, s *SessionSecrets) (*frameEncoder, error) {
	block, err := aes.NewCipher(s.AESSecret[:])
	if err != nil {
		return nil, err
	}
	m, err := newKeccakMac(seed[:], s.MACSecret[:], s.AuthWire)
	if err != nil {
		return nil, err
	}
	return &frameEncoder{encrypt: cipher.NewCTR(block, make([]byte, 16)), egressMAC: m}, nil
}

func newDecoder(seed *[32]byte, s *SessionSecrets) (*frameDecoder, error) {
	block, err := aes.NewCipher(s.AESSecret[:])
	if err != nil {
		return nil, err
	}
	m, err := newKeccakMac(seed[:], s.MACSecret[:], s.AckWire)
	if err != nil {
		return nil, err
	}
	return &frameDecoder{decrypt: cipher.NewCTR(block, make([]byte, 16)), ingressMAC: m}, nil
}

func xor32(a, b [32]byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// EncodeFrame wraps one message (code + payload) into a full wire frame.
func (c *FrameCodec) EncodeFrame(messageCode uint64, body []byte) []byte {
	return c.enc.encodeFrame(messageCode, body)
}

// DecodeHeader verifies and decrypts a 16-byte encrypted header, returning
// the frame's unpadded body length. encHeader must be exactly 16 bytes.
func (c *FrameCodec) DecodeHeader(encHeader, headerMAC []byte) (int, error) {
	return c.dec.decodeHeader(encHeader, headerMAC)
}

// DecodeBody verifies and decrypts a padded frame body. bodyLen is the
// unpadded length returned by DecodeHeader.
func (c *FrameCodec) DecodeBody(encBody, bodyMAC []byte, bodyLen int) (*DecodedFrame, error) {
	return c.dec.decodeBody(encBody, bodyMAC, bodyLen)
}

func (e *frameEncoder) encodeFrame(messageCode uint64, body []byte) []byte {
	var payload []byte
	if messageCode == 0 {
		payload = body // Hello travels uncompressed
	} else {
		payload = snappy.Encode(nil, body)
	}

	msgID := minimalInt(messageCode)
	coded := make([]byte, 0, len(msgID)+len(payload)+16)
	coded = append(coded, msgID...)
	coded = append(coded, payload...)
	bodyLen := len(coded)
	if pad := bodyLen % 16; pad != 0 {
		coded = append(coded, make([]byte, 16-pad)...)
	}

	header := make([]byte, 16)
	header[0] = byte(bodyLen >> 16)
	header[1] = byte(bodyLen >> 8)
	header[2] = byte(bodyLen)
	header[3] = 0xc2
	header[4] = 0x80
	header[5] = 0x80
	e.encrypt.XORKeyStream(header, header)
	headerMAC := e.egressMAC.updateHeader(header)
	e.encrypt.XORKeyStream(coded, coded)
	bodyMAC := e.egressMAC.updateBody(coded)

	frame := make([]byte, 0, 32+len(coded)+16)
	frame = append(frame, header...)
	frame = append(frame, headerMAC...)
	frame = append(frame, coded...)
	frame = append(frame, bodyMAC...)
	return frame
}

func (d *frameDecoder) decodeHeader(encHeader, headerMAC []byte) (int, error) {
	if len(encHeader) != 16 || len(headerMAC) != 16 {
		return 0, errors.New("rlpx: bad header sizes")
	}
	expected := d.ingressMAC.updateHeader(encHeader)
	if subtle.ConstantTimeCompare(headerMAC, expected) != 1 {
		return 0, errors.New("rlpx: header MAC mismatch")
	}
	header := make([]byte, 16)
	copy(header, encHeader)
	d.decrypt.XORKeyStream(header, header)
	bodyLen := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if bodyLen > MaxFrameBodySize {
		return 0, fmt.Errorf("rlpx: frame body size %d exceeds maximum", bodyLen)
	}
	return bodyLen, nil
}

func (d *frameDecoder) decodeBody(encBody, bodyMAC []byte, bodyLen int) (*DecodedFrame, error) {
	if len(bodyMAC) != 16 || len(encBody)%16 != 0 || bodyLen > len(encBody) {
		return nil, errors.New("rlpx: bad body framing")
	}
	expected := d.ingressMAC.updateBody(encBody)
	if subtle.ConstantTimeCompare(bodyMAC, expected) != 1 {
		return nil, errors.New("rlpx: body MAC mismatch")
	}
	body := make([]byte, len(encBody))
	copy(body, encBody)
	d.decrypt.XORKeyStream(body, body)

	code, offset, err := decodeMsgID(body)
	if err != nil {
		return nil, err
	}
	if offset > bodyLen {
		return nil, errors.New("rlpx: msg-id overruns body")
	}
	raw := body[offset:bodyLen]

	// Snappy-decompress except Hello, falling back to raw (some peers send
	// uncompressed control messages). Bound the DECLARED length first: the
	// snappy header's varint can claim ~4 GiB from 6 bytes and snappy.Decode
	// allocates it up front — a hostile frame must not become an allocation
	// storm (myotis-net frame.rs pins the same guard).
	payload := raw
	if code != 0 && len(raw) > 0 {
		if n, ok := snappyLen(raw); ok && n <= MaxFrameBodySize {
			if dec, err := snappy.Decode(make([]byte, n), raw); err == nil {
				payload = dec
			}
		}
	}
	return &DecodedFrame{MessageCode: code, Payload: payload}, nil
}

// snappyLen reads the varint decoded-length from a snappy block header.
func snappyLen(b []byte) (int, bool) {
	v, shift := 0, 0
	for i := 0; i < 5; i++ {
		if i >= len(b) {
			return 0, false
		}
		c := b[i]
		v |= int(c&0x7f) << shift
		if c < 0x80 {
			if v < 0 {
				return 0, false
			}
			return v, true
		}
		shift += 7
	}
	return 0, false
}

// minimalInt is the canonical RLP encoding of a message id (what frames
// carry ahead of the payload).
func minimalInt(v uint64) []byte {
	switch {
	case v == 0:
		return []byte{0x80}
	case v < 0x80:
		return []byte{byte(v)}
	default:
		var be []byte
		for x := v; x > 0; x >>= 8 {
			be = append([]byte{byte(x)}, be...)
		}
		return append([]byte{byte(0x80 + len(be))}, be...)
	}
}

// decodeMsgID reads the RLP message id at the front of a decrypted body,
// returning (code, bytes-consumed).
func decodeMsgID(body []byte) (uint64, int, error) {
	if len(body) == 0 {
		return 0, 0, errors.New("rlpx: empty body")
	}
	first := body[0]
	switch {
	case first <= 0x7f:
		return uint64(first), 1, nil
	case first == 0x80:
		return 0, 1, nil // canonical RLP zero
	case first <= 0x88:
		n := int(first - 0x80)
		if 1+n > len(body) {
			return 0, 0, errors.New("rlpx: truncated msg-id")
		}
		var code uint64
		for _, b := range body[1 : 1+n] {
			code = code<<8 | uint64(b)
		}
		return code, 1 + n, nil
	default:
		return 0, 0, errors.New("rlpx: unsupported msg-id encoding")
	}
}

// keccakMac is the streaming Keccak-256 MAC chain (go-eth compatible). The
// AES here is the SEPARATE AES-256-ECB cipher keyed macSecret; Go's
// hash.Hash.Sum reads the digest without disturbing the chain, standing in
// for the Rust side's cloneable Keccak256.
type keccakMac struct {
	h        hash.Hash
	ecbBlock cipher.Block // AES-256-ECB, keyed macSecret
}

func newKeccakMac(seed, macSecret, handshakeWire []byte) (*keccakMac, error) {
	h := sha3.NewLegacyKeccak256()
	h.Write(seed)
	h.Write(handshakeWire)
	block, err := aes.NewCipher(macSecret)
	if err != nil {
		return nil, err
	}
	return &keccakMac{h: h, ecbBlock: block}, nil
}

func (m *keccakMac) updateHeader(encHeader []byte) []byte {
	return m.updateMAC(encHeader)
}

func (m *keccakMac) updateBody(encBody []byte) []byte {
	m.h.Write(encBody)
	seed := m.digest16()
	return m.updateMAC(seed)
}

// updateMAC: aesbuf = AES256-ECB(digest[:16]) XOR seed[:16];
// keccak.update(aesbuf); return keccak.digest[:16].
func (m *keccakMac) updateMAC(seed16 []byte) []byte {
	digest := m.digest16()
	block := make([]byte, 16)
	m.ecbBlock.Encrypt(block, digest)
	for i := 0; i < 16; i++ {
		block[i] ^= seed16[i]
	}
	m.h.Write(block)
	return m.digest16()
}

func (m *keccakMac) digest16() []byte {
	full := m.h.Sum(nil)
	out := make([]byte, 16)
	copy(out, full[:16])
	return out
}
