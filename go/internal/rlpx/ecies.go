// Package rlpx implements the RLPx transport: the ECIES cipher used by the
// EIP-8 auth/ack handshake, the handshake itself with its session-secret
// derivation, and the framed channel (AES-256-CTR + streaming keccak MAC) that
// carries p2p/eth messages. It is the twin of the Rust
// myotis-wire/src/rlpx/{ecies,handshake,frame}.rs and must stay
// byte-compatible with it — the conformance test replays the shared corpus in
// rust/testdata/el/rlpx (docs/spec/02 §5, §9).
package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// EcdhX returns the X coordinate of priv·pub — the ECDH shared secret both
// ECIES and the handshake key schedule use. The peer point is validated
// (on-curve, not infinity) before use, like the Rust ecdh_x. Exported for
// the responder half the transport test scripts (the engine itself only ever
// runs the initiator).
func EcdhX(priv *ecdsa.PrivateKey, pub64 []byte) ([32]byte, error) {
	var out [32]byte
	if len(pub64) != 64 {
		return out, fmt.Errorf("ecies: pubkey must be 64 bytes, got %d", len(pub64))
	}
	x := new(big.Int).SetBytes(pub64[:32])
	y := new(big.Int).SetBytes(pub64[32:])
	if !crypto.S256().IsOnCurve(x, y) {
		return out, errors.New("ecies: peer point not on secp256k1")
	}
	bx, _ := crypto.S256().ScalarMult(x, y, priv.D.Bytes())
	// Refuse a nil result by name (PR #832 review hardening): go-ethereum
	// v1.16.9's ScalarMult returns nil for an out-of-range point — the
	// IsOnCurve check above rejects those since that same version added the
	// range check, so today's pairing is safe, but an unchecked nil landing
	// on bx.Sign() would panic on a peer packet inside the host process. Do
	// not rely on the pairing.
	if bx == nil {
		return out, errors.New("ecies: ECDH scalar multiplication failed")
	}
	if bx.Sign() == 0 {
		return out, errors.New("ecies: ECDH produced the point at infinity")
	}
	b := bx.Bytes()
	if len(b) > 32 {
		return out, errors.New("ecies: ECDH x coordinate overflows 32 bytes")
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// concatKDF is the NIST SP 800-56 concatenation KDF with SHA-256:
// SHA256(counter_be32 || Z), counter from 1 — NOT SHA256(Z || counter),
// which is the classic bug this ordering pins (docs/spec/02 §9.1).
func concatKDF(z []byte, outLen int) []byte {
	out := make([]byte, 0, 32)
	for counter := uint32(1); len(out) < outLen; counter++ {
		h := sha256.New()
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		h.Write(z)
		out = h.Sum(out)
	}
	return out[:outLen]
}

// eciesEncrypt seals plaintext to recipientPub64 with a caller-supplied
// ephemeral secret and IV (so the pure path is deterministic and testable;
// the dialer supplies OS entropy). aad is folded into the MAC — the EIP-8
// size prefix, always included even when empty.
// Output layout: 0x04 ‖ ephPub(64) ‖ IV(16) ‖ ciphertext ‖ MAC(32).
func eciesEncrypt(plaintext, recipientPub64 []byte, ephSecret, iv, aad []byte) ([]byte, error) {
	eph, err := crypto.ToECDSA(ephSecret)
	if err != nil {
		return nil, fmt.Errorf("ecies: bad ephemeral secret: %w", err)
	}
	shared, err := EcdhX(eph, recipientPub64)
	if err != nil {
		return nil, err
	}
	encKey, macKey := deriveECIESKeys(shared[:])

	ct := make([]byte, len(plaintext))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(ct, plaintext)

	mac := eciesMAC(macKey, iv, ct, aad)

	pub := crypto.FromECDSAPub(&eph.PublicKey) // 0x04‖X‖Y
	out := make([]byte, 0, 1+64+len(iv)+len(ct)+32)
	out = append(out, pub[0]) // 0x04 marker
	out = append(out, pub[1:]...)
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, mac...)
	return out, nil
}

// EciesDecrypt opens an eciesEncrypt message with the recipient's static key.
// aad must match what the sender used (the EIP-8 size prefix).
func EciesDecrypt(encrypted []byte, recipient *ecdsa.PrivateKey, aad []byte) ([]byte, error) {
	if len(encrypted) < 1+64+16+32 {
		return nil, errors.New("ecies: message too short")
	}
	if encrypted[0] != 0x04 {
		return nil, errors.New("ecies: expected uncompressed point marker 0x04")
	}
	ephPub := encrypted[1:65]
	iv := encrypted[65:81]
	ct := encrypted[81 : len(encrypted)-32]
	mac := encrypted[len(encrypted)-32:]

	shared, err := EcdhX(recipient, ephPub)
	if err != nil {
		return nil, err
	}
	encKey, macKey := deriveECIESKeys(shared[:])
	if !hmac.Equal(mac, eciesMAC(macKey, iv, ct, aad)) {
		return nil, errors.New("ecies: MAC verification failed")
	}

	plain := make([]byte, len(ct))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(plain, ct)
	return plain, nil
}

// deriveECIESKeys expands the ECDH secret to (AES-128 key, raw mac key) via
// the concat-KDF; the raw mac key is hashed again before use as the HMAC key.
func deriveECIESKeys(shared []byte) (encKey, macKey []byte) {
	material := concatKDF(shared, 32)
	return material[:16], material[16:32]
}

// eciesMAC = HMAC-SHA256(SHA256(macKey), IV ‖ ciphertext ‖ aad).
func eciesMAC(macKey, iv, ciphertext, aad []byte) []byte {
	key := sha256.Sum256(macKey)
	m := hmac.New(sha256.New, key[:])
	m.Write(iv)
	m.Write(ciphertext)
	m.Write(aad)
	return m.Sum(nil)
}
