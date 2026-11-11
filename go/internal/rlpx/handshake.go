package rlpx

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/biafra23/myotis/go/internal/rlpcode"
	"github.com/ethereum/go-ethereum/crypto"
)

const rlpxVersion = 4

// SessionSecrets is the negotiated channel state: the two symmetric secrets
// plus the nonces and FULL wire bytes (size prefix included) that seed the
// frame MAC chains. Field roles follow the Rust SessionSecrets
// (myotis-wire/src/rlpx/handshake.rs): EgressNonce is ours, IngressNonce the
// peer's; the initiator's AuthWire seeds the egress MAC, AckWire the ingress
// one — a responder swaps both.
type SessionSecrets struct {
	AESSecret    [32]byte
	MACSecret    [32]byte
	EgressNonce  [32]byte
	IngressNonce [32]byte
	AuthWire     []byte
	AckWire      []byte
}

// Initiator drives the EIP-8 auth/ack side of an outbound RLPx connection.
// Like both reference engines, the Go engine is dialer-only, so there is no
// responder half here (the transport test scripts one).
type Initiator struct {
	localKey    *ecdsa.PrivateKey
	remotePub64 []byte
	// ephemeral is the handshake signing key, distinct from the ECIES
	// ephemeral inside the auth message.
	ephemeral  *ecdsa.PrivateKey
	localNonce [32]byte
	authWire   []byte
}

// NewInitiator prepares a handshake against remotePub64 (the peer's 64-byte
// static public key, no 0x04 prefix). ephemeralSecret and localNonce are
// parameters (not drawn internally) so tests can pin fixed material.
func NewInitiator(localKey *ecdsa.PrivateKey, remotePub64 []byte, ephemeralSecret []byte, localNonce [32]byte) (*Initiator, error) {
	if len(remotePub64) != 64 {
		return nil, fmt.Errorf("rlpx: remote pubkey must be 64 bytes, got %d", len(remotePub64))
	}
	eph, err := crypto.ToECDSA(ephemeralSecret)
	if err != nil {
		return nil, fmt.Errorf("rlpx: bad ephemeral secret: %w", err)
	}
	return &Initiator{
		localKey:    localKey,
		remotePub64: remotePub64,
		ephemeral:   eph,
		localNonce:  localNonce,
	}, nil
}

// BuildAuth produces the EIP-8 auth wire: size(2 BE) ‖ ECIES(authBody, aad=size).
// The body is [sig(65), pubkey(64), nonce(32), version(4), padding] — the
// random padding is a TRAILING list element (go-eth `rlp:"tail"`). The sig
// signs the token (staticShared XOR localNonce) DIRECTLY with the handshake
// ephemeral key, no re-hash (docs/spec/02 §9.3).
//
// eciesEphemeralSecret/eciesIV parameterize the ECIES layer; padding is
// 100-300 random bytes live (geth's dialer range).
func (in *Initiator) BuildAuth(eciesEphemeralSecret, eciesIV, padding []byte) ([]byte, error) {
	staticShared, err := EcdhX(in.localKey, in.remotePub64)
	if err != nil {
		return nil, fmt.Errorf("rlpx: auth ecdh: %w", err)
	}
	var token [32]byte
	for i := range token {
		token[i] = staticShared[i] ^ in.localNonce[i]
	}
	// crypto.Sign returns 65 bytes R‖S‖V — the recid-bearing form EIP-8 wants,
	// and the form Ecrecover(token, sig) accepts on the peer side.
	sig, err := crypto.Sign(token[:], in.ephemeral)
	if err != nil {
		return nil, fmt.Errorf("rlpx: sign token: %w", err)
	}
	pub64 := crypto.FromECDSAPub(&in.localKey.PublicKey)[1:]

	body := rlpcode.List(
		rlpcode.Bytes(sig),
		rlpcode.Bytes(pub64),
		rlpcode.Bytes(in.localNonce[:]),
		rlpcode.Uint(rlpxVersion),
		rlpcode.Bytes(padding),
	)

	// enc-auth-body = ephPub(65) ‖ IV(16) ‖ plaintext ‖ MAC(32); the 2-byte
	// size prefix counts everything after it and is the ECIES AAD.
	encSize := len(body) + 65 + 16 + 32
	if encSize > 0xffff {
		return nil, fmt.Errorf("rlpx: auth too large (%d)", encSize)
	}
	sizePrefix := []byte{byte(encSize >> 8), byte(encSize)}
	ct, err := eciesEncrypt(body, in.remotePub64, eciesEphemeralSecret, eciesIV, sizePrefix)
	if err != nil {
		return nil, fmt.Errorf("rlpx: auth ecies: %w", err)
	}
	wire := append(append([]byte{}, sizePrefix...), ct...)
	in.authWire = wire
	return append([]byte{}, wire...), nil
}

// ProcessAck opens the responder's ack wire and derives the session secrets.
func (in *Initiator) ProcessAck(ackWire []byte) (*SessionSecrets, error) {
	if in.authWire == nil {
		return nil, errors.New("rlpx: BuildAuth must precede ProcessAck")
	}
	if len(ackWire) < 2 {
		return nil, errors.New("rlpx: ack too short")
	}
	plain, err := EciesDecrypt(ackWire[2:], in.localKey, ackWire[:2])
	if err != nil {
		return nil, fmt.Errorf("rlpx: ack ecies: %w", err)
	}
	// ack body: [ephemeral-pubkey(64), nonce(32), version(4), …]. Live peers
	// append EIP-8 random padding as RAW BYTES after the list (measured on
	// mainnet: the dominant ack failure when this is strict), and some
	// append list fields; like the Rust twin's decode_prefix we take the
	// FIRST top-level item strictly and ignore whatever trails it.
	first, _, err := rlpcode.SplitItem(plain)
	if err != nil {
		return nil, fmt.Errorf("rlpx: ack body: %w", err)
	}
	items, err := rlpcode.Items(first)
	if err != nil {
		return nil, fmt.Errorf("rlpx: ack body: %w", err)
	}
	if len(items) < 2 {
		return nil, fmt.Errorf("rlpx: ack body too short (%d items)", len(items))
	}
	remoteEph, err := rlpcode.FixedBytes(items[0], 64)
	if err != nil {
		return nil, fmt.Errorf("rlpx: ack ephemeral: %w", err)
	}
	remoteNonce, err := rlpcode.FixedBytes(items[1], 32)
	if err != nil {
		return nil, fmt.Errorf("rlpx: ack nonce: %w", err)
	}
	var rn [32]byte
	copy(rn[:], remoteNonce)
	return DeriveSecrets(in.ephemeral, remoteEph, in.localNonce, rn, in.authWire, ackWire)
}

// DeriveSecrets computes the channel secrets from the two ephemeral keys and
// nonces (docs/spec/02 §5.2):
//
//	ephShared    = ECDH(localEph, remoteEph)
//	sharedSecret = keccak256(ephShared ‖ keccak256(remoteNonce ‖ localNonce))
//	aesSecret    = keccak256(ephShared ‖ sharedSecret)
//	macSecret    = keccak256(ephShared ‖ aesSecret)
//
// Exported so the conformance test can pin the derivation directly against
// the corpus, like the Rust derive_secrets.
func DeriveSecrets(localEph *ecdsa.PrivateKey, remoteEphPub64 []byte, localNonce, remoteNonce [32]byte, authWire, ackWire []byte) (*SessionSecrets, error) {
	ephShared, err := EcdhX(localEph, remoteEphPub64)
	if err != nil {
		return nil, fmt.Errorf("rlpx: eph ecdh: %w", err)
	}
	nonceHash := crypto.Keccak256(remoteNonce[:], localNonce[:])
	sharedSecret := crypto.Keccak256(ephShared[:], nonceHash)
	aesSecret := crypto.Keccak256(ephShared[:], sharedSecret)
	macSecret := crypto.Keccak256(ephShared[:], aesSecret)

	s := &SessionSecrets{
		EgressNonce:  localNonce,
		IngressNonce: remoteNonce,
		AuthWire:     append([]byte{}, authWire...),
		AckWire:      append([]byte{}, ackWire...),
	}
	copy(s.AESSecret[:], aesSecret)
	copy(s.MACSecret[:], macSecret)
	return s, nil
}

// AckWire builds a responder's EIP-8 ack wire — the mirror of BuildAuth. It
// exists for tests (the engine itself never accepts inbound connections), and
// scripting one is what proves our initiator byte-compatible in both
// directions. The ack is ECIES-only: nothing is signed, no local key needed.
func AckWire(remotePub64, ephSecret, iv, nonce []byte) ([]byte, error) {
	return AckWirePadded(remotePub64, ephSecret, iv, nonce, nil)
}

// AckWirePadded is AckWire with raw (NOT RLP-encoded) bytes appended after
// the body list — the EIP-8 padding shape live mainnet peers actually send.
func AckWirePadded(remotePub64, ephSecret, iv, nonce, rawPadding []byte) ([]byte, error) {
	eph, err := crypto.ToECDSA(ephSecret)
	if err != nil {
		return nil, fmt.Errorf("rlpx: bad ack ephemeral: %w", err)
	}
	eph64 := crypto.FromECDSAPub(&eph.PublicKey)[1:]
	var n [32]byte
	copy(n[:], nonce)
	body := append(rlpcode.List(
		rlpcode.Bytes(eph64),
		rlpcode.Bytes(n[:]),
		rlpcode.Uint(rlpxVersion),
	), rawPadding...)
	encSize := len(body) + 65 + 16 + 32
	sizePrefix := []byte{byte(encSize >> 8), byte(encSize)}
	ct, err := eciesEncrypt(body, remotePub64, ephSecret, iv, sizePrefix)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, sizePrefix...), ct...), nil
}
