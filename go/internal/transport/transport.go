// Package transport dials a discovered peer and drives the connection to a
// READY eth session: the EIP-8 RLPx handshake, the framed channel, the p2p
// Hello capability negotiation and the eth Status gate (docs/spec/02 §5-§6).
// Twin of myotis-net's RlpxConnection + EthSession::handshake — dialer-only,
// like every reference path.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/ethwire"
	"github.com/biafra23/myotis/go/internal/rlpx"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

var (
	// Defaults from the Rust session (handshake 30 s, request 15 s).
	DefaultDialTimeout      = 10 * time.Second
	DefaultHandshakeTimeout = 30 * time.Second
	DefaultRequestTimeout   = 15 * time.Second
)

// Config is one dial: our identity + the pinned network + the candidate.
type Config struct {
	LocalKey *ecdsa.PrivateKey
	Network  *chain.Network
	Node     *enode.Node

	DialTimeout      time.Duration // 0 → DefaultDialTimeout
	HandshakeTimeout time.Duration // 0 → DefaultHandshakeTimeout
	RequestTimeout   time.Duration // 0 → DefaultRequestTimeout

	// Rand is the entropy source for the handshake ephemerals; nil →
	// crypto/rand. Tests inject fixed material.
	Rand io.Reader
}

// Session is a READY eth session on one peer connection. Requests are
// single-flight (one request/response at a time), like the Rust one-shot
// EthSession; the read side answers pings transparently and ignores gossip.
type Session struct {
	conn  net.Conn
	codec *rlpx.FrameCodec

	writeMu sync.Mutex // serializes all frame writes (keystream is positional)
	readMu  sync.Mutex // serializes all frame reads (keccak MAC chain too)

	requestID atomic.Uint64

	PeerID     enode.ID
	ClientID   string
	Caps       []ethwire.Capability
	EthVersion uint64
	Snap       *uint64 // nil → peer has no usable snap
	PeerStatus *ethwire.Status

	requestTimeout time.Duration
}

// Dial connects and drives HANDSHAKE → READY. A peer failing the network-id /
// genesis gate, the fork-id expectation, or any framing check returns an
// error; the caller drops it and dials the next candidate. Closing the ctx
// bounds the whole exchange.
func Dial(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Network == nil || cfg.Node == nil || cfg.LocalKey == nil {
		return nil, errors.New("transport: incomplete dial config")
	}
	if cfg.Node.Pubkey() == nil {
		return nil, fmt.Errorf("transport: candidate %s has no secp256k1 key", cfg.Node.ID())
	}
	dialTimeout := orDefault(cfg.DialTimeout, DefaultDialTimeout)
	hsTimeout := orDefault(cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	randSrc := cfg.Rand
	if randSrc == nil {
		randSrc = rand.Reader
	}

	addr := &net.TCPAddr{IP: cfg.Node.IP(), Port: cfg.Node.TCP()}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	deadline := time.Now().Add(hsTimeout)
	if dl, yes := ctx.Deadline(); yes && dl.Before(deadline) {
		deadline = dl
	}

	remotePub64 := crypto.FromECDSAPub(cfg.Node.Pubkey())[1:]

	// --- RLPx EIP-8 auth/ack ---
	ephSecret, err := random32(randSrc)
	if err != nil {
		return nil, err
	}
	nonce, err := random32(randSrc)
	if err != nil {
		return nil, err
	}
	initiator, err := rlpx.NewInitiator(cfg.LocalKey, remotePub64, ephSecret[:], nonce)
	if err != nil {
		return nil, err
	}
	eciesEph, err := random32(randSrc)
	if err != nil {
		return nil, err
	}
	eciesIV := make([]byte, 16)
	if _, err := io.ReadFull(randSrc, eciesIV); err != nil {
		return nil, err
	}
	// EIP-8 padding: 100-300 random bytes (geth's dialer range), as a
	// trailing list element.
	padding := make([]byte, 100+randomInRange(randSrc, 201))
	if _, err := io.ReadFull(randSrc, padding); err != nil {
		return nil, err
	}
	auth, err := initiator.BuildAuth(eciesEph[:], eciesIV, padding)
	if err != nil {
		return nil, err
	}

	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(auth); err != nil {
		return nil, fmt.Errorf("transport: send auth: %w", err)
	}

	ack, err := readAck(conn, deadline)
	if err != nil {
		return nil, err
	}
	secrets, err := initiator.ProcessAck(ack)
	if err != nil {
		return nil, err
	}
	codec, err := rlpx.NewFrameCodec(secrets)
	if err != nil {
		return nil, err
	}

	s := &Session{
		conn:           conn,
		codec:          codec,
		requestTimeout: orDefault(cfg.RequestTimeout, DefaultRequestTimeout),
		PeerID:         cfg.Node.ID(),
	}
	s.requestID.Store(randomRequestID(randSrc))

	// --- p2p Hello ---
	localPub64 := crypto.FromECDSAPub(&cfg.LocalKey.PublicKey)[1:]
	if err := s.send(ethwire.P2PHello, ethwire.EncodeHello(localPub64, uint16(cfg.Network.ListenPort)), deadline); err != nil {
		return nil, err
	}
	first, err := s.recv(deadline)
	if err != nil {
		return nil, err
	}
	if first.MessageCode == ethwire.P2PDisconnect {
		return nil, fmt.Errorf("transport: peer disconnected during handshake: %s", ethwire.DescribeDisconnect(first.Payload))
	}
	if first.MessageCode != ethwire.P2PHello {
		return nil, fmt.Errorf("transport: expected Hello, got code 0x%02x", first.MessageCode)
	}
	peerHello, err := ethwire.DecodeHello(first.Payload)
	if err != nil {
		return nil, err
	}
	ethVersion, snap, ok2 := ethwire.Negotiate(peerHello)
	if !ok2 {
		return nil, fmt.Errorf("transport: no common eth version with %q", peerHello.ClientID)
	}
	s.ClientID = peerHello.ClientID
	s.Caps = peerHello.Capabilities
	s.EthVersion = ethVersion
	s.Snap = snap

	// --- eth Status ---
	// Fork id: the pin as-is. (The Rust twin also rolls to a pinned
	// forkNext successor once it passes — mainnet's pin has no scheduled
	// next fork, so that step is a no-op here; add it with the next fork.)
	genesis := cfg.Network.GenesisHash
	var status []byte
	if ethVersion >= 69 {
		// We hold no headers yet, so we SERVE only [0,0] (genesis window);
		// claiming more invites header requests we cannot answer (#694's
		// lesson, docs/spec/02 §6.4).
		status = ethwire.EncodeStatus69(ethVersion, cfg.Network.NetworkID, genesis, genesis, cfg.Network.ForkIDHash, cfg.Network.ForkNext, 0, 0)
	} else {
		// Post-Merge td is empty; a light client may send genesis as best
		// hash — peers gate on the fork id, not it.
		status = ethwire.EncodeStatus(ethVersion, cfg.Network.NetworkID, genesis, genesis, cfg.Network.ForkIDHash, cfg.Network.ForkNext)
	}
	if err := s.send(ethwire.StatusMsg, status, deadline); err != nil {
		return nil, err
	}

	peerStatus, err := s.awaitStatus(ethVersion, deadline)
	if err != nil {
		return nil, err
	}
	if !peerStatus.Compatible(cfg.Network.NetworkID, genesis) {
		return nil, fmt.Errorf("transport: peer on wrong chain (networkId %d, genesis %s)", peerStatus.NetworkID, peerStatus.GenesisHash)
	}
	s.PeerStatus = peerStatus

	// Steady state: no handshake-wide deadline; requests set their own.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// GetBlockHeadersByHash requests up to `count` headers starting at hash
// (fork/genesis probes) and returns their raw RLP. Each header's hash is the
// caller's to verify against a pin.
func (s *Session) GetBlockHeadersByHash(origin common.Hash, count uint64) ([][]byte, error) {
	id := s.requestID.Add(1)
	return s.getHeaders(id, ethwire.EncodeGetBlockHeadersByHash(id, origin, count, 0, false),
		fmt.Sprintf("headers by hash %s", origin))
}

// GetBlockHeadersByNumber requests `count` ascending headers from origin.
func (s *Session) GetBlockHeadersByNumber(origin, count uint64) ([][]byte, error) {
	id := s.requestID.Add(1)
	return s.getHeaders(id, ethwire.EncodeGetBlockHeadersByNumber(id, origin, count, 0, false),
		fmt.Sprintf("headers from #%d", origin))
}

func (s *Session) getHeaders(requestID uint64, req []byte, what string) ([][]byte, error) {
	deadline := time.Now().Add(s.requestTimeout)
	if err := s.send(ethwire.GetBlockHeaders, req, deadline); err != nil {
		return nil, err
	}
	for {
		frame, err := s.recv(deadline)
		if err != nil {
			return nil, fmt.Errorf("transport: awaiting %s: %w", what, err)
		}
		switch frame.MessageCode {
		case ethwire.BlockHeaders:
			id, headers, err := ethwire.DecodeBlockHeaders(frame.Payload)
			if err != nil {
				return nil, err
			}
			// Responses are correlated by request id; a foreign id is
			// another exchange's answer (or a lie) — skip it, like the
			// Rust await loop, rather than serve it as ours.
			if id != requestID {
				continue
			}
			return headers, nil
		case ethwire.P2PDisconnect:
			return nil, fmt.Errorf("transport: peer disconnected while awaiting %s: %s", what, ethwire.DescribeDisconnect(frame.Payload))
		default:
			// Gossip and unrelated messages are skipped — the wallet
			// never serves them (docs/spec/02 §6.5).
		}
	}
}

// Close tears down the connection.
func (s *Session) Close() error { return s.conn.Close() }

// send frames and writes one message (serialized: the egress keystream is
// position-dependent).
func (s *Session) send(code uint64, payload []byte, deadline time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := s.conn.Write(s.codec.EncodeFrame(code, payload))
	return err
}

// recv reads and opens exactly one frame.
func (s *Session) recv(deadline time.Time) (*rlpx.DecodedFrame, error) {
	// Reads never overlap (single caller at a time), so one lock covers the
	// deadline + the full frame read.
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	head := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, head); err != nil {
		return nil, fmt.Errorf("transport: read header: %w", err)
	}
	headMac := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, headMac); err != nil {
		return nil, fmt.Errorf("transport: read header mac: %w", err)
	}
	bodyLen, err := s.codec.DecodeHeader(head, headMac)
	if err != nil {
		return nil, err
	}
	padded := bodyLen
	if pad := padded % 16; pad != 0 {
		padded += 16 - pad
	}
	encBody := make([]byte, padded)
	if _, err := io.ReadFull(s.conn, encBody); err != nil {
		return nil, fmt.Errorf("transport: read body: %w", err)
	}
	bodyMac := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, bodyMac); err != nil {
		return nil, fmt.Errorf("transport: read body mac: %w", err)
	}
	return s.codec.DecodeBody(encBody, bodyMac, bodyLen)
}

// awaitStatus reads frames until the peer's Status arrives, answering pings
// in between. The first non-ping frame must be Status or Disconnect — like
// geth's readStatusMsg, a stray message fails the handshake rather than
// being skipped (myotis-net session.rs).
func (s *Session) awaitStatus(ethVersion uint64, deadline time.Time) (*ethwire.Status, error) {
	for {
		frame, err := s.recv(deadline)
		if err != nil {
			return nil, err
		}
		switch frame.MessageCode {
		case ethwire.P2PPing:
			// Pong body is an empty RLP list.
			if err := s.send(ethwire.P2PPong, []byte{0xc0}, deadline); err != nil {
				return nil, err
			}
		case ethwire.StatusMsg:
			return ethwire.DecodeStatus(frame.Payload, ethVersion)
		case ethwire.P2PDisconnect:
			return nil, fmt.Errorf("transport: peer disconnected after our Status: %s", ethwire.DescribeDisconnect(frame.Payload))
		default:
			return nil, fmt.Errorf("transport: expected Status, got code 0x%02x", frame.MessageCode)
		}
	}
}

// readAck reads the EIP-8 ack: the 2-byte size prefix, then exactly that
// many bytes (the prefix counts everything after it).
func readAck(conn net.Conn, deadline time.Time) ([]byte, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		return nil, fmt.Errorf("transport: read ack prefix: %w", err)
	}
	size := int(prefix[0])<<8 | int(prefix[1])
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("transport: read ack body: %w", err)
	}
	return append(prefix, body...), nil
}

func random32(r io.Reader) ([32]byte, error) {
	var out [32]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, fmt.Errorf("transport: entropy: %w", err)
	}
	return out, nil
}

// randomInRange returns [0, n) without modulo bias.
func randomInRange(r io.Reader, n int64) int {
	v, err := rand.Int(r, big.NewInt(n))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// randomRequestID starts the request-id counter above 0 so id 0 can mark a
// malformed response.
func randomRequestID(r io.Reader) uint64 {
	v, err := rand.Int(r, big.NewInt(1<<62))
	if err != nil {
		return 1
	}
	return v.Uint64() + 1
}

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
