// Package transport dials a discovered peer and drives the connection to a
// READY eth session: the EIP-8 RLPx handshake, the framed channel, the p2p
// Hello capability negotiation and the eth Status gate (docs/spec/02 §5-§6).
// Twin of myotis-net's RlpxConnection + EthSession — dialer-only, like every
// reference path.
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
	// pongWriteTimeout bounds a Pong write from the reader goroutine (the
	// write side is shared with requests; a stuck peer must not stall the
	// reader).
	pongWriteTimeout = 5 * time.Second
	// frameBodyTimeout bounds the time between an accepted frame header and
	// its body MAC (Rust FRAME_BODY_TIMEOUT, myotis-net el/rlpx/transport.rs):
	// a peer that announces a 10 MiB body and then idles must not pin the
	// buffer and the session forever. Waiting for the NEXT header stays
	// unbounded — idle peers are normal.
	frameBodyTimeout = 30 * time.Second
)

// Config is one dial: our identity + the pinned network + the candidate.
type Config struct {
	LocalKey *ecdsa.PrivateKey
	Network  *chain.Network
	Node     *enode.Node

	DialTimeout      time.Duration // 0 → DefaultDialTimeout
	HandshakeTimeout time.Duration // 0 → DefaultHandshakeTimeout
	RequestTimeout   time.Duration // 0 → DefaultRequestTimeout

	// AdvertiseTCPPort is what our Hello names as our TCP port — the port a
	// peer would dial to reach us. The engine does not listen, so the CLI
	// passes the operator's configured port when it is a real one and 0
	// when the socket is ephemeral; never the network's constant, which is
	// a wrong-on-the-wire value whenever the operator moved off it.
	AdvertiseTCPPort uint16

	// Rand is the entropy source for the handshake ephemerals; nil →
	// crypto/rand. Tests inject fixed material.
	Rand io.Reader
}

// Session is a READY eth session on one peer connection. A background
// reader owns the ingress: it answers pings (geth drops silent peers on
// ping-timeout), routes responses to the caller, and signals Done when the
// connection dies — so a session in a pool never silently rots. Requests
// are single-flight (one request/response at a time), like the Rust
// one-shot EthSession.
type Session struct {
	conn  net.Conn
	codec *rlpx.FrameCodec

	writeMu sync.Mutex // serializes all frame writes (keystream is positional)
	// readMu only covers the handshake-phase reads that run before the
	// reader goroutine starts; after READY the reader is the sole reader.
	readMu sync.Mutex

	requestID atomic.Uint64

	PeerID     enode.ID
	ClientID   string
	Caps       []ethwire.Capability
	EthVersion uint64
	Snap       *uint64 // nil → peer has no usable snap
	PeerStatus *ethwire.Status

	requestTimeout time.Duration

	// Reader → waiters.
	done      chan struct{} // closed when the connection dies (any cause)
	closeOnce sync.Once
	closeErr  error // why it died (nil → local Close); guarded by errMu after close
	errMu     sync.Mutex

	// flightMu serializes requests (single-flight, one outstanding per
	// session); reqMu guards only the pending map. They MUST be distinct:
	// the waiter holds flightMu across its select, and the reader goroutine
	// needs reqMu to deliver the very response it is waiting for — one lock
	// for both deadlocks every request.
	flightMu sync.Mutex
	reqMu    sync.Mutex                         // guards pending
	pending  map[uint64]chan *rlpx.DecodedFrame // request id → response
}

// Dial connects and drives HANDSHAKE → READY. A peer failing the network-id
// + genesis gate or any framing check returns an error; the caller drops it
// and dials the next candidate. The fork id flows the other way at this
// stage (peers validate OUR pinned fork id and drop mismatches, see the
// chain.Network pin comment); we record the peer's for later use, like the
// Rust session, but do not gate on it — a peer announcing a newer fork
// branch is not a protocol violation. Closing the ctx bounds the handshake.
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
	// Make ctx cancellation (caller shutdown) actually bound the handshake,
	// not just its deadline: cancelling closes the socket under the
	// handshake's blocking reads. Released once the session is READY — from
	// then on the caller's dial ctx must not kill a live session.
	stopCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopCancel()

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
		done:           make(chan struct{}),
		pending:        map[uint64]chan *rlpx.DecodedFrame{},
	}
	s.requestID.Store(randomRequestID(randSrc))

	// --- p2p Hello ---
	localPub64 := crypto.FromECDSAPub(&cfg.LocalKey.PublicKey)[1:]
	if err := s.send(ethwire.P2PHello, ethwire.EncodeHello(localPub64, cfg.AdvertiseTCPPort), deadline); err != nil {
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
		// claiming more invites header requests we cannot answer.
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

	// Steady state: the reader goroutine owns the ingress, with no
	// deadline; requests set their own write deadlines.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	go s.readLoop()
	ok = true
	return s, nil
}

// Done closes when the session dies — peer disconnect, read error, or
// Close. Pool owners select on it to evict dead sessions promptly, so a
// "READY peers" count reflects live connections, not a historical census.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports why the session died after Done fired ("local close" when we
// closed it).
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.closeErr != nil {
		return s.closeErr
	}
	select {
	case <-s.done:
		return errors.New("transport: session closed")
	default:
		return nil
	}
}

// Close tears down the connection; Done fires and any waiting request
// unblocks with an error.
func (s *Session) Close() error {
	return s.shutdown(errors.New("transport: local close"))
}

func (s *Session) shutdown(reason error) error {
	var err error
	s.closeOnce.Do(func() {
		s.errMu.Lock()
		s.closeErr = reason
		s.errMu.Unlock()
		err = s.conn.Close()
		close(s.done)
	})
	return err
}

// readLoop is the steady-state ingress owner: answer pings (silent peers
// get dropped by geth on ping-timeout), route responses to their
// single-flight waiter, skip gossip, and end the session on any disconnect
// or read error.
func (s *Session) readLoop() {
	for {
		frame, err := s.recv(time.Time{})
		if err != nil {
			s.shutdown(fmt.Errorf("transport: read: %w", err))
			return
		}
		switch frame.MessageCode {
		case ethwire.P2PPing:
			// Pong body is an empty RLP list.
			if err := s.send(ethwire.P2PPong, []byte{0xc0}, time.Now().Add(pongWriteTimeout)); err != nil {
				s.shutdown(fmt.Errorf("transport: pong write: %w", err))
				return
			}
		case ethwire.P2PDisconnect:
			s.shutdown(fmt.Errorf("transport: peer disconnected: %s", ethwire.DescribeDisconnect(frame.Payload)))
			return
		default:
			if id, ok := ethwire.LeadingRequestID(frame.Payload); ok {
				s.reqMu.Lock()
				ch, waiting := s.pending[id]
				s.reqMu.Unlock()
				if waiting {
					select {
					case ch <- frame:
					default: // waiter already timed out; drop
					}
				}
			}
			// Gossip (NewPooledTransactionHashes, NewBlock, …) is skipped
			// — the wallet never serves it (docs/spec/02 §6.5).
		}
	}
}

// GetBlockHeadersByHash requests up to `count` headers starting at hash
// (fork/genesis probes) and returns their raw RLP. Each header's hash is
// the caller's to verify against a pin.
func (s *Session) GetBlockHeadersByHash(origin common.Hash, count uint64) ([][]byte, error) {
	id := s.requestID.Add(1)
	return s.getHeaders(id, ethwire.EncodeGetBlockHeadersByHash(id, origin, count, 0, false),
		int(count), fmt.Sprintf("headers by hash %s", origin))
}

// GetBlockHeadersByNumber requests `count` ascending headers from origin.
// Like GetBlockHeadersByHash it returns the peer's RAW bytes, unverified: a
// by-number request carries no hash to check against, so the caller owns
// the verification — an anchored hash for the first header, or a parent-
// hash chain from one (part 4's verified reads do exactly this).
func (s *Session) GetBlockHeadersByNumber(origin, count uint64) ([][]byte, error) {
	id := s.requestID.Add(1)
	return s.getHeaders(id, ethwire.EncodeGetBlockHeadersByNumber(id, origin, count, 0, false),
		int(count), fmt.Sprintf("headers from #%d", origin))
}

func (s *Session) getHeaders(requestID uint64, req []byte, expect int, what string) ([][]byte, error) {
	payload, err := s.requestFrame(requestID, ethwire.GetBlockHeaders, req, ethwire.BlockHeaders, what)
	if err != nil {
		return nil, err
	}
	id, headers, err := ethwire.DecodeBlockHeaders(payload, expect)
	if err != nil {
		return nil, err
	}
	// Responses are correlated by request id; a foreign id (we only get
	// here for our own) or an over-long list is already refused above.
	if id != requestID {
		return nil, fmt.Errorf("transport: %s response id %d ≠ requested %d", what, id, requestID)
	}
	return headers, nil
}

// requestFrame runs one single-flight request: the reader goroutine
// delivers the response frame to this call only (matched by request
// id), or the call times out / the session dies. It checks the
// response CODE and hands back the payload; decoding and the id match
// are the typed caller's (headers in transport.go, the snap range
// reads in snap.go).
func (s *Session) requestFrame(requestID, sendCode uint64, req []byte, wantCode uint64, what string) ([]byte, error) {
	s.flightMu.Lock() // single-flight: one outstanding request per session
	defer s.flightMu.Unlock()

	ch := make(chan *rlpx.DecodedFrame, 1)
	s.reqMu.Lock()
	s.pending[requestID] = ch
	s.reqMu.Unlock()
	defer func() {
		s.reqMu.Lock()
		delete(s.pending, requestID)
		s.reqMu.Unlock()
	}()

	deadline := time.Now().Add(s.requestTimeout)
	if err := s.send(sendCode, req, deadline); err != nil {
		return nil, err
	}
	timer := time.NewTimer(s.requestTimeout)
	defer timer.Stop()
	var frame *rlpx.DecodedFrame
	select {
	case frame = <-ch:
	case <-s.done:
		return nil, s.Err()
	case <-timer.C:
		return nil, fmt.Errorf("transport: timed out awaiting %s", what)
	}
	if frame.MessageCode != wantCode {
		return nil, fmt.Errorf("transport: %s: expected 0x%02x, got 0x%02x", what, wantCode, frame.MessageCode)
	}
	return frame.Payload, nil
}

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

// recv reads and opens exactly one frame. deadline is the zero time for
// "no deadline" (the reader loop); handshake-phase calls pass a real one.
func (s *Session) recv(deadline time.Time) (*rlpx.DecodedFrame, error) {
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
	// From here the header COMMITS us to reading bodyLen bytes: bound that
	// stretch even for the deadline-less reader, so an announced-but-never-
	// sent body times out instead of pinning the buffer (frameBodyTimeout;
	// the next recv's SetReadDeadline clears it again).
	if deadline.IsZero() {
		if err := s.conn.SetReadDeadline(time.Now().Add(frameBodyTimeout)); err != nil {
			return nil, err
		}
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
