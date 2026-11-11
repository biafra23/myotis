package eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/forkid"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	dialTimeout    = 10 * time.Second
	handshakeTotal = 30 * time.Second // Hello+Status budget (spec §6.1)
	writeTimeout   = 10 * time.Second
	requestTimeout = 15 * time.Second
	idleTimeout    = 90 * time.Second // no inbound traffic at all → drop peer
	pingEvery      = 30 * time.Second
)

var ErrPeerClosed = errors.New("eth: peer closed")

// ErrBadAnswer marks a peer whose ANSWER failed protocol validation —
// undecodable, over-served, or failing the hash-link checks. Callers use it
// to tell "this peer lied/broke, drop it" apart from transport failure or a
// timeout, where the peer may still be worth keeping.
var ErrBadAnswer = errors.New("eth: bad answer from peer")

// Header is one verified header: the raw RLP as received plus its recomputed
// hash (docs/spec/02 §6.6 — hash = keccak256 of the canonical RLP; a
// non-canonical re-encode is a verification failure, not a re-format).
type Header struct {
	Hash       common.Hash
	Raw        []byte
	Number     uint64
	Time       uint64
	StateRoot  common.Hash
	ParentHash common.Hash
}

// Peer is one READY eth connection. Reads run on a dedicated goroutine;
// writes are marshaled through one mutex (the frame codec is stateful —
// docs/spec/02 §5.4).
type Peer struct {
	Node     *enode.Node
	ID       enode.ID
	ClientID string
	Version  uint
	Status   PeerStatus

	conn *rlpx.Conn
	log  *slog.Logger

	writeMu sync.Mutex
	nextReq atomic.Uint64

	pendMu  sync.Mutex
	pending map[uint64]chan rlp.RawValue

	closeOnce sync.Once
	closed    chan struct{}
	done      sync.WaitGroup
}

// Dial connects, runs the RLPx EIP-8 handshake, Hello, and Status, and
// returns a ready peer or an error (with the socket already closed). ctx
// bounds connect+handshake only; the returned peer lives until Close.
func Dial(ctx context.Context, key *ecdsa.PrivateKey, node *enode.Node, netw *chain.Network, log *slog.Logger) (*Peer, error) {
	if node.TCP() == 0 {
		return nil, fmt.Errorf("eth: node %s has no TCP port", node.ID().TerminalString())
	}
	d := net.Dialer{Timeout: dialTimeout}
	tc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(node.IP().String(), fmt.Sprint(node.TCP())))
	if err != nil {
		return nil, fmt.Errorf("eth: tcp dial: %w", err)
	}
	rc := rlpx.NewConn(tc, node.Pubkey())
	if err := rc.SetDeadline(time.Now().Add(handshakeTotal)); err != nil {
		rc.Close()
		return nil, err
	}
	remote, err := rc.Handshake(key)
	if err != nil {
		rc.Close()
		return nil, fmt.Errorf("eth: rlpx handshake: %w", err)
	}
	if !bytes.Equal(crypto.FromECDSAPub(remote), crypto.FromECDSAPub(node.Pubkey())) {
		rc.Close()
		return nil, errors.New("eth: rlpx authenticated a different key than the ENR we dialed")
	}

	p := &Peer{
		Node:    node,
		ID:      node.ID(),
		conn:    rc,
		log:     log.With("peer", node.ID().TerminalString()),
		closed:  make(chan struct{}),
		pending: map[uint64]chan rlp.RawValue{},
	}

	// Hello runs uncompressed (spec §5.3: snappy applies to everything
	// except Hello; geth toggles the flag the same way). Re-enable it
	// explicitly before any goroutine touches the connection — a defer
	// would race the readLoop's first Read.
	rc.SetSnappy(false)
	if err := p.sendHello(key); err != nil {
		rc.Close()
		return nil, err
	}
	peerVersions, clientID, err := p.readHello()
	if err != nil {
		rc.Close()
		return nil, err
	}
	p.ClientID = clientID
	p.Version = HighestCommon(peerVersions)
	if p.Version == 0 {
		rc.Close()
		return nil, fmt.Errorf("eth: no common eth version with %s (peer offers %v)", clientID, peerVersions)
	}
	rc.SetSnappy(true)
	if err := p.exchangeStatus(netw); err != nil {
		rc.Close()
		return nil, err
	}
	// Hand deadline control over: clear the handshake deadline on both
	// directions, then arm the READ side with the idle timeout. Writes arm
	// their own deadline per send (p.write). The read loop re-arms on every
	// inbound frame — the keepalive must not arm it too, or a peer that
	// receives our Pings but never speaks would never expire.
	if err := rc.SetDeadline(time.Time{}); err != nil {
		rc.Close()
		return nil, err
	}
	if err := rc.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		rc.Close()
		return nil, err
	}

	p.done.Add(1)
	go p.readLoop()
	p.done.Add(1)
	go p.keepalive()
	p.log.Info("eth peer ready", "client", clientID, "version", p.Version, "best", p.Status.BestHash)
	return p, nil
}

// Close sends a polite Disconnect and tears the connection down. Safe to
// call after the peer already died on its own.
func (p *Peer) Close() {
	_ = p.write(p.conn, msgDisconnect, mustRLP([]uint{uint(discQuit)}))
	p.markDead()
	p.done.Wait()
	p.failAllPending(ErrPeerClosed)
}

// Dead is closed when the peer is gone — either Close()d by us or when the
// read side ends (peer disconnect, timeout, frame error). Callers hold this
// to evict dead peers from their own bookkeeping.
func (p *Peer) Dead() <-chan struct{} { return p.closed }

func (p *Peer) markDead() {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.conn.Close()
	})
}

func (p *Peer) sendHello(key *ecdsa.PrivateKey) error {
	caps := make([]capPair, 0, len(supportedEthVersions))
	for _, v := range supportedEthVersions {
		caps = append(caps, capPair{Name: "eth", Version: v})
	}
	pub := crypto.FromECDSAPub(&key.PublicKey) // 65 bytes, 0x04 prefix
	var id64 [64]byte
	copy(id64[:], pub[1:])
	h := helloMsg{
		Capability:   5,
		ClientID:     "myotis-go/v0.1.0",
		Capabilities: caps,
		ListenPort:   0, // dialer: no inbound TCP
		NodeID:       id64,
	}
	return p.write(p.conn, msgHello, mustRLP(h))
}

// Size bounds for control messages and response elements (spec §9.12:
// refuse oversized control frames BEFORE decoding them — a hostile
// Capabilities list or ClientID must not cost an unbounded parse/log).
const (
	maxControlMsg  = 16 * 1024 // Hello / Status / Disconnect, like the Rust engine
	maxHeaderBytes = 64 * 1024 // one header element inside a BlockHeaders answer
)

func (p *Peer) readHello() (ethVersions []uint, clientID string, err error) {
	code, payload, _, err := p.conn.Read()
	if err != nil {
		return nil, "", fmt.Errorf("eth: read hello: %w", err)
	}
	if code != msgHello {
		return nil, "", fmt.Errorf("eth: expected hello (0x00), got 0x%02x (%s)", code, disconnectReason(payload))
	}
	if len(payload) > maxControlMsg {
		return nil, "", fmt.Errorf("eth: hello frame %d bytes over the %d cap", len(payload), maxControlMsg)
	}
	var h helloMsg
	if err := rlp.DecodeBytes(payload, &h); err != nil {
		return nil, "", fmt.Errorf("eth: decode hello: %w", err)
	}
	for _, c := range h.Capabilities {
		if c.Name == "eth" {
			ethVersions = append(ethVersions, c.Version)
		}
	}
	return ethVersions, strings.TrimSpace(h.ClientID), nil
}

func (p *Peer) exchangeStatus(netw *chain.Network) error {
	ourID := forkid.ID{Hash: netw.ForkIDHash, Next: netw.ForkNext}.IDAt(uint64(time.Now().Unix()))
	st := status68{
		Version:   uint32(p.Version),
		NetworkID: netw.NetworkID,
		TD:        rlp.RawValue{0x80}, // zero, RLP-encoded
		BestHash:  netw.GenesisHash,
		Genesis:   netw.GenesisHash,
		ForkID:    forkIDRLP{Hash: ourID.Hash, Next: ourID.Next},
	}
	if err := p.write(p.conn, msgStatus, mustRLP(st)); err != nil {
		return fmt.Errorf("eth: send status: %w", err)
	}

	// The loop below only reads, so this bounds the READ wait; our Status
	// write already armed its own deadline inside p.write.
	deadline := time.Now().Add(handshakeTotal)
	if err := p.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	for {
		code, payload, _, err := p.conn.Read()
		if err != nil {
			return fmt.Errorf("eth: read status: %w", err)
		}
		switch code {
		case msgStatus:
			if len(payload) > maxControlMsg {
				return fmt.Errorf("eth: status frame %d bytes over the %d cap", len(payload), maxControlMsg)
			}
			var got status68
			if err := rlp.DecodeBytes(payload, &got); err != nil {
				return fmt.Errorf("eth: decode status: %w", err)
			}
			if got.NetworkID != netw.NetworkID {
				p.disconnect(discUselessPeer)
				return fmt.Errorf("eth: peer on network %d, we are %d", got.NetworkID, netw.NetworkID)
			}
			if got.Genesis != netw.GenesisHash {
				p.disconnect(discUselessPeer)
				return fmt.Errorf("eth: peer genesis %s, we pin %s", got.Genesis, netw.GenesisHash)
			}
			theirs := forkid.ID{Hash: got.ForkID.Hash, Next: got.ForkID.Next}
			if !forkid.Accept(ourID, theirs) {
				p.disconnect(discSubprotocolErr)
				return fmt.Errorf("eth: fork id %x/%d not compatible with ours %x/%d", theirs.Hash, theirs.Next, ourID.Hash, ourID.Next)
			}
			p.Status = PeerStatus{
				Version:   got.Version,
				NetworkID: got.NetworkID,
				BestHash:  got.BestHash,
				Genesis:   got.Genesis,
				ForkHash:  got.ForkID.Hash,
				ForkNext:  got.ForkID.Next,
			}
			return nil
		case msgDisconnect:
			return fmt.Errorf("eth: peer disconnected during status (%s)", disconnectReason(payload))
		default:
			// Some peers start gossiping immediately; ignore until Status.
		}
	}
}

// GetBlockHeaders asks for `amount` headers walking backward from a hash
// (or forward from a number when reverse is true), correlated by request id.
func (p *Peer) GetBlockHeaders(fromHash common.Hash, amount uint32) ([]Header, error) {
	reqID := p.nextReq.Add(1)
	origin, err := rlp.EncodeToBytes(fromHash)
	if err != nil {
		return nil, err
	}
	ch := p.registerRequest(reqID)
	payload := mustRLP(getBlockHeaders66{
		ReqID: reqID,
		// Reverse from a hash origin walks BACKWARD from it (a forward
		// walk from the head is a one-header answer — learned live).
		Query: headerQuery{Origin: origin, Amount: amount, Reverse: true},
	})
	if err := p.write(p.conn, msgGetBlockHeaders, payload); err != nil {
		p.unregisterRequest(reqID)
		return nil, err
	}

	var raws [][]byte
	select {
	case raw, ok := <-ch:
		if !ok {
			return nil, ErrPeerClosed
		}
		// Walk the answer element-by-element instead of DecodeBytes:
		// a 16 MiB list of small elements would materialise as a
		// ~1 GB owned tree first (spec §9.12, #454). Bound by what
		// we asked for, not a global constant — callers may rely on
		// len(result) <= amount.
		raws, err = walkBlockHeaders(raw, amount)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadAnswer, err)
		}
	case <-time.After(requestTimeout):
		p.unregisterRequest(reqID)
		return nil, fmt.Errorf("eth: GetBlockHeaders %d timed out", reqID)
	case <-p.closed:
		return nil, ErrPeerClosed
	}
	if uint32(len(raws)) > amount {
		return nil, fmt.Errorf("%w: asked %d headers, peer sent %d", ErrBadAnswer, amount, len(raws))
	}
	// No second reqID check needed: readLoop routed this payload to us by
	// exactly that id (firstRequestID).
	return p.verifyBackwardChain(fromHash, raws)
}

// walkBlockHeaders reads [reqId, [header…]] off the stream, taking at most
// amount+1 raw headers: one MORE than requested is refused without the
// decoder pre-allocating the whole (possibly enormous) list, so an
// over-serving peer stays visible and cheap (#454).
func walkBlockHeaders(raw rlp.RawValue, amount uint32) ([][]byte, error) {
	s := rlp.NewStream(bytes.NewReader(raw), uint64(len(raw))+1)
	if _, err := s.List(); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	var reqID uint64
	if err := s.Decode(&reqID); err != nil { // routed already; read for position
		return nil, fmt.Errorf("decode request id: %w", err)
	}
	if _, err := s.List(); err != nil {
		return nil, fmt.Errorf("decode header list: %w", err)
	}
	var out [][]byte
	for {
		item, err := s.Raw()
		if err == rlp.EOL {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode header element: %w", err)
		}
		if uint32(len(out)) >= amount+1 {
			return nil, fmt.Errorf("peer sent more than the %d requested headers", amount)
		}
		if len(item) > maxHeaderBytes {
			return nil, fmt.Errorf("header element %d bytes over the %d cap", len(item), maxHeaderBytes)
		}
		// Raw() returns a slice the caller keeps; nothing reuses it here.
		out = append(out, item)
	}
	if err := s.ListEnd(); err != nil {
		return nil, fmt.Errorf("close header list: %w", err)
	}
	if err := s.ListEnd(); err != nil {
		return nil, fmt.Errorf("close envelope: %w", err)
	}
	return out, nil
}

// verifyBackwardChain recomputes every header hash from its raw RLP (and
// refuses non-canonical re-encodings), then checks the chain links: the
// first header hashes to the requested head, each next one is the previous
// one's parent, numbers step by one. Anchoring to a trusted root is the
// light client's job (part 3), not this function's.
func (p *Peer) verifyBackwardChain(fromHash common.Hash, raws [][]byte) ([]Header, error) {
	if len(raws) == 0 {
		return nil, fmt.Errorf("%w: peer returned no headers", ErrBadAnswer)
	}
	out := make([]Header, 0, len(raws))
	for i, raw := range raws {
		hc, err := headerCore(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: header %d undecodable: %v", ErrBadAnswer, i, err)
		}
		// The identity hash is keccak over the RAW bytes — never over a
		// re-encode of what we understood — so unknown future fields are
		// covered by the hash while still being tolerated (§6.6).
		hash := crypto.Keccak256Hash(raw)
		out = append(out, Header{
			Hash: hash, Raw: raw, Number: hc.Number,
			Time: hc.Time, StateRoot: hc.StateRoot, ParentHash: hc.ParentHash,
		})
	}
	if out[0].Hash != fromHash {
		return nil, fmt.Errorf("%w: head mismatch: asked %s, first header is %s", ErrBadAnswer, fromHash, out[0].Hash)
	}
	for i := 1; i < len(out); i++ {
		prev := out[i-1]
		if out[i].Hash != prev.ParentHash {
			return nil, fmt.Errorf("%w: broken chain at %d: hash %s != parent %s", ErrBadAnswer, prev.Number, out[i].Hash, prev.ParentHash)
		}
		if out[i].Number+1 != prev.Number {
			return nil, fmt.Errorf("%w: number jump %d → %d", ErrBadAnswer, prev.Number, out[i].Number)
		}
	}
	return out, nil
}

// headerFields are the four header fields this layer verifies with; they are
// read by walking the RLP list, NOT via geth's types.Header. A struct
// decode rejects any element the pinned geth doesn't declare ("input list
// has too many elements"), which would make the next header-extending fork
// (Amsterdam's blockAccessListHash/slotNumber, live on Sepolia since
// 2026-10-06) unreadable no matter that forkid.IDAt keeps announcing the
// right fork id across it. Spec §6.6 asks for tolerance; the Rust twin walks
// the same way (myotis-core/src/header.rs). Canonicality comes from the
// stream itself: RLP uints must be minimally encoded (this also rejects a
// number beyond uint64 — the old IsUint64 guard), and common.Hash decoding
// requires exactly 32 bytes.
type headerFields struct {
	ParentHash common.Hash
	StateRoot  common.Hash
	Number     uint64
	Time       uint64
}

// Field indices inside the header list (Frontier layout; every fork so far
// only APPENDED): parentHash=0, stateRoot=3, number=8, timestamp=11.
func headerCore(raw []byte) (headerFields, error) {
	var hc headerFields
	s := rlp.NewStream(bytes.NewReader(raw), maxHeaderBytes)
	if _, err := s.List(); err != nil {
		return hc, err
	}
	read := func(idx int, dst any) error {
		if err := s.Decode(dst); err != nil {
			return fmt.Errorf("field %d: %w", idx, err)
		}
		return nil
	}
	skip := func(idx int) error {
		if _, err := s.Raw(); err != nil {
			return fmt.Errorf("field %d: %w", idx, err)
		}
		return nil
	}
	steps := []func() error{
		func() error { return read(0, &hc.ParentHash) },
		func() error { return skip(1) },
		func() error { return skip(2) },
		func() error { return read(3, &hc.StateRoot) },
		func() error { return skip(4) },
		func() error { return skip(5) },
		func() error { return skip(6) },
		func() error { return skip(7) },
		func() error { return read(8, &hc.Number) },
		func() error { return skip(9) },
		func() error { return skip(10) },
		func() error { return read(11, &hc.Time) },
	}
	for _, st := range steps {
		if err := st(); err != nil {
			return hc, err
		}
	}
	// Consume the tail: unknown future fields are tolerated, but the list
	// must end cleanly and nothing may trail it (corpus case
	// 093-header-trailing-byte: trailing bytes are a decode error).
	for {
		if _, err := s.Raw(); err == rlp.EOL {
			break
		} else if err != nil {
			return hc, fmt.Errorf("tail: %w", err)
		}
	}
	if err := s.ListEnd(); err != nil {
		return hc, fmt.Errorf("list end: %w", err)
	}
	if _, err := s.Raw(); err != io.EOF {
		return hc, errors.New("trailing bytes after header list")
	}
	return hc, nil
}

func (p *Peer) keepalive() {
	defer p.done.Done()
	tick := time.NewTicker(pingEvery)
	defer tick.Stop()
	for {
		select {
		case <-p.closed:
			return
		case <-tick.C:
			// No read-deadline arming here: the deadline must expire on
			// SILENCE, and every inbound frame re-arms it in readLoop. A
			// live peer answers our Ping with a Pong; arming on our own
			// successful write instead (as this once did) would keep a
			// black-holed peer — whose writes only hit the kernel buffer
			// — alive forever, and its slot in the stage's ready set
			// with it.
			if err := p.write(p.conn, msgPing, mustRLP([]any{})); err != nil {
				p.log.Debug("keepalive ping failed, dropping peer", "err", err)
				p.conn.Close()
				return
			}
		}
	}
}

func (p *Peer) readLoop() {
	defer p.done.Done()
	defer p.markDead() // a peer that vanishes on its own is Dead() too
	for {
		code, payload, _, err := p.conn.Read()
		if err != nil {
			select {
			case <-p.closed:
			default:
				p.log.Debug("peer read ended", "err", err)
			}
			return
		}
		_ = p.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		switch code {
		case msgBlockHeaders, msgBlockBodies, msgPooledTxs, msgReceipts:
			id, err := firstRequestID(payload)
			if err != nil {
				p.log.Debug("bad response payload", "code", code, "err", err)
				continue
			}
			p.deliverResponse(id, payload) // else: late answer after a timeout, drop
		case msgPing:
			_ = p.write(p.conn, msgPong, mustRLP([]any{}))
		case msgPong, msgNewBlockHashes, msgTransactions, msgNewBlock, msgNewPooledTxHashes:
			// Wallet ignores gossip/mempool (spec §6.3).
		case msgDisconnect:
			// The one log that explains why a READY peer dropped us.
			p.log.Debug("peer disconnected", "reason", disconnectReason(payload))
			return
		case msgGetBlockHeaders, msgGetBlockBodies, msgGetReceipts, msgGetPooledTxs:
			// Answer empty so peers keep the connection (spec §Scope).
			if id, err := firstRequestID(payload); err == nil {
				empty := mustRLP([]any{id, []any{}})
				_ = p.write(p.conn, mapRequestToResponse(code), empty)
			}
		default:
			p.log.Debug("unhandled message", "code", code)
		}
	}
}

func mapRequestToResponse(req uint64) uint64 {
	switch req {
	case msgGetBlockHeaders:
		return msgBlockHeaders
	case msgGetBlockBodies:
		return msgBlockBodies
	case msgGetReceipts:
		return msgReceipts
	case msgGetPooledTxs:
		return msgPooledTxs
	}
	return req
}

// firstRequestID reads just the leading uint of a [reqId, …] response
// without building an owned RLP tree (spec §9.12).
func firstRequestID(payload []byte) (uint64, error) {
	stream := rlp.NewStream(bytes.NewReader(payload), 0)
	if _, err := stream.List(); err != nil {
		return 0, err
	}
	var id uint64
	if err := stream.Decode(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// deliverResponse hands a routed response payload to its requester. The
// CLONE is load-bearing: rlpx.Conn.Read returns a buffer valid only until
// the next Read (with snappy on, it is the shared decompression buffer),
// and readLoop turns straight back around to Read — a chatty peer's next
// frame would otherwise overwrite the answer under the requester's
// decoder. geth's own transport copies at the same seam (p2p/transport.go
// ReadMsg) for the same reason.
func (p *Peer) deliverResponse(id uint64, payload []byte) {
	if ch := p.takePending(id); ch != nil {
		ch <- rlp.RawValue(bytes.Clone(payload))
		close(ch)
	}
}

func (p *Peer) registerRequest(id uint64) chan rlp.RawValue {
	ch := make(chan rlp.RawValue, 1)
	p.pendMu.Lock()
	p.pending[id] = ch
	p.pendMu.Unlock()
	return ch
}

func (p *Peer) unregisterRequest(id uint64) {
	p.pendMu.Lock()
	delete(p.pending, id)
	p.pendMu.Unlock()
}

func (p *Peer) takePending(id uint64) chan rlp.RawValue {
	p.pendMu.Lock()
	defer p.pendMu.Unlock()
	ch := p.pending[id]
	delete(p.pending, id)
	return ch
}

func (p *Peer) failAllPending(err error) {
	p.pendMu.Lock()
	defer p.pendMu.Unlock()
	for id, ch := range p.pending {
		close(ch)
		delete(p.pending, id)
	}
}

// disconnect sends the wire form devp2p mandates: a ONE-element list
// ([reason]), same as geth's rlp.Encode([]DiscReason{r}). A bare uint is
// what this function used to send, which spec-conformant peers (geth
// included) failed to parse and recorded as reason 0.
func (p *Peer) disconnect(reason uint) {
	_ = p.write(p.conn, msgDisconnect, mustRLP([]uint{reason}))
}

// write serializes onto the connection and arms a write deadline.
func (p *Peer) write(rc *rlpx.Conn, code uint64, data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := rc.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if _, err := rc.Write(code, data); err != nil {
		return err
	}
	return nil
}

// disconnectReason renders a Disconnect payload for logs. The devp2p wire
// form is a ONE-element list ([reason] — geth's `c104` = too-many-peers),
// so a list is tried first; some clients historically sent the bare uint,
// which is accepted as the fallback. The returned string carries no
// leading space — callers format it. Hex output is capped: the payload can
// be any frame a peer sends under the Disconnect code.
func disconnectReason(payload []byte) string {
	var rs []uint
	if err := rlp.DecodeBytes(payload, &rs); err == nil && len(rs) == 1 {
		return namedReason(rs[0])
	}
	var r uint
	if err := rlp.DecodeBytes(payload, &r); err == nil {
		return namedReason(r)
	}
	hexed := payload
	suffix := ""
	if len(hexed) > 32 {
		hexed, suffix = hexed[:32], fmt.Sprintf("… (%d bytes)", len(payload))
	}
	return fmt.Sprintf("payload %x%s", hexed, suffix)
}

func namedReason(r uint) string {
	// geth's DiscReason table (p2p/peer_error.go).
	names := map[uint]string{
		0x00: "disconnect-requested", 0x01: "network-error", 0x02: "protocol-error",
		0x03: "useless-peer", 0x04: "too-many-peers", 0x05: "already-connected",
		0x06: "incompatible-version", 0x07: "invalid-identity", 0x08: "quitting",
		0x09: "unexpected-identity", 0x0a: "self-connect", 0x0b: "read-timeout",
		0x10: "subprotocol-error",
	}
	if n, ok := names[r]; ok {
		return fmt.Sprintf("reason 0x%02x %s", r, n)
	}
	return fmt.Sprintf("reason 0x%02x", r)
}

func mustRLP(v any) []byte {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic("eth: rlp encode: " + err.Error())
	}
	return b
}
