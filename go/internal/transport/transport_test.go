package transport

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/ethwire"
	"github.com/biafra23/myotis/go/internal/rlpcode"
	"github.com/biafra23/myotis/go/internal/rlpx"
	"github.com/biafra23/myotis/go/internal/snapwire"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// scriptedPeer plays the responder half of a full session over a real TCP
// connection: decrypts our auth and checks its signature, sends a proper ack,
// exchanges Hello/Status over the framed channel, and answers one
// GetBlockHeaders. The engine is always the initiator — it never accepts —
// so the responder exists only here, to prove both sides of our byte order
// in CI without a live network (the live proof is the CLI smoke).
type scriptedPeer struct {
	t    *testing.T
	conn net.Conn
	key  *ecdsa.PrivateKey

	ethVersion  uint64
	snapVersion uint64 // 0 → advertise eth only (the chain-gate test does)
	networkID   uint64
	genesis     common.Hash
	mangle      bool // reply a wrong genesis to exercise the chain gate

	// answerRequest, when set, replaces the scripted GetBlockHeaders
	// answer (the snap round-trip test answers GetAccountRange there).
	answerRequest func(f *rlpx.DecodedFrame, send func(code uint64, payload []byte))

	// pongDone closes once the peer has verified our answer to its
	// post-handshake Ping; the test waits on it so the assertion cannot
	// race the deferred Close.
	pongDone chan struct{}
}

// peerHello hand-builds a Hello advertising only eth/<version> — the wire
// shape without reusing our own capability list.
func (p *scriptedPeer) hello() []byte {
	caps := []rlp.RawValue{rlpcode.List(rlpcode.String("eth"), rlpcode.Uint(p.ethVersion))}
	if p.snapVersion > 0 {
		caps = append(caps, rlpcode.List(rlpcode.String("snap"), rlpcode.Uint(p.snapVersion)))
	}
	return rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.String("scripted-peer/0"),
		rlpcode.List(caps...),
		rlpcode.Uint(30303),
		rlpcode.Bytes(crypto.FromECDSAPub(&p.key.PublicKey)[1:]),
	)
}

func (p *scriptedPeer) run() {
	t := p.t
	defer p.conn.Close()
	_ = rlp.ListSize // keep rlp imported if the helpers above change

	// --- decrypt the auth, verify its signature ---
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(p.conn, prefix); err != nil {
		return // initiator gone: ordinary teardown, the test asserts it
	}
	size := int(prefix[0])<<8 | int(prefix[1])
	body := make([]byte, size)
	if _, err := io.ReadFull(p.conn, body); err != nil {
		return
	}
	authWire := append(append([]byte{}, prefix...), body...)
	plain, err := rlpx.EciesDecrypt(authWire[2:], p.key, prefix)
	if err != nil {
		t.Errorf("peer: auth decrypt: %v", err)
		return
	}
	items, err := rlpcode.Items(plain)
	if err != nil || len(items) < 3 {
		t.Errorf("peer: auth body malformed: %v", err)
		return
	}
	sig, err := rlpcode.FixedBytes(items[0], 65)
	if err != nil {
		t.Errorf("peer: auth sig: %v", err)
		return
	}
	aPub64, err := rlpcode.FixedBytes(items[1], 64)
	if err != nil {
		t.Errorf("peer: auth pubkey: %v", err)
		return
	}
	aNonce, err := rlpcode.FixedBytes(items[2], 32)
	if err != nil {
		t.Errorf("peer: auth nonce: %v", err)
		return
	}
	// The auth sig is signed by the initiator's EPHEMERAL key over
	// token = ECDH(static,static) XOR nonce — recovery on this side is how a
	// responder learns the initiator's ephemeral pubkey (there is nothing
	// else to check it against; docs/spec/02 §9.3).
	var nonceArr [32]byte
	copy(nonceArr[:], aNonce)
	staticShared, err := rlpx.EcdhX(p.key, aPub64)
	if err != nil {
		t.Errorf("peer: ecdh: %v", err)
		return
	}
	var token [32]byte
	for i := range token {
		token[i] = staticShared[i] ^ nonceArr[i]
	}
	rec, err := crypto.Ecrecover(token[:], sig)
	if err != nil || len(rec) != 65 || rec[0] != 0x04 {
		t.Errorf("peer: auth sig does not recover (err %v)", err)
		return
	}
	aEph64 := rec[1:] // the initiator's ephemeral pubkey, recovered

	// --- ack ---
	// (t.Errorf, not t.Fatal: this runs on the acceptor goroutine, and
	// Fatal from a non-test goroutine only kills that goroutine — turning a
	// clear failure into a mysterious dial timeout.)
	bEphSecret, err := crypto.HexToECDSA("e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4")
	if err != nil {
		t.Errorf("peer: fixed ephemeral: %v", err)
		return
	}
	var bNonce [32]byte
	copy(bNonce[:], crypto.Keccak256([]byte("scripted-b-nonce")))
	ackWire, err := rlpx.AckWire(aPub64, crypto.FromECDSA(bEphSecret), crypto.Keccak256([]byte("scripted-iv"))[:16], bNonce[:])
	if err != nil {
		t.Errorf("peer: ack: %v", err)
		return
	}
	if _, err := p.conn.Write(ackWire); err != nil {
		t.Errorf("peer: write ack: %v", err)
		return
	}

	// Responder-side secrets: the SAME channel secrets, with the nonce and
	// auth/ack-wire roles swapped (myotis-wire handshake.rs — the derivation
	// is symmetric over the two ephemerals; only the MAC seeding is
	// directional). The initiator ephemeral is the one recovered above.
	ephShared, err := rlpx.EcdhX(bEphSecret, aEph64)
	if err != nil {
		t.Errorf("peer: eph ecdh: %v", err)
		return
	}
	nonceHash := crypto.Keccak256(bNonce[:], aNonce) // the fixed pairing
	shared := crypto.Keccak256(ephShared[:], nonceHash)
	aesS := crypto.Keccak256(ephShared[:], shared)
	macS := crypto.Keccak256(ephShared[:], aesS)
	var aesA, macA, aN32, bN32 [32]byte
	copy(aesA[:], aesS)
	copy(macA[:], macS)
	copy(aN32[:], aNonce)
	copy(bN32[:], bNonce[:])
	secrets := &rlpx.SessionSecrets{
		AESSecret: aesA, MACSecret: macA,
		EgressNonce: bN32, IngressNonce: aN32, // responder view
		AuthWire: ackWire, AckWire: authWire,
	}
	codec, err := rlpx.NewFrameCodec(secrets)
	if err != nil {
		t.Errorf("peer: codec: %v", err)
		return
	}

	// --- framed exchange ---
	recv := func() *rlpx.DecodedFrame {
		head := make([]byte, 16)
		if _, err := io.ReadFull(p.conn, head); err != nil {
			return nil // teardown, not a verdict
		}
		headMac := make([]byte, 16)
		if _, err := io.ReadFull(p.conn, headMac); err != nil {
			return nil
		}
		n, err := codec.DecodeHeader(head, headMac)
		if err != nil {
			t.Errorf("peer: header MAC (byte orders diverged): %v", err)
			return nil
		}
		padded := n + (16-n%16)%16
		enc := make([]byte, padded)
		if _, err := io.ReadFull(p.conn, enc); err != nil {
			return nil
		}
		mac := make([]byte, 16)
		if _, err := io.ReadFull(p.conn, mac); err != nil {
			return nil
		}
		f, err := codec.DecodeBody(enc, mac, n)
		if err != nil {
			t.Errorf("peer: body MAC: %v", err)
			return nil
		}
		return f
	}
	send := func(code uint64, payload []byte) {
		if _, err := p.conn.Write(codec.EncodeFrame(code, payload)); err != nil {
			t.Errorf("peer: write frame %d: %v", code, err)
		}
	}

	if f := recv(); f == nil || f.MessageCode != ethwire.P2PHello {
		return
	}
	send(ethwire.P2PHello, p.hello())

	f := recv()
	if f == nil {
		return
	}
	if f.MessageCode != ethwire.StatusMsg {
		t.Errorf("peer: expected our Status, got 0x%02x", f.MessageCode)
		return
	}
	genesis := p.genesis
	if p.mangle {
		genesis = common.Hash{0xde}
	}
	send(ethwire.StatusMsg, ethwire.EncodeStatus(p.ethVersion, p.networkID, genesis,
		common.Hash{0xbb}, [4]byte{0x07, 0xc9, 0x46, 0x2e}, 0))

	// Answer one request (GetBlockHeaders, or whatever answerRequest
	// handles) — the hash/proof verification against a pin is the
	// caller's surface, exercised in the tests that set answerRequest.
	f = recv()
	if f == nil {
		return
	}
	if p.answerRequest != nil {
		p.answerRequest(f, send)
	} else {
		if f.MessageCode != ethwire.GetBlockHeaders {
			t.Errorf("peer: expected GetBlockHeaders, got 0x%02x", f.MessageCode)
			return
		}
		// Request is [reqId, [query…]]; echo the id back in [reqId, [header]].
		reqItems, err := rlpcode.Items(f.Payload)
		if err != nil || len(reqItems) < 2 {
			t.Errorf("peer: malformed GetBlockHeaders: %v", err)
			return
		}
		if q, err := rlpcode.Items(reqItems[1]); err != nil || len(q) != 4 {
			t.Errorf("peer: GetBlockHeaders query not nested 4-tuple: %v", err)
			return
		}
		send(ethwire.BlockHeaders, rlpcode.List(reqItems[0], rlpcode.List(rlpcode.Bytes([]byte{0xba, 0xbe}))))
	}

	// Post-handshake, the session's background reader must answer pings —
	// geth ping-timeout-drops silent clients, so a "READY" session that
	// ignores Ping is a lie that lasts ~90 s. This phase reads LOUDLY (with
	// a deadline and reported errors): the silent-teardown path above only
	// applies while the test's assertions are still ahead. The chain-gate
	// test runs without a pongDone: its dial fails at the gate, so by now
	// our side is closed and a Ping would only trip a spurious write error.
	if p.pongDone == nil {
		return
	}
	defer close(p.pongDone) // any exit path: the test's wait must not hang
	send(ethwire.P2PPing, []byte{0xc0})
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 16)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		t.Errorf("peer: ping unanswered (read: %v)", err)
		return
	}
	headMac := make([]byte, 16)
	io.ReadFull(p.conn, headMac)
	if n, err := codec.DecodeHeader(head, headMac); err == nil {
		padded := n + (16-n%16)%16
		enc := make([]byte, padded)
		io.ReadFull(p.conn, enc)
		mac := make([]byte, 16)
		io.ReadFull(p.conn, mac)
		if f, err := codec.DecodeBody(enc, mac, n); err == nil && f.MessageCode != ethwire.P2PPong {
			t.Errorf("peer: ping answered with code 0x%02x, want Pong", f.MessageCode)
		}
	}
}

func startScriptedListener(t *testing.T, mangle bool) (addr string, bKey *ecdsa.PrivateKey, pongDone chan struct{}, cleanup func()) {
	t.Helper()
	return startScriptedPeerListener(t, scriptedPeer{
		ethVersion: 68, networkID: 1,
		genesis: chain.Mainnet().GenesisHash,
		mangle:  mangle,
	}, !mangle)
}

func startScriptedPeerListener(t *testing.T, base scriptedPeer, wantPong bool) (addr string, bKey *ecdsa.PrivateKey, pongDone chan struct{}, cleanup func()) {
	t.Helper()
	bKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pongDone = make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		peer := base
		peer.t = t
		peer.conn = conn
		peer.key = bKey
		if wantPong {
			peer.pongDone = pongDone
		}
		peer.run()
	}()
	return ln.Addr().String(), bKey, pongDone, func() { ln.Close() }
}

func dialListener(t *testing.T, addr string, bKey *ecdsa.PrivateKey) (*Session, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	node := enode.NewV4(&bKey.PublicKey, net.ParseIP("127.0.0.1"), port, port)
	aKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Dial(ctx, Config{LocalKey: aKey, Network: chain.Mainnet(), Node: node})
}

func TestDialReachesReadyAndFetchesHeaders(t *testing.T) {
	addr, bKey, pongDone, lnCleanup := startScriptedListener(t, false)
	defer lnCleanup()
	sess, err := dialListener(t, addr, bKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	if sess.EthVersion != 68 {
		t.Fatalf("negotiated eth/%d", sess.EthVersion)
	}
	if sess.PeerStatus == nil || sess.PeerStatus.NetworkID != 1 {
		t.Fatalf("peer status %+v", sess.PeerStatus)
	}
	headers, err := sess.GetBlockHeadersByNumber(0, 1)
	if err != nil {
		t.Fatalf("get headers: %v", err)
	}
	// Items come back fully RLP-encoded (a real header's encoding IS the
	// header the hash is taken over) — the fake is the bytes 0xbabe, so its
	// item is 0x82 0xba 0xbe.
	if len(headers) != 1 || hex.EncodeToString(headers[0]) != "82babe" {
		t.Fatalf("headers = %x", headers)
	}
	// The scripted peer pings after the headers; the session's background
	// reader must answer with a Pong (the peer asserts it and closes
	// pongDone either way — a silent close without the answer reads as a
	// failed assertion on its side).
	select {
	case <-pongDone:
	case <-time.After(10 * time.Second):
		t.Fatal("session never answered the peer's post-handshake ping")
	}
}

func TestDialRejectsForeignChain(t *testing.T) {
	addr, bKey, _, lnCleanup := startScriptedListener(t, true)
	defer lnCleanup()
	sess, err := dialListener(t, addr, bKey)
	if err == nil {
		sess.Close()
		t.Fatal("a peer on another genesis must not reach READY")
	}
}

// TestSnapAccountRangeRoundTrip is the full-stack proof of the snap
// read path with no live network: the scripted peer advertises snap/1,
// the session negotiates the dynamic codes for eth/68, a GetAccountRange
// goes out on wire code 0x21, the answer arrives on 0x22 carrying a
// real single-leaf trie proof, and snapwire.VerifyAccount verifies it
// against the state root — proving transport routing, code derivation,
// the wire codec, and the trust anchor all agree on one connection.
func TestSnapAccountRangeRoundTrip(t *testing.T) {
	var address [20]byte
	copy(address[:], crypto.Keccak256([]byte("transport-test-account"))[:20])
	key := crypto.Keccak256Hash(address[:])
	var sroot, chash [32]byte
	copy(sroot[:], crypto.Keccak256([]byte("test-storage-root")))
	copy(chash[:], crypto.Keccak256([]byte("test-code")))
	leafValue := rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.Bytes([]byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}),
		rlpcode.Bytes(sroot[:]),
		rlpcode.Bytes(chash[:]),
	)
	compact := append([]byte{0x20}, key[:]...)
	node := rlpcode.List(rlpcode.Bytes(compact), rlpcode.Bytes(leafValue))
	stateRoot := crypto.Keccak256Hash(node)

	peer := scriptedPeer{
		ethVersion: 68, snapVersion: 1, networkID: 1,
		genesis: chain.Mainnet().GenesisHash,
	}
	peer.answerRequest = func(f *rlpx.DecodedFrame, send func(code uint64, payload []byte)) {
		// eth/68 → snap base 0x21: GetAccountRange in, AccountRange out.
		if f.MessageCode != 0x21 {
			t.Errorf("peer: expected GetAccountRange 0x21, got 0x%02x", f.MessageCode)
			return
		}
		reqItems, err := rlpcode.Items(f.Payload)
		if err != nil || len(reqItems) != 5 {
			t.Errorf("peer: malformed GetAccountRange: %v", err)
			return
		}
		if root, err := rlpcode.FixedBytes(reqItems[1], 32); err != nil || hex.EncodeToString(root) != hex.EncodeToString(stateRoot[:]) {
			t.Errorf("peer: request names a different state root: %x %v", root, err)
		}
		send(0x22, rlpcode.List(reqItems[0], rlpcode.List(), rlpcode.List(rlpcode.Bytes(node))))
	}

	addr, bKey, pongDone, lnCleanup := startScriptedPeerListener(t, peer, true)
	defer lnCleanup()
	sess, err := dialListener(t, addr, bKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	if !sess.HasSnap() || *sess.Snap != 1 {
		t.Fatalf("snap not negotiated: %v", sess.Snap)
	}

	ar, err := sess.GetAccountRange(stateRoot, key, [32]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}, 4096)
	if err != nil {
		t.Fatalf("GetAccountRange: %v", err)
	}
	out, err := snapwire.VerifyAccount(stateRoot, address, ar)
	if err != nil || out.Absent() {
		t.Fatalf("verify: %+v %v", out, err)
	}
	if out.Account.Nonce != 5 || out.Account.StorageRoot != sroot || out.Account.CodeHash != chash {
		t.Fatalf("verified account wrong: %+v", out.Account)
	}

	select {
	case <-pongDone:
	case <-time.After(10 * time.Second):
		t.Fatal("session never answered the peer's post-handshake ping")
	}
}

// TestSnapRequestWithoutCapability refuses instead of blocking: a
// session whose peer never advertised snap must fail fast (the read
// pool filters on HasSnap; this is the belt to those suspenders).
func TestSnapRequestWithoutCapability(t *testing.T) {
	addr, bKey, _, lnCleanup := startScriptedListener(t, false)
	defer lnCleanup()
	sess, err := dialListener(t, addr, bKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	if _, err := sess.GetAccountRange([32]byte{}, [32]byte{}, [32]byte{}, 4096); err == nil {
		t.Fatal("want refusal without a snap capability")
	}
}
