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

	ethVersion uint64
	networkID  uint64
	genesis    common.Hash
	mangle     bool // reply a wrong genesis to exercise the chain gate
}

// peerHello hand-builds a Hello advertising only eth/<version> — the wire
// shape without reusing our own capability list.
func (p *scriptedPeer) hello() []byte {
	cap := rlpcode.List(rlpcode.String("eth"), rlpcode.Uint(p.ethVersion))
	return rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.String("scripted-peer/0"),
		rlpcode.List(cap),
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
	bEphSecret, err := crypto.HexToECDSA("e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4")
	if err != nil {
		t.Fatal(err)
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

	// Answer one GetBlockHeaders with a single trivial "header" (the hash
	// verification against a pin is part 4's surface).
	f = recv()
	if f == nil {
		return
	}
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

func startScriptedListener(t *testing.T, mangle bool) (addr string, bKey *ecdsa.PrivateKey, cleanup func()) {
	t.Helper()
	bKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		(&scriptedPeer{
			t: t, conn: conn, key: bKey,
			ethVersion: 68, networkID: 1,
			genesis: chain.Mainnet().GenesisHash,
			mangle:  mangle,
		}).run()
	}()
	return ln.Addr().String(), bKey, func() { ln.Close() }
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
	addr, bKey, lnCleanup := startScriptedListener(t, false)
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
}

func TestDialRejectsForeignChain(t *testing.T) {
	addr, bKey, lnCleanup := startScriptedListener(t, true)
	defer lnCleanup()
	sess, err := dialListener(t, addr, bKey)
	if err == nil {
		sess.Close()
		t.Fatal("a peer on another genesis must not reach READY")
	}
}
