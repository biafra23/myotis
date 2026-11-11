package clsync

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestFullDuplexAnswer surface-tests ServeInstall over a REAL
// libp2p connection — the review of PR #769 was right that a
// request-only client never exercises the inbound Answer/serve path,
// and this test is the gap it named (extended in 3c to real-status
// byte-exactness). B plays the eth2 server (our handlers), A the
// dialing peer: status is exchanged, ping and metadata are answered
// with proper response framing, and the reply digests are checked.
func TestFullDuplexAnswer(t *testing.T) {
	srv, err := NewListeningHostForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := NewHost()
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ourDigest := [4]byte{0x8C, 0x9F, 0x62, 0xFE}
	ourStatus := &clwire.StatusMessage{
		ForkDigest:     ourDigest,
		FinalizedEpoch: 488000,
		HeadSlot:       15632000,
	}
	ServeInstall(srv, func() *clwire.StatusMessage { return ourStatus })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := cli.Connect(ctx, peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()}); err != nil {
		t.Fatal(err)
	}

	// Status: the reply must be proper response framing (result byte +
	// NO context bytes for status) carrying our digest.
	st, err := ExchangeStatus(ctx, cli, peer.AddrInfo{ID: srv.ID()}, ourStatus)
	if err != nil {
		t.Fatalf("status exchange: %v", err)
	}
	if st.ForkDigest != ourDigest || st.FinalizedEpoch != 488000 {
		t.Fatalf("status reply: %+v", st)
	}

	// Ping: the spec answers with a metadata seq number, framed.
	raw, err := Request(ctx, cli, peer.AddrInfo{ID: srv.ID()}, clwire.Ping,
		clwire.EncodeRequest([]byte{7, 0, 0, 0, 0, 0, 0, 0}), respTimeout)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	res, err := clwire.DecodeResponse(raw, false)
	if err != nil || len(res.Payload) != 8 || !bytes.Equal(res.Payload, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("ping reply: %v %x", err, res.Payload)
	}

	// Metadata v2: 17 zero bytes (no subscriptions), framed.
	raw, err = Request(ctx, cli, peer.AddrInfo{ID: srv.ID()}, clwire.MetadataV2,
		clwire.EncodeRequest(nil), respTimeout)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	res, err = clwire.DecodeResponse(raw, false)
	if err != nil || len(res.Payload) != 17 {
		t.Fatalf("metadata reply: %v len=%d", err, len(res.Payload))
	}

}
