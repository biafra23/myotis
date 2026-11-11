package clsync

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

// Timeouts ported from the Rust twin (reqresp.rs): 10 s for a
// single-chunk response, 60 s for a paced multi-chunk batch.
const (
	respTimeout    = 10 * time.Second
	updatesTimeout = 60 * time.Second
	dialTimeout    = 10 * time.Second

	// maxResponseBytes caps the read; the codec caps the DECOMPRESSED
	// payload separately (clwire.MaxUncompressedPayload).
	maxResponseBytes = 16 * 1024 * 1024
)

// NewHost builds the eth2-shaped libp2p host: ephemeral secp256k1
// identity, TCP + Noise XX + yamux, no listen address (outbound-only
// light client). QUIC, mplex (Nimbus) and the inbound meshsub/custody
// extras are documented part-3c follow-ups — the static set this engine
// dials (roost + Lighthouse pins) negotiates TCP+noise+yamux.
func NewHost() (host.Host, error) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	if err != nil {
		return nil, err
	}
	return libp2p.New(
		libp2p.Identity(priv),
		libp2p.NoListenAddrs,
		libp2p.NoTransports,
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		// Identify KEEPS RUNNING on this host (PR #770 review: the
		// option below does not stop it) — but it identifies us the way
		// the Rust twin does: "eth2/1.0.0" is the protocol_version
		// FIELD of the Identify message (identify::Config::new,
		// reqresp.rs:364-365), not a protocol id. Without this we
		// advertise the go-libp2p default "ipfs/0.1.0" to every eth2
		// peer, which is exactly the wrong-fork flag their peer
		// scoring looks at.
		libp2p.ProtocolVersion("eth2/1.0.0"),
		libp2p.UserAgent("myotis-go"),
		// No observed-address discovery at all: an outbound-only
		// dialer with explicit pinned addresses has no use for
		// ObservedAddr feedback. (The first version of this host had
		// DisableIdentifyAddressDiscovery() as a workaround for a
		// "remote sent go away" after Status; the PR #770 review read
		// the option's source — it only stops the ObservedAddr
		// consumer, nothing that can stall a dial — and a live smoke
		// without it passed, confirming the real fix was the
		// InstallGossipSubHold below. The LC-server peer tier that
		// identify's protocol lists feed is 3c work, docs/spec/01
		// §10.1.)
	)
}

// InstallGossipSubHold answers /meshsub/1.1.0 streams by holding them
// open and discarding traffic: Lighthouse opens a gossip stream at
// EVERY peer after the status exchange and scores a refused
// negotiation as grounds for a Goodbye — the reason a pure
// req/resp-only peer gets "remote sent go away" one second after
// Status. Holding the stream costs a goroutine and zero subscriptions
// (same posture as Rust's gossipsub with no subscriptions).
func InstallGossipSubHold(h host.Host) {
	// The three ids a rust-libp2p gossipsub peer offers
	// (libp2p-gossipsub-0.49.5/src/protocol.rs:47-56 — Lighthouse's
	// stack); multistream will negotiate whichever the opener prefers.
	for _, p := range []string{"/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0"} {
		h.SetStreamHandler(protocol.ID(p), func(s network.Stream) {
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := s.Read(buf); err != nil {
						_ = s.Reset()
						return
					}
				}
			}()
		})
	}
}

// ServeInstall registers the minimal inbound surface so a peer's
// mandatory requests (status/ping/metadata/goodbye) get an answer
// instead of a protocol rejection, which Lighthouse scores against us.
// statusFunc supplies our live Status (digest of the wall clock,
// finalized header from the store); nil answers with nothing (close).
//
// The request body is handled per the Rust twin's table
// (respond_inbound, reqresp.rs:2061-2075): a protocol whose expected
// size is 0 (metadata) has its body NOT parsed at all — which is also
// why an empty request never trips us, whatever framing the peer chose
// — and a body that fails the pinned-size decode is answered with an
// InvalidRequest error chunk, not a silent stream reset (a reset is
// the "answered nothing" signal we ourselves treat as failure).
func ServeInstall(h host.Host, statusFunc func() *clwire.StatusMessage) {
	answer := func(proto string, handler func(req []byte) []byte) {
		expected := clwire.ExpectedRequestSize(proto)
		h.SetStreamHandler(protocol.ID(proto), func(s network.Stream) {
			defer s.Reset()
			_ = s.SetDeadline(time.Now().Add(respTimeout))
			req, err := readAllCapped(s, 1<<20)
			if err != nil {
				return
			}
			var ssz []byte
			if expected > 0 {
				ssz, err = clwire.ParseRequestSszExpecting(req, expected)
				if err != nil {
					_, _ = s.Write(clwire.EncodeErrorResponse(clwire.ResultInvalidRequest,
						"InvalidRequest: unparseable body"))
					_ = s.Close()
					return
				}
			}
			if resp := handler(ssz); resp != nil {
				// status/ping/metadata responses carry NO context bytes.
				if _, err := s.Write(clwire.EncodeSuccessResponse(resp, nil)); err != nil {
					return
				}
			}
			_ = s.Close()
		})
	}
	v2 := func(trimV1 bool) func([]byte) []byte {
		return func([]byte) []byte {
			if statusFunc == nil {
				return nil
			}
			m := statusFunc()
			if m == nil {
				return nil
			}
			if trimV1 {
				return m.EncodeV1()
			}
			return m.Encode()
		}
	}
	answer(clwire.StatusV2, v2(false))
	answer(clwire.StatusV1, v2(true))
	// ping is answered with our metadata seq number: 0, because a light
	// client's metadata (no attnets, no syncnets) never changes.
	answer(clwire.Ping, func([]byte) []byte { return []byte{0, 0, 0, 0, 0, 0, 0, 0} })
	answer(clwire.MetadataV2, func([]byte) []byte { return clwire.MetadataV2LightClient() })
	answer(clwire.MetadataV3, func([]byte) []byte {
		// custody_group_count = CUSTODY_REQUIREMENT (4), the value
		// Lighthouse insists on (status.rs:93-108).
		return append(clwire.MetadataV2LightClient(), 4, 0, 0, 0, 0, 0, 0, 0)
	})
	// Goodbye: the request_response machinery expects a response, and
	// the Rust twin answers by echoing the reason (reqresp.rs:2114-2124,
	// "the caller of this function disconnects the peer"). Answering
	// with nothing is the same "answered nothing" a reset would be.
	answer(clwire.Goodbye, func(req []byte) []byte {
		body := make([]byte, 8)
		if len(req) == 8 {
			copy(body, req)
		}
		return body
	})
}

// ExchangeStatus performs the mandatory first Status exchange on a
// fresh connection (§13.6). WE send ours first — the Rust twin does the
// same on ConnectionEstablished (reqresp.rs:1680-1688), and Lighthouse
// answers an empty status request with an empty stream — v2 first with
// a v1 fallback on UnsupportedProtocol. The reply's digest is checked
// against ours (a mismatch = wrong-fork peer, dropped before any
// light-client request) and earliest_available_slot is returned for
// the caller's skip heuristic.
func ExchangeStatus(ctx context.Context, h host.Host, info peer.AddrInfo, ours *clwire.StatusMessage) (clwire.StatusMessage, error) {
	var zero clwire.StatusMessage
	var lastErr error
	for _, proto := range []string{clwire.StatusV2, clwire.StatusV1} {
		req := clwire.EncodeRequest(ours.Encode())
		if proto == clwire.StatusV1 {
			req = clwire.EncodeRequest(ours.EncodeV1())
		}
		resp, err := Request(ctx, h, info, proto, req, respTimeout)
		if err != nil {
			lastErr = err
			continue // protocol not negotiated → try the older version
		}
		res, err := clwire.DecodeResponse(resp, false)
		if err != nil {
			lastErr = err
			continue
		}
		st, err := clwire.DecodeStatus(res.Payload)
		if proto == clwire.StatusV1 {
			st, err = clwire.DecodeStatusV1(res.Payload)
		}
		if err != nil {
			return zero, err
		}
		if st.ForkDigest != ours.ForkDigest {
			return zero, fmt.Errorf("clsync: peer %s fork digest %x != ours %x (wrong-fork peer)",
				info.ID, st.ForkDigest, ours.ForkDigest)
		}
		return st, nil
	}
	return zero, fmt.Errorf("clsync: status exchange failed with %s: %w", info.ID, lastErr)
}

// Request opens one req/resp stream, dials first when not connected,
// writes the framed request (nil = write nothing: the finality/
// optimistic protocols half-close with no bytes), half-closes, and
// reads the response. This is the variant the Status exchange uses —
// the one place this engine dials.
func Request(ctx context.Context, h host.Host, info peer.AddrInfo, proto string, req []byte, timeout time.Duration) ([]byte, error) {
	return request(ctx, h, info, proto, req, timeout, true)
}

// RequestOnConn is Request with dialing switched off (WithNoDial):
// for the light-client protocols, which must ride the connection the
// Status exchange established. A silently-dropped connection then
// surfaces as an error (caller moves to the next peer) instead of a
// silent re-dial putting a light-client request FIRST on the fresh
// connection — the exact sequence the relevance policy punishes.
//
// A read that fails mid-response returns the bytes already buffered
// alongside the error. Lighthouse paces multi-chunk answers ~10 s
// apart (the Rust twin's read_until_quiet exists for exactly this,
// reqresp.rs:41-72), so a deadline or reset partway through a batch
// is ordinary service, and the chunks that arrived are what
// DecodeMultiChunk's truncated-tail salvage was ported to keep.
func RequestOnConn(ctx context.Context, h host.Host, info peer.AddrInfo, proto string, req []byte, timeout time.Duration) ([]byte, error) {
	return request(ctx, h, info, proto, req, timeout, false)
}

func request(ctx context.Context, h host.Host, info peer.AddrInfo, proto string, req []byte, timeout time.Duration, dial bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !dial {
		ctx = network.WithNoDial(ctx, "clsync: only the Status exchange dials")
	}
	if h.Network().Connectedness(info.ID) != network.Connected {
		if !dial {
			return nil, fmt.Errorf("clsync: peer %s not connected", info.ID)
		}
		dialCtx, dcancel := context.WithTimeout(ctx, dialTimeout)
		defer dcancel()
		if err := h.Connect(dialCtx, info); err != nil {
			return nil, err
		}
	}
	s, err := h.NewStream(ctx, info.ID, protocol.ID(proto))
	if err != nil {
		return nil, err
	}
	defer s.Reset()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if req != nil {
		if _, err := s.Write(req); err != nil {
			return nil, err
		}
	}
	if err := s.CloseWrite(); err != nil {
		return nil, err
	}
	out, err := readAllCapped(s, maxResponseBytes)
	if err != nil {
		return out, err // partial kept; the caller decides what to salvage
	}
	// Close cleanly on success — a fully-served request must not end in
	// an RST_STREAM (the deferred Reset is the failure path only; the
	// responder half of this very file has always closed properly).
	_ = s.Close()
	return out, nil
}

func readAllCapped(r io.Reader, cap int) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, int64(cap)+1))
	if err != nil {
		// io.ReadAll hands back what it buffered with the error — pass it
		// through; discarding it is what made the salvage unreachable.
		return out, err
	}
	if len(out) > cap {
		return nil, fmt.Errorf("clsync: response exceeds %d bytes", cap)
	}
	return out, nil
}

// NewListeningHostForTest is NewHost with a loopback listener, so two
// in-process hosts can actually connect (both production hosts are
// outbound-only; this exists for the full-duplex surface test).
func NewListeningHostForTest() (host.Host, error) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	if err != nil {
		return nil, err
	}
	return libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.NoTransports,
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
	)
}
