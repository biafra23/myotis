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
		// eth2 servers answer identify under the id "eth2/1.0.0", not
		// /ipfs/0.1.0 — go-libp2p's default identify would block every
		// Connect waiting for an answer that never comes (roost and
		// Lighthouse alike, docs/spec/01 §10.1). The 3c Identify
		// protocol-id work restores the LC-server discovery it feeds.
		libp2p.DisableIdentifyAddressDiscovery(),
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
	for _, p := range []string{"/meshsub/1.1.0", "/meshsub/1.2.0-noselect", "/fish/1.0.0"} {
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
func ServeInstall(h host.Host, statusFunc func() *clwire.StatusMessage) {
	answer := func(proto string, handler func(req []byte) []byte) {
		h.SetStreamHandler(protocol.ID(proto), func(s network.Stream) {
			defer s.Reset()
			_ = s.SetDeadline(time.Now().Add(respTimeout))
			req, err := readAllCapped(s, 1<<20)
			if err != nil {
				return
			}
			ssz, err := parseRequestSsz(req)
			if err != nil {
				return
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
	answer(clwire.Goodbye, func([]byte) []byte { return nil })
}

// parseRequestSsz decodes an inbound request body (varint || frames)
// with no expected-length pin (we answer several protocols here). A
// bare 0x00 is the ENCODING of an empty request (varint(0), no snappy
// data — metadata/ping carry none), not a malformed one: rejecting it
// stream-reset us in the eyes of any peer that asks politely.
func parseRequestSsz(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, clwire.ErrCodec
	}
	if len(raw) == 1 && raw[0] == 0x00 {
		return nil, nil
	}
	if len(raw) < 2 {
		return nil, clwire.ErrCodec
	}
	declared, start, err := clwire.ReadVarint(raw, 0)
	if err != nil || declared == 0 || start >= len(raw) {
		return nil, clwire.ErrCodec
	}
	return clwire.DecompressFramed(raw[start:], int(declared))
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

// Request opens one req/resp stream, writes the framed request (nil =
// write nothing: the finality/optimistic protocols half-close with no
// bytes), half-closes, and reads the response to EOF under the timeout.
// It dials first when not connected.
func Request(ctx context.Context, h host.Host, info peer.AddrInfo, proto string, req []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if h.Network().Connectedness(info.ID) != network.Connected {
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
	return readAllCapped(s, maxResponseBytes)
}

func readAllCapped(r io.Reader, cap int) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, int64(cap)+1))
	if err != nil {
		return nil, err
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
		libp2p.DisableIdentifyAddressDiscovery(),
	)
}
