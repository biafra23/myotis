// Package ethwire holds the p2p base and `eth` sub-protocol messages the Go
// engine speaks: Hello with capability advertisement and negotiation, and the
// eth/66-69 Status with its fork id. It is the twin of myotis-wire's
// rlpx/hello.rs and eth.rs (docs/spec/02 §5.4, §6) — same wire shapes, same
// acceptance rules.
package ethwire

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/biafra23/myotis/go/internal/rlpcode"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// p2p base message codes.
const (
	P2PHello      uint64 = 0x00
	P2PDisconnect uint64 = 0x01
	P2PPing       uint64 = 0x02
	P2PPong       uint64 = 0x03
)

// eth sub-protocol message codes (absolute: 0x10 + sub-code, per the
// Request/Response multiplexing of eth/66+). Only the subset the verified
// read path needs is named; the rest are decoded-and-skipped.
const (
	StatusMsg          uint64 = 0x10
	GetBlockHeaders    uint64 = 0x13
	BlockHeaders       uint64 = 0x14
	BlockRangeUpdate69 uint64 = 0x21
)

// ClientID is the identity our Hello advertises. The Rust engine derives its
// id from the workspace version (myotis/<ver>); the Go module has no version
// pin yet, so the id names the engine without one until release tooling
// covers go/ (a version here that drifts would lie to peers).
const ClientID = "myotis/go"

// Our advertised eth versions (highest-common wins, floor 66) and snap
// versions, mirroring the Rust engine's OUR_ETH_VERSIONS / OUR_SNAP_VERSIONS.
var (
	OurEthVersions         = []uint64{66, 67, 68, 69, 70, 71}
	OurSnapVersions        = []uint64{1, 2}
	MinEthVersion   uint64 = 66
)

// Capability is one advertised (name, version) pair from a peer Hello.
type Capability struct {
	Name    string
	Version uint64
}

// Hello is a decoded p2p Hello.
type Hello struct {
	ProtocolVersion uint64
	ClientID        string
	Capabilities    []Capability
	ListenPort      uint64
	NodeID          []byte
}

// EncodeHello builds our Hello body advertising eth/66-71 + snap/1 + snap/2
// (ascending), protocol version 5, listening on listenPort with nodePubkey
// (64-byte, no prefix).
func EncodeHello(nodePubkey64 []byte, listenPort uint16) []byte {
	caps := make([]rlp.RawValue, 0, 8)
	for _, v := range OurEthVersions {
		caps = append(caps, rlpcode.List(rlpcode.String("eth"), rlpcode.Uint(v)))
	}
	for _, v := range OurSnapVersions {
		caps = append(caps, rlpcode.List(rlpcode.String("snap"), rlpcode.Uint(v)))
	}
	return rlpcode.List(
		rlpcode.Uint(5),
		rlpcode.String(ClientID),
		rlpcode.List(caps...),
		rlpcode.Uint(uint64(listenPort)),
		rlpcode.Bytes(nodePubkey64),
	)
}

// maxControlMsgSize mirrors rlpx.MaxFrame's cap for tree-decoded control
// messages (#454): a 10 MiB Hello could cost ~0.5 GB to decode, real ones
// are a few hundred bytes. (Declared here, not imported from rlpx, to keep
// ethwire free of a transport dependency.)
const maxControlMsgSize = 16 * 1024

// DecodeHello parses a peer Hello. Oversized Hellos are refused before their
// tree is walked.
func DecodeHello(body []byte) (*Hello, error) {
	if len(body) > maxControlMsgSize {
		return nil, fmt.Errorf("hello: %d bytes over the %d-byte control cap", len(body), maxControlMsgSize)
	}
	items, err := rlpcode.Items(body)
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}
	if len(items) < 5 {
		return nil, fmt.Errorf("hello: expected 5 fields, got %d", len(items))
	}
	h := &Hello{}
	if h.ProtocolVersion, err = rlpcode.U64(items[0]); err != nil {
		return nil, fmt.Errorf("hello: protocol version: %w", err)
	}
	id, err := rlpcode.LeafBytes(items[1])
	if err != nil {
		return nil, fmt.Errorf("hello: client id: %w", err)
	}
	h.ClientID = lossyUTF8(id)
	// items[] entries are full item encodings, which is what Items() walks.
	caps, err := rlpcode.Items(items[2])
	if err != nil {
		return nil, fmt.Errorf("hello: capabilities: %w", err)
	}
	for _, c := range caps {
		fields, err := rlpcode.Items(c)
		if err != nil {
			return nil, fmt.Errorf("hello: capability: %w", err)
		}
		if len(fields) < 2 {
			continue
		}
		name, err := rlpcode.LeafBytes(fields[0])
		if err != nil {
			return nil, fmt.Errorf("hello: capability name: %w", err)
		}
		ver, err := rlpcode.U64(fields[1])
		if err != nil {
			return nil, fmt.Errorf("hello: capability version: %w", err)
		}
		h.Capabilities = append(h.Capabilities, Capability{Name: lossyUTF8(name), Version: ver})
	}
	if h.ListenPort, err = rlpcode.U64(items[3]); err != nil {
		return nil, fmt.Errorf("hello: listen port: %w", err)
	}
	if h.NodeID, err = rlpcode.LeafBytes(items[4]); err != nil {
		return nil, fmt.Errorf("hello: node id: %w", err)
	}
	return h, nil
}

// Negotiate returns the highest common eth version (floor 66) and the highest
// common snap version (nil when the peer has neither snap/1 nor snap/2). RLPx
// runs one version per capability name — the highest both sides advertise —
// so a peer offering snap/1 and snap/2 is a snap/2 session, and a
// snap/2-only peer (reth implements no snap/1) is not mistaken for one
// without snap. Returns nil eth when there is no usable eth version.
func Negotiate(h *Hello) (eth uint64, snap *uint64, ok bool) {
	for _, c := range h.Capabilities {
		if c.Name == "eth" && contains(OurEthVersions, c.Version) && c.Version >= MinEthVersion {
			if !ok || c.Version > eth {
				eth = c.Version
			}
			ok = true
		}
		if c.Name == "snap" && contains(OurSnapVersions, c.Version) {
			if snap == nil || c.Version > *snap {
				v := c.Version
				snap = &v
			}
		}
	}
	return eth, snap, ok
}

func contains(set []uint64, v uint64) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

// Status is a decoded eth Status. eth/67-68 carries the (post-Merge empty)
// total difficulty and a best hash; eth/69 replaces td with the servable
// block range (EIP-7642).
type Status struct {
	ProtocolVersion uint64
	NetworkID       uint64
	GenesisHash     common.Hash
	// BestHash is the peer's best block hash (eth/67-68) or its latest-block
	// hash (eth/69).
	BestHash      common.Hash
	ForkIDHash    [4]byte
	ForkNext      uint64
	LatestBlock   *uint64 // eth/69 only
	EarliestBlock *uint64 // eth/69 only
}

// EncodeStatus builds our Status for eth/67-68:
// [version, networkId, td(empty), bestHash, genesisHash, [forkHash, forkNext]]
// — post-Merge td is empty, and a light client may send genesis as bestHash
// (peers gate on the fork id, not it).
func EncodeStatus(ethVersion, networkID uint64, genesisHash, bestHash common.Hash, forkIDHash [4]byte, forkNext uint64) []byte {
	return rlpcode.List(
		rlpcode.Uint(ethVersion),
		rlpcode.Uint(networkID),
		rlpcode.Bytes(nil), // td = empty (post-Merge)
		rlpcode.Bytes(bestHash.Bytes()),
		rlpcode.Bytes(genesisHash.Bytes()),
		rlpcode.List(rlpcode.Bytes(forkIDHash[:]), rlpcode.Uint(forkNext)),
	)
}

// EncodeStatus69 builds our Status for eth/69 (EIP-7642):
// [version, networkId, genesis, [forkHash, forkNext], earliest, latest,
// latestHash]. The range is a promise of what we can SERVE — a peer probing
// a block we claim must get it — so a light client with no held headers
// advertises the [0, 0] genesis-only window.
func EncodeStatus69(ethVersion, networkID uint64, genesisHash, latestBlockHash common.Hash, forkIDHash [4]byte, forkNext, earliestBlock, latestBlock uint64) []byte {
	return rlpcode.List(
		rlpcode.Uint(ethVersion),
		rlpcode.Uint(networkID),
		rlpcode.Bytes(genesisHash.Bytes()),
		rlpcode.List(rlpcode.Bytes(forkIDHash[:]), rlpcode.Uint(forkNext)),
		rlpcode.Uint(earliestBlock),
		rlpcode.Uint(latestBlock),
		rlpcode.Bytes(latestBlockHash.Bytes()),
	)
}

// DecodeStatus parses a peer Status; ethVersion >= 69 selects the eth/69
// layout.
func DecodeStatus(body []byte, ethVersion uint64) (*Status, error) {
	if len(body) > maxControlMsgSize {
		return nil, fmt.Errorf("status: %d bytes over the %d-byte control cap", len(body), maxControlMsgSize)
	}
	items, err := rlpcode.Items(body)
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	s := &Status{}
	switch {
	case ethVersion >= 69:
		// [version, networkId, genesis, forkId, earliest, latest, latestHash]
		if len(items) < 7 {
			return nil, fmt.Errorf("status: too few fields (%d) for eth/%d", len(items), ethVersion)
		}
		if s.ProtocolVersion, err = rlpcode.U64(items[0]); err != nil {
			return nil, fmt.Errorf("status: version: %w", err)
		}
		if s.NetworkID, err = rlpcode.U64(items[1]); err != nil {
			return nil, fmt.Errorf("status: networkId: %w", err)
		}
		if s.GenesisHash, err = hashItem(items[2]); err != nil {
			return nil, fmt.Errorf("status: genesis: %w", err)
		}
		if err = decodeForkID(items[3], s); err != nil {
			return nil, err
		}
		earliest, err := rlpcode.U64(items[4])
		if err != nil {
			return nil, fmt.Errorf("status: earliest: %w", err)
		}
		latest, err := rlpcode.U64(items[5])
		if err != nil {
			return nil, fmt.Errorf("status: latest: %w", err)
		}
		if s.BestHash, err = hashItem(items[6]); err != nil {
			return nil, fmt.Errorf("status: latestHash: %w", err)
		}
		s.EarliestBlock, s.LatestBlock = &earliest, &latest
	default:
		// [version, networkId, td, bestHash, genesis, forkId]; forkId is
		// MANDATORY for eth/66+ (EIP-2124), so require all 6 fields.
		if len(items) < 6 {
			return nil, fmt.Errorf("status: too few fields (%d) for eth/%d", len(items), ethVersion)
		}
		if s.ProtocolVersion, err = rlpcode.U64(items[0]); err != nil {
			return nil, fmt.Errorf("status: version: %w", err)
		}
		if s.NetworkID, err = rlpcode.U64(items[1]); err != nil {
			return nil, fmt.Errorf("status: networkId: %w", err)
		}
		if s.BestHash, err = hashItem(items[3]); err != nil {
			return nil, fmt.Errorf("status: bestHash: %w", err)
		}
		if s.GenesisHash, err = hashItem(items[4]); err != nil {
			return nil, fmt.Errorf("status: genesis: %w", err)
		}
		if err = decodeForkID(items[5], s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func decodeForkID(item []byte, s *Status) error {
	fork, err := rlpcode.Items(item)
	if err != nil {
		return fmt.Errorf("status: forkId: %w", err)
	}
	if len(fork) < 1 {
		return errors.New("status: empty forkId")
	}
	// EIP-2124: the fork hash is EXACTLY 4 bytes (CRC32). Anything else is a
	// malformed peer, not a different chain.
	b, err := rlpcode.FixedBytes(fork[0], 4)
	if err != nil {
		return fmt.Errorf("status: forkId hash: %w", err)
	}
	copy(s.ForkIDHash[:], b)
	if len(fork) >= 2 {
		if s.ForkNext, err = rlpcode.U64(fork[1]); err != nil {
			return fmt.Errorf("status: forkId next: %w", err)
		}
	}
	return nil
}

// Compatible is the network gate: same network id AND genesis
// (docs/spec/02 §6.4). A mismatch means the peer is on another chain; it is
// dropped, never trusted.
func (s *Status) Compatible(networkID uint64, genesis common.Hash) bool {
	return s.NetworkID == networkID && s.GenesisHash == genesis
}

// EncodeGetBlockHeadersByHash builds eth/66+ GetBlockHeaders (0x13):
// [requestId, [originHash, amount, skip, reverse]]. The query is a NESTED
// list (geth's RLPx-packet wrapping; a flat query makes geth answer
// BreachOfProtocol — measured live): the origin is a hash iff exactly
// 32 bytes, a number if minimal-BE ≤ 8.
func EncodeGetBlockHeadersByHash(requestID uint64, origin common.Hash, amount uint64, skip uint64, reverse bool) []byte {
	return encodeGetHeaders(requestID, rlpcode.Bytes(origin.Bytes()), amount, skip, reverse)
}

// EncodeGetBlockHeadersByNumber builds the by-number origin form.
func EncodeGetBlockHeadersByNumber(requestID, origin, amount, skip uint64, reverse bool) []byte {
	return encodeGetHeaders(requestID, rlpcode.Uint(origin), amount, skip, reverse)
}

func encodeGetHeaders(requestID uint64, origin rlp.RawValue, amount, skip uint64, reverse bool) []byte {
	return rlpcode.List(
		rlpcode.Uint(requestID),
		rlpcode.List(origin, rlpcode.Uint(amount), rlpcode.Uint(skip), rlpcode.Uint(b2u(reverse))),
	)
}

// DecodeBlockHeaders parses a BlockHeaders (0x14) response:
// [requestId, [rawHeaderRLP…]], returning the request id and the raw headers.
// Each header's own hash is the caller's to verify (that is part 4's job).
func DecodeBlockHeaders(body []byte) (requestID uint64, headers [][]byte, err error) {
	items, err := rlpcode.Items(body)
	if err != nil {
		return 0, nil, fmt.Errorf("block headers: %w", err)
	}
	if len(items) < 2 {
		return 0, nil, fmt.Errorf("block headers: too few fields (%d)", len(items))
	}
	if requestID, err = rlpcode.U64(items[0]); err != nil {
		return 0, nil, fmt.Errorf("block headers: request id: %w", err)
	}
	if headers, err = rlpcode.Items(items[1]); err != nil {
		return 0, nil, fmt.Errorf("block headers: list: %w", err)
	}
	return requestID, headers, nil
}

// DescribeDisconnect renders a Disconnect payload for logs.
func DescribeDisconnect(payload []byte) string {
	items, err := rlpcode.Items(payload)
	if err != nil || len(items) == 0 {
		return "reason ?"
	}
	reason, err := rlpcode.U64(items[0])
	if err != nil {
		return "reason ?"
	}
	name := map[uint64]string{
		0x00: "Quit", 0x01: "TCPSubsystemError", 0x02: "BreachOfProtocol",
		0x03: "UselessPeer", 0x04: "TooManyPeers", 0x05: "AlreadyConnected",
		0x06: "IncompatibleVersion", 0x07: "InvalidIdentity",
		0x08: "ClientQuotaExceeded", 0x09: "Disconnected",
		0x0a: "SubscribeSubprotocolSent", 0x10: "WantedToDialButMissingInHello",
	}[reason]
	if name == "" {
		name = "Unknown"
	}
	return fmt.Sprintf("reason 0x%02x (%s)", reason, name)
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func hashItem(item []byte) (common.Hash, error) {
	b, err := rlpcode.FixedBytes(item, 32)
	var h common.Hash
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

func lossyUTF8(b []byte) string {
	if !utf8.Valid(b) {
		// Debug-escape: peer-controlled text reaching host log drains must not
		// forge log lines (the Rust twin Debug-escapes client_id for this).
		return fmt.Sprintf("%q", b)
	}
	return string(b)
}
