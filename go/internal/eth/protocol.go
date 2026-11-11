// Package eth speaks the eth/66-68 sub-protocol over RLPx: the Hello/Status
// handshake with the pinned fork id, request-id correlated GetBlockHeaders,
// and the polite-empty answers to inbound requests that keep peers from
// dropping us (docs/spec/02-execution-networking.md §5-6).
//
// eth/69-71 are deliberately not negotiated yet: the Status/headers layout
// they keep is identical to 68's for everything this engine sends, and what
// they add (BlockRangeUpdate serving, bloomless receipts, BALs) matters only
// once snap reads and receipts land — until then 68 is the highest version
// whose full behavior we implement on both directions.
package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// p2p-level message codes.
const (
	msgHello      uint64 = 0x00
	msgDisconnect uint64 = 0x01
	msgPing       uint64 = 0x02
	msgPong       uint64 = 0x03
)

// eth message codes, absolute. We advertise eth as the only capability, so
// the base is 0x10 with eth offset 0 (docs/spec/02 §6.3).
const (
	msgStatus            = 0x10
	msgNewBlockHashes    = 0x11
	msgTransactions      = 0x12
	msgGetBlockHeaders   = 0x13
	msgBlockHeaders      = 0x14
	msgGetBlockBodies    = 0x15
	msgBlockBodies       = 0x16
	msgNewBlock          = 0x17
	msgNewPooledTxHashes = 0x18
	msgGetPooledTxs      = 0x19
	msgPooledTxs         = 0x1a
	msgGetReceipts       = 0x1f
	msgReceipts          = 0x20
)

// Supported eth versions, ascending as the Hello capability list requires.
var supportedEthVersions = []uint{66, 67, 68}

// forkIDRLP is the EIP-2124 [hash, next] pair inside Status.
type forkIDRLP struct {
	Hash [4]byte
	Next uint64
}

// HighestCommon returns the highest eth version both sides offer (0 = none).
// A peer offering only eth/69+ is usable at its 66-68 entry too — geth and
// Nethermind all still advertise those.
func HighestCommon(peerVersions []uint) uint {
	var best uint
	for _, v := range peerVersions {
		if v > best && v <= 68 && v >= 66 {
			best = v
		}
	}
	return best
}

// Disconnect reasons we use — geth's DiscReason table (p2p/peer_error.go);
// geth's eth handler drops failed-status peers with DiscUselessPeer, which is
// what we do too.
const (
	discQuit           = 0x00 // "disconnect requested"
	discUselessPeer    = 0x03 // status validation failures (geth's choice)
	discSubprotocolErr = 0x10
)

type capPair struct {
	Name    string
	Version uint
}

type helloMsg struct {
	Capability   uint32
	ClientID     string
	Capabilities []capPair
	ListenPort   uint16
	NodeID       [64]byte
}

// status68 is the eth/66-68 Status. Post-Merge TD carries no meaning; we
// send zero (geth and Nethermind do the same) and keep whatever we receive
// unparsed — some peers still put a TD-shaped integer there.
type status68 struct {
	Version   uint32
	NetworkID uint64
	TD        rlp.RawValue
	BestHash  common.Hash
	Genesis   common.Hash
	ForkID    forkIDRLP
}

// PeerStatus is what we keep from a peer's Status.
type PeerStatus struct {
	Version   uint32
	NetworkID uint64
	BestHash  common.Hash
	Genesis   common.Hash
	ForkHash  [4]byte
	ForkNext  uint64
}

// getBlockHeaders66: [reqId, [origin, amount, skip, reverse]]. origin is a
// block number (RLP integer) or a 32-byte hash.
type getBlockHeaders66 struct {
	ReqID uint64
	Query headerQuery
}

type headerQuery struct {
	Origin  rlp.RawValue
	Amount  uint32
	Skip    uint32
	Reverse bool
}
