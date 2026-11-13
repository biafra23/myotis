// Package nodekey owns the node's persistent secp256k1 identity, mirroring
// the other engines' NodeKey (docs/spec/02 §1.1): the secret is stored as a
// 64-hex-char file, and the node id is keccak256 of the 64-byte uncompressed
// public key without the 0x04 prefix.
package nodekey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

const fileName = "nodekey"

// Load reads the node key from dir/nodekey, generating and persisting a fresh
// one when the file does not exist yet.
func Load(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, fileName)

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate node key: %w", err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
		secret := hexEncode(crypto.FromECDSA(key))
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("persist node key: %w", err)
		}
		return key, nil
	case err != nil:
		return nil, fmt.Errorf("read node key: %w", err)
	}

	raw := strings.TrimSpace(string(data))
	secret, err := hexDecode(raw)
	if err != nil {
		return nil, fmt.Errorf("node key %s is not 64 hex chars: %w", path, err)
	}
	key, err := crypto.ToECDSA(secret)
	if err != nil {
		return nil, fmt.Errorf("node key %s is not a valid secp256k1 secret: %w", path, err)
	}
	return key, nil
}

// NodeID returns the Kademlia/enode node id: keccak256 of the 64-byte
// uncompressed public key (no 0x04 prefix).
func NodeID(pub *ecdsa.PublicKey) []byte {
	return crypto.Keccak256(crypto.FromECDSAPub(pub)[1:])
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func hexDecode(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("length %d", len(s))
	}
	out := make([]byte, 32)
	for i := range out {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex char %q", c)
	}
}
