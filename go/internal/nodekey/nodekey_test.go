package nodekey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestLoadGeneratesThenReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")

	key1, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); len(got) != 64 || strings.Trim(got, "0123456789abcdefABCDEF") != "" {
		t.Errorf("nodekey file is not 64 hex chars: %q", got)
	}
	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("nodekey perms = %o, want 600", perm)
	}

	key2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(crypto.FromECDSA(key1)) != string(crypto.FromECDSA(key2)) {
		t.Error("reload produced a different key")
	}
}

func TestNodeIDIsKeccakOfUncompressedPubkey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := crypto.FromECDSAPub(&key.PublicKey) // 65 bytes, 0x04-prefixed
	want := crypto.Keccak256(pub[1:])
	if got := NodeID(&key.PublicKey); string(got) != string(want) {
		t.Errorf("NodeID = %x, want %x", got, want)
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("garbage node key accepted")
	}
}
