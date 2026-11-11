package rlpx

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Replays the EL-A4 RLPx conformance corpus (rust/testdata/el/rlpx/) and
// asserts the verdicts recorded in expected.txt — the same files the Java
// side generates (ElRlpxVectorConformanceTest) and the Rust side
// (myotis-net/tests/el_rlpx_conformance.rs) asserts, so the Go engine is
// pinned to both. Three deterministic cross-language classes:
//
//  1. ECIES decrypt of the canonical EIP-8 auth vectors (legacy + EIP-8),
//  2. session-secret derivation reproducing the EIP-8 published secrets,
//  3. byte-identical frame output for the uncompressed Hello, plus decode
//     verdicts for Java's actual frame bytes (compressed frames decode but
//     are not byte-compared — snappy encoders differ).
func TestRLPXCorpus(t *testing.T) {
	// go/internal/rlpx → repo root is three levels up.
	corpus := filepath.Join("..", "..", "..", "rust", "testdata", "el", "rlpx")
	expected := parseExpected(t, filepath.Join(corpus, "expected.txt"))
	if len(expected) == 0 {
		t.Skipf("corpus not present at %s", corpus)
	}

	actual := map[string]string{}

	// (1) ECIES decrypt of the canonical EIP-8 vectors.
	privB, err := crypto.ToECDSA(mustHex(t, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"))
	if err != nil {
		t.Fatal(err)
	}
	auth1 := mustHex(t, auth1LegacyHex)
	plain1, err := EciesDecrypt(auth1, privB, nil)
	if err != nil {
		t.Fatalf("auth1 decrypt: %v", err)
	}
	actual["ecies.auth1-legacy.plaintext"] = hex.EncodeToString(plain1)

	auth2 := mustHex(t, auth2EIP8Hex)
	plain2, err := EciesDecrypt(auth2[2:], privB, auth2[:2])
	if err != nil {
		t.Fatalf("auth2 decrypt: %v", err)
	}
	actual["ecies.auth2-eip8.plaintext"] = hex.EncodeToString(plain2)

	// (2) Session-secret derivation — must reproduce the EIP-8 published
	// secrets (the same constants the EIP text publishes).
	aEph, err := crypto.ToECDSA(mustHex(t, "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d"))
	if err != nil {
		t.Fatal(err)
	}
	bEphPriv, err := crypto.ToECDSA(mustHex(t, "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4"))
	if err != nil {
		t.Fatal(err)
	}
	var aNonce, bNonce [32]byte
	copy(aNonce[:], mustHex(t, "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6"))
	copy(bNonce[:], mustHex(t, "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"))
	derived, err := DeriveSecrets(aEph, pub64(bEphPriv), aNonce, bNonce, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual["secrets.aes"] = hex.EncodeToString(derived.AESSecret[:])
	actual["secrets.mac"] = hex.EncodeToString(derived.MACSecret[:])

	// (3a) Hello frame is uncompressed → byte-match Java's committed bytes.
	enc, err := NewFrameCodec(corpusSecrets(true))
	if err != nil {
		t.Fatal(err)
	}
	actual["frame.hello.bytes"] = hex.EncodeToString(enc.EncodeFrame(0x00, []byte{0xc0}))

	// (3b) Both .bin files are Java's ACTUAL output — decode them with the
	// responder-side codec (the cross-language interop proof).
	dec, err := NewFrameCodec(corpusSecrets(false))
	if err != nil {
		t.Fatal(err)
	}
	helloCommitted, err := os.ReadFile(filepath.Join(corpus, "001-frame-hello.bin"))
	if err != nil {
		t.Fatal(err)
	}
	actual["frame.hello.decode"] = decodeVerdict(dec, helloCommitted, 0x00, []byte{0xc0})

	msgBody := make([]byte, 300)
	for i := range msgBody {
		msgBody[i] = byte(i)
	}
	msgCommitted, err := os.ReadFile(filepath.Join(corpus, "002-frame-compressed.bin"))
	if err != nil {
		t.Fatal(err)
	}
	actual["frame.compressed.decode"] = decodeVerdict(dec, msgCommitted, 0x10, msgBody)

	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, ok := actual[k]
		if !ok {
			t.Errorf("expected key %q missing from Go replay", k)
			continue
		}
		if got != expected[k] {
			t.Errorf("verdict diverges for %s:\n got %s\nwant %s", k, got, expected[k])
		}
	}
	for k := range actual {
		if _, ok := expected[k]; !ok {
			t.Errorf("Go replay produced key %q the corpus does not record", k)
		}
	}
}

// corpusSecrets mirrors the Rust conformance test's frame_secrets(): fixed
// keccak material over the "rlpx:frame:" labels, initiator or responder
// view.
func corpusSecrets(initiator bool) *SessionSecrets {
	var aesS, macS, aN, bN [32]byte
	copy(aesS[:], crypto.Keccak256([]byte("rlpx:frame:aes")))
	copy(macS[:], crypto.Keccak256([]byte("rlpx:frame:mac")))
	copy(aN[:], crypto.Keccak256([]byte("rlpx:frame:A-nonce")))
	copy(bN[:], crypto.Keccak256([]byte("rlpx:frame:B-nonce")))
	auth := []byte("RLPX-AUTH-WIRE-OPAQUE")
	ack := []byte("RLPX-ACK-WIRE-OPAQUE")
	if initiator {
		return &SessionSecrets{AESSecret: aesS, MACSecret: macS, EgressNonce: aN, IngressNonce: bN, AuthWire: auth, AckWire: ack}
	}
	return &SessionSecrets{AESSecret: aesS, MACSecret: macS, EgressNonce: bN, IngressNonce: aN, AuthWire: ack, AckWire: auth}
}

func decodeVerdict(c *FrameCodec, frame []byte, wantCode uint64, wantBody []byte) string {
	bodyEnd := len(frame) - 16
	n, err := c.DecodeHeader(frame[:16], frame[16:32])
	if err != nil {
		return "HEADER_FAIL"
	}
	d, err := c.DecodeBody(frame[32:bodyEnd], frame[bodyEnd:], n)
	if err != nil || d.MessageCode != wantCode || !bytes.Equal(d.Payload, wantBody) {
		return "MISMATCH"
	}
	return "ok"
}

func parseExpected(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// The two canonical EIP-8 auth vectors (geth's ecies test fixtures, the same
// bytes the Java/Rust corpus replays).
const (
	auth1LegacyHex = "048ca79ad18e4b0659fab4853fe5bc58eb83992980f4c9cc147d2aa31532efd29a3d3dc6a3d89eaf" +
		"913150cfc777ce0ce4af2758bf4810235f6e6ceccfee1acc6b22c005e9e3a49d6448610a58e98744" +
		"ba3ac0399e82692d67c1f58849050b3024e21a52c9d3b01d871ff5f210817912773e610443a9ef14" +
		"2e91cdba0bd77b5fdf0769b05671fc35f83d83e4d3b0b000c6b2a1b1bba89e0fc51bf4e460df310" +
		"5c444f14be226458940d6061c296350937ffd5e3acaceeaaefd3c6f74be8e23e0f45163cc7ebd762" +
		"20f0128410fd05250273156d548a414444ae2f7dea4dfca2d43c057adb701a715bf59f6fb66b2d1d" +
		"20f2c703f851cbf5ac47396d9ca65b6260bd141ac4d53e2de585a73d1750780db4c9ee4cd4d22517" +
		"3a4592ee77e2bd94d0be3691f3b406f9bba9b591fc63facc016bfa8"
	auth2EIP8Hex = "01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b" +
		"0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b849" +
		"634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c" +
		"da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc" +
		"147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6" +
		"d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee" +
		"70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09" +
		"c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3" +
		"6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e" +
		"2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c" +
		"3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c"
)
