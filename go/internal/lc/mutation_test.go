package lc

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
)

// The corpus alone only proves ACCEPTANCE (and two period-gate
// rejections); the review on PR #769 correctly noted VerifySyncAggregate
// could return nil unconditionally and TestLCCorpus would stay green.
// These mutations break one input each on the first corpus update
// (001-update.ssz, which applies cleanly to a bootstrap-fresh store) and
// require the GATE THAT OWNS that input to be the one that says no.

func corpusBootstrap(t *testing.T) *Bootstrap {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")
	b, err := DecodeBootstrap(readCorpus(t, filepath.Join(dir, "bootstrap.ssz")))
	if err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	return b
}

func corpusUpdate001(t *testing.T) *Update {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")
	u, err := DecodeUpdate(readCorpus(t, filepath.Join(dir, "001-update.ssz")))
	if err != nil {
		t.Fatalf("decode 001-update: %v", err)
	}
	return u
}

func freshStore(t *testing.T) *Store {
	t.Helper()
	boot := corpusBootstrap(t)
	s, err := NewFromBootstrap(boot, NewForkSchedule(consensusForTest()), consensusForTest(),
		boot.Header.Beacon.Root())
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return s
}

func consensusForTest() *chain.Consensus { return chain.ConsensusMainnet() }

func requireReject(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("mutation accepted; want rejection containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("rejected by the wrong gate: %v (want %q)", err, want)
	}
}

func TestSignatureBitFlipDiesAtBLS(t *testing.T) {
	u := corpusUpdate001(t)
	u.Aggregate.Signature[50] ^= 1 // mid-point byte: still decodes, wrong key
	requireReject(t, freshStore(t).ProcessUpdate(u), "signature")
}

func TestFinalityBranchFlip(t *testing.T) {
	u := corpusUpdate001(t)
	u.FinalityBranch[0][0] ^= 1
	requireReject(t, freshStore(t).ProcessUpdate(u), "finality branch does not verify")
}

func TestFinalizedPayloadRootFlip(t *testing.T) {
	u := corpusUpdate001(t)
	u.Finalized.Exec[5] ^= 1 // payload header root forged under a real body root
	requireReject(t, freshStore(t).ProcessUpdate(u), "finalized execution branch")
}

func TestAttestedExecBranchFlip(t *testing.T) {
	u := corpusUpdate001(t)
	u.Attested.Branch[2][7] ^= 1
	requireReject(t, freshStore(t).ProcessUpdate(u), "attested execution branch")
}

func TestNextCommitteePubkeyFlipFailsItsBranchNotBLS(t *testing.T) {
	// The signature covers the attested header under the CURRENT
	// committee, so BLS still passes; the tampered committee must die at
	// its own branch (gate 7).
	u := corpusUpdate001(t)
	u.NextCommittee.Pubkeys[10][20] ^= 1
	requireReject(t, freshStore(t).ProcessUpdate(u), "next-committee branch does not verify")
}

func TestParticipationBelowBarDiesBeforeBLS(t *testing.T) {
	u := corpusUpdate001(t)
	// 100 of 512 participants: below the 2/3 bar (342). The aggregate is
	// untouched, so a missing participation gate would show up as a BLS
	// failure — the message tells the two apart.
	u.Aggregate.Participation = [64]byte{}
	for i := 0; i < 100; i++ {
		u.Aggregate.Participation[i/8] |= 1 << (uint(i) % 8)
	}
	err := freshStore(t).ProcessUpdate(u)
	requireReject(t, err, "below the 2/3 bar")
	if errors.Is(err, ErrPeriodGate) {
		t.Fatal("period gate must not claim the participation rejection")
	}
}

func TestBootstrapCommitteeBranchFlip(t *testing.T) {
	boot := corpusBootstrap(t)
	boot.CommitteeBranch[0][0] ^= 1
	_, err := NewFromBootstrap(boot, NewForkSchedule(consensusForTest()), consensusForTest(),
		boot.Header.Beacon.Root())
	requireReject(t, err, "committee branch does not verify")
}

func TestBootstrapExecBranchFlip(t *testing.T) {
	// The finding this pins (PR #769 review): a peer may pair the genuine
	// checkpoint header and committee with a payload header of its own —
	// the execution branch is what binds them.
	boot := corpusBootstrap(t)
	boot.Header.Branch[1][3] ^= 1
	_, err := NewFromBootstrap(boot, NewForkSchedule(consensusForTest()), consensusForTest(),
		boot.Header.Beacon.Root())
	requireReject(t, err, "execution branch does not verify")
}
