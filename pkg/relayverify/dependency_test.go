// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"sigsum.org/sigsum-go/pkg/types"
)

// SIGSUM-GO IS PINNED AT v0.14.1, THE VERSION WHOSE SOURCE WAS READ, AND UPGRADING IT IS A
// CONTRACT AMENDMENT, NOT A DEPENDENCY BUMP.
//
// The contract's Ed25519 rule is Go's crypto/ed25519, and it covers every Ed25519 signature a
// client verifies: the leaf signatures, and the log's and the witnesses' signatures inside a
// sigsum proof (<workspace>/docs/contracts/relay-list.md, The Ed25519 verification rule). At
// v0.14.1 sigsum-go verifies the log's and witnesses' signatures with crypto/ed25519.Verify
// itself (pkg/crypto/crypto.go). v1.0.0 is different twice over: its go.mod requires go 1.27,
// which would raise every consumer's floor, and its crypto.PublicKey.Verify refuses a
// non-canonical or low-order public key and a low-order R (pkg/crypto/ed25519.go, "consistent
// with ed25519-dalek's verify_strict") -- a different rule for log and witness signatures.
//
// This package also relies on behaviour read at v0.14.1: policy.VerifyCosignedTreeHead reads a
// cosignature's timestamp only as signed data, so a tree head with a filtered cosignature map is
// a filtered quorum evaluation; "quorum none" is a 0-of-0 group that evaluates true; and
// proof.SigsumProof.FromASCII accepts proof versions 1 and 2. Before changing the version below,
// re-read pkg/crypto, pkg/policy, pkg/proof and pkg/types at the new version, and have the
// contract amended.
func TestSigsumGoIsPinnedAtTheVersionWhoseSourceWasRead(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}
	if !regexp.MustCompile(`(?m)^\s*(require\s+)?sigsum\.org/sigsum-go v0\.14\.1(\s|$)`).Match(b) {
		t.Error("go.mod does not require sigsum.org/sigsum-go v0.14.1. Upgrading sigsum-go is a contract " +
			"amendment, not a dependency bump: v1.0.0 changes the Ed25519 rule for log and witness signatures " +
			"(<workspace>/docs/contracts/relay-list.md). Re-read its pkg/crypto, pkg/policy, pkg/proof and " +
			"pkg/types, have the contract amended, and only then change this test")
	}
}

func TestTheLeafNamespaceIsSigsums(t *testing.T) {
	if leafNamespace != types.TreeLeafNamespace {
		t.Errorf("leafNamespace = %q, sigsum-go's is %q", leafNamespace, types.TreeLeafNamespace)
	}
}
