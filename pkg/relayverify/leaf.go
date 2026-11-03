// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// leafNamespace is sigsum's tree-leaf namespace. The contract pins it; dependency_test.go holds
// it equal to sigsum-go's types.TreeLeafNamespace.
const leafNamespace = "sigsum.org/v1/tree-leaf"

// leafMessage is message = SHA-256(x) (contract, The hashing, pinned exactly).
func leafMessage(x []byte) [32]byte { return sha256.Sum256(x) }

// leafChecksum is checksum = SHA-256(message) = SHA-256(SHA-256(x)).
func leafChecksum(x []byte) [32]byte {
	m := leafMessage(x)

	return sha256.Sum256(m[:])
}

// leafSigned is the 56 octets a sigsum submitter signs: the namespace, one NUL, the checksum.
// NEVER x itself (vector N1) and never a single hash (vector N2).
func leafSigned(x []byte) []byte {
	c := leafChecksum(x)
	out := make([]byte, 0, len(leafNamespace)+1+len(c))
	out = append(out, leafNamespace...)
	out = append(out, 0)

	return append(out, c[:]...)
}

// verifyEd25519 IS the client's Ed25519 rule: Go's crypto/ed25519, RFC 8032 cofactorless
// verification refusing a non-canonical S. Every leaf signature goes through here, and
// speccheck_test.go holds it to the contract's twelve verdicts -- case 11 ACCEPTED. Leaf
// signatures are never routed through sigsum-go: from v1.0.0 its verifier is stricter than this
// rule and disagrees with it.
func verifyEd25519(pub [32]byte, msg, sig []byte) bool { return ed25519.Verify(pub[:], msg, sig) }

// verifyLeaf reports whether sig is pub's sigsum leaf signature over the octets x.
func verifyLeaf(pub [32]byte, x []byte, sig [64]byte) bool {
	return verifyEd25519(pub, leafSigned(x), sig[:])
}
