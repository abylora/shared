// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import "testing"

// The rule's own cases -- every small-order and non-canonical encoding, and the honest keys -- are
// pinned through the exported API in weak_key_api_test.go. This internal test keeps only what
// needs the package's internals: the attack itself, end to end.

// THE ATTACK THIS STOPS. crypto/ed25519 -- the contract's rule -- accepts the signature
// R = identity, S = 0 under the identity key over ANY message (speccheck case 0), so a certified
// identity key would let anyone sign lists. The forged signature does verify over vector L, and
// the bundle is refused at the certificate.
func TestACertifiedIdentityKeyIsRefusedBeforeItsForgedListIsAccepted(t *testing.T) {
	identity := mustHex32(t, "0100000000000000000000000000000000000000000000000000000000000000") // (0, 1)
	var forged [64]byte
	copy(forged[:32], identity[:])
	if !verifyLeaf(identity, []byte(vectorL), forged) {
		t.Fatal("the forged signature does not verify; this test no longer shows the attack")
	}

	b := Bundle{
		RelayList:               fixture(t, "list/vector-l.json"),
		RelayListProof:          fixture(t, "list/vector-l.identity-key.proof"),
		SigningCertificate:      fixture(t, "certificate/identity-key.json"),
		SigningCertificateProof: fixture(t, "certificate/identity-key.current.proof"),
	}
	requireRefused(t, b, ErrCertificateKeyWeak)
}
