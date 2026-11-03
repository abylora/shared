// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"encoding/hex"
	"testing"
)

// The 8 small-order encodings and the 6 non-canonical encodings of small-order points, copied
// from ed25519-speccheck's src/main.rs, EIGHT_TORSION and EIGHT_TORSION_NON_CANONICAL, at commit
// 65519336fda78a3d016e947df6d82848aca0c9da (Apache-2.0), converted from decimal bytes to hex.
// Never computed here.
var (
	speccheckEightTorsion = []string{
		"0100000000000000000000000000000000000000000000000000000000000000", // (0, 1), order 1, the identity
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"0000000000000000000000000000000000000000000000000000000000000080", // order 4
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
		"0000000000000000000000000000000000000000000000000000000000000000", // order 4
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	}
	speccheckEightTorsionNonCanonical = []string{
		"0100000000000000000000000000000000000000000000000000000000000080", // the identity, x-sign set on x = 0
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y = 2^255 - 18, x-sign set
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y = -1, x-sign set on x = 0
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = 2^255 - 18
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y = 2^255 - 19, x-sign set
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = 2^255 - 19
	}
)

// Contract, Roles are bound by key: a certificate whose key is a small-order point (any of the 8
// encodings) or a non-canonical encoding is refused.
func TestASmallOrderOrNonCanonicalKeyIsWeak(t *testing.T) {
	if len(speccheckEightTorsion) != 8 {
		t.Fatalf("%d small-order encodings, want 8", len(speccheckEightTorsion))
	}
	for _, list := range [][]string{speccheckEightTorsion, speccheckEightTorsionNonCanonical} {
		for _, h := range list {
			if !weakKey(mustHex32(t, h)) {
				t.Errorf("%s is not weak", h)
			}
		}
	}
}

// The contract's two test keys and the fixtures' next root are not weak: the check refuses small
// order and non-canonical encodings, and nothing else.
func TestAFullOrderCanonicalKeyIsNotWeak(t *testing.T) {
	for _, h := range []string{testRootPubHex, testSigningPubHex, hex.EncodeToString(func() []byte {
		k := publicKey(t, "next-root")
		return k[:]
	}())} {
		if weakKey(mustHex32(t, h)) {
			t.Errorf("%s is weak", h)
		}
	}
}

// THE ATTACK THIS STOPS. crypto/ed25519 -- the contract's rule -- accepts the signature
// R = identity, S = 0 under the identity key over ANY message (speccheck case 0), so a certified
// identity key would let anyone sign lists. The forged signature does verify over vector L, and
// the bundle is refused at the certificate.
func TestACertifiedIdentityKeyIsRefusedBeforeItsForgedListIsAccepted(t *testing.T) {
	identity := mustHex32(t, speccheckEightTorsion[0])
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
