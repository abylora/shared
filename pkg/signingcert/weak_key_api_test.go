// SPDX-License-Identifier: AGPL-3.0-only

package signingcert_test

import (
	"encoding/hex"
	"testing"

	"github.com/abylora/shared/pkg/signingcert"
)

// THE API PIN for IsWeakKey, the one copy of the certified-key rule. Encode refuses a weak key,
// relayverify's Verify refuses a certificate carrying one, and control-plane's ceremony calls it,
// rather than any of them spelling the list again: two copies would be a parser differential.

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

func key32(t *testing.T, h string) [32]byte {
	t.Helper()
	var k [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(k) {
		t.Fatalf("failed to decode a 32-byte hex key: %v", err)
	}
	copy(k[:], b)

	return k
}

// Contract, Roles are bound by key: a certificate whose key is a small-order point (any of the 8
// encodings) or a non-canonical encoding is refused, by clients and at the ceremony.
func TestIsWeakKeyRefusesEverySmallOrderAndNonCanonicalEncoding(t *testing.T) {
	if len(speccheckEightTorsion) != 8 {
		t.Fatalf("%d small-order encodings, want 8", len(speccheckEightTorsion))
	}
	for _, list := range [][]string{speccheckEightTorsion, speccheckEightTorsionNonCanonical} {
		for _, h := range list {
			if !signingcert.IsWeakKey(key32(t, h)) {
				t.Errorf("IsWeakKey(%s) = false, want true", h)
			}
		}
	}
}

// The contract's two test keys (RFC 8032 TEST 1 and TEST 2) and the next root of relayverify's
// fixtures (testdata/public-keys.txt there) are full-order canonical keys: the rule refuses small
// order and non-canonical encodings, and nothing else.
func TestIsWeakKeyAcceptsFullOrderCanonicalKeys(t *testing.T) {
	honest := []string{
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", // RFC 8032 TEST 1
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", // RFC 8032 TEST 2
		"282b832e17f1202961977ce7b80ca1c24c2853e857787f57c4a93c67031e2119", // relayverify's next root
	}

	for _, h := range honest {
		if signingcert.IsWeakKey(key32(t, h)) {
			t.Errorf("IsWeakKey(%s) = true, want false", h)
		}
	}
}
