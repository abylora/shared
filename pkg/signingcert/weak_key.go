// SPDX-License-Identifier: AGPL-3.0-only

package signingcert

import "encoding/hex"

// smallOrderKeys are the 8 encodings of the Ed25519 points of small order, the 8-torsion
// subgroup: ed25519-speccheck's src/main.rs, EIGHT_TORSION, at commit
// 65519336fda78a3d016e947df6d82848aca0c9da (Apache-2.0), converted from decimal bytes to hex.
// Taken from that published source, never computed here.
var smallOrderKeys = func() map[[32]byte]bool {
	m := make(map[[32]byte]bool, 8)
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000", // (0, 1), order 1, the identity
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"0000000000000000000000000000000000000000000000000000000000000080", // order 4
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
		"0000000000000000000000000000000000000000000000000000000000000000", // order 4
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	} {
		var k [32]byte
		if n, err := hex.Decode(k[:], []byte(h)); err != nil || n != len(k) {
			panic("signingcert: a small-order encoding is not 32 bytes of hex")
		}
		m[k] = true
	}

	return m
}()

// IsWeakKey reports whether key may not be certified as a signing key (contract, Roles are bound
// by key): one of the 8 small-order Ed25519 encodings, or not a canonical point encoding.
//
// THIS IS THE ONE COPY OF THE RULE, and it lives here so that every Go path holding a certificate
// meets it. The contract refuses such a key "by clients and at the ceremony", and the ceremony
// produces the certificate only through Encode: Encode refuses a weak key, Decode refuses one,
// both with ErrKeyWeak, so no Go code can hold a parsed certificate carrying one; relayverify's
// Verify and control-plane's ceremony call IsWeakKey rather than spell the list again. Two copies
// would be a parser differential. A caller reports a true result as ErrKeyWeak, which
// relayverify's ErrCertificateKeyWeak is an alias of.
//
// It checks the key alone, never any signature, needs no cryptography -- these are byte
// comparisons -- and does not change the verification rule. crypto/ed25519, the contract's rule,
// accepts the signature R = identity, S = 0 under the identity key over any message (speccheck
// case 0), so a certified small-order key would let anyone sign lists.
//
// An encoding is the 255-bit little-endian y with the sign of x in the top bit. It is
// non-canonical when y >= p = 2^255 - 19, or when the sign bit is set on a point whose x is 0,
// which are exactly y = 1 and y = p - 1. An encoding that is canonical but not a point at all
// fails every verification, so it fails closed without a check here.
func IsWeakKey(key [32]byte) bool {
	if smallOrderKeys[key] {
		return true
	}

	y := key
	y[31] &= 0x7f
	signSet := key[31]&0x80 != 0

	return yAtLeastP(y) || (signSet && (y == yOne || y == yMinusOne))
}

// yOne and yMinusOne are y = 1 and y = p - 1, the two y values with x = 0.
var (
	yOne      = [32]byte{1}
	yMinusOne = [32]byte{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
)

// yAtLeastP reports whether the 255-bit little-endian y is at least p = 2^255 - 19, whose
// encoding is 0xed, then 30 bytes of 0xff, then 0x7f.
func yAtLeastP(y [32]byte) bool {
	if y[31] != 0x7f || y[0] < 0xed {
		return false
	}
	for _, b := range y[1:31] {
		if b != 0xff {
			return false
		}
	}

	return true
}
