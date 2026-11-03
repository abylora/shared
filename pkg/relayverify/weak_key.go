// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

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
			panic("relayverify: a small-order encoding is not 32 bytes of hex")
		}
		m[k] = true
	}

	return m
}()

// weakKey reports whether k may not be certified as a signing key (contract, Roles are bound by
// key): one of the 8 small-order encodings, or not a canonical point encoding. crypto/ed25519 --
// the contract's verification rule, which this does not change -- accepts the signature R =
// identity, S = 0 under the identity key over any message (speccheck case 0), so a certified
// small-order key would let anyone sign lists.
//
// An encoding is the 255-bit little-endian y with the sign of x in the top bit. It is
// non-canonical when y >= p = 2^255 - 19, or when the sign bit is set on a point whose x is 0,
// which are exactly y = 1 and y = p - 1. An encoding that is canonical but not a point at all
// fails every verification, so it fails closed without a check here.
func weakKey(k [32]byte) bool {
	if smallOrderKeys[k] {
		return true
	}

	y := k
	y[31] &= 0x7f
	signSet := k[31]&0x80 != 0

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
