// SPDX-License-Identifier: AGPL-3.0-only

package signingcert

import (
	"encoding/hex"
	"testing"
)

// The 14 weak encodings: the 8 small-order ones and the 6 non-canonical encodings of small-order
// points, from ed25519-speccheck's src/main.rs (EIGHT_TORSION and EIGHT_TORSION_NON_CANONICAL)
// at commit 65519336fda78a3d016e947df6d82848aca0c9da, converted to hex; the same list
// weak_key_api_test.go pins through the exported API.
var weakKeyEncodings = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// THE ROUND-TRIP PIN: for every weak key, Encode refuses with ErrKeyWeak, and Decode, fed vector
// C's octets with that key written in by hand (Encode refuses to write them), refuses with the
// identical sentinel. No Go code path can hold a parsed certificate carrying a weak key.
func TestEncodeAndDecodeBothRefuseAWeakKeyWithErrKeyWeak(t *testing.T) {
	for _, h := range weakKeyEncodings {
		t.Run(h[:8]+"..."+h[56:], func(t *testing.T) {
			o := vectorCOpts(t)
			o.Key = mustHex32(t, h)
			got, err := Encode(o)
			if err != ErrKeyWeak {
				t.Errorf("Encode() error = %v, want ErrKeyWeak (bare)", err)
			}
			if got != nil {
				t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
			}

			octets := replaceOnce(t, `"key":"`+testSigningPubHex+`"`, `"key":"`+h+`"`)
			if _, err := Decode([]byte(octets)); err != ErrKeyWeak {
				t.Errorf("Decode() error = %v, want ErrKeyWeak (bare), the same value Encode returns", err)
			}
		})
	}
}

// The fixture list is the API pin's: every entry is weak by IsWeakKey, so the two tests cannot
// drift apart unnoticed.
func TestTheRefusalRowsAreAllWeak(t *testing.T) {
	if len(weakKeyEncodings) != 14 {
		t.Fatalf("%d weak encodings, want 14", len(weakKeyEncodings))
	}
	for _, h := range weakKeyEncodings {
		if b, err := hex.DecodeString(h); err != nil || !IsWeakKey([32]byte(b)) {
			t.Errorf("%s is not weak by IsWeakKey", h)
		}
	}
}

// ErrKeyWeak is its own refusal, distinct from every other sentinel of this package.
func TestErrKeyWeakIsDistinct(t *testing.T) {
	for _, other := range []error{ErrMalformed, ErrTrailingBytes, ErrDuplicateKey, ErrUnknownField, ErrFieldMissing,
		ErrTypeUnknown, ErrSpecVersionUnsupported, ErrEnvUnknown, ErrRootMalformed, ErrKeyMalformed,
		ErrTimestampMalformed, ErrValidityEmpty, ErrWhitespace, ErrEscape, ErrSelfCertificate} {
		if ErrKeyWeak == other || ErrKeyWeak.Error() == other.Error() {
			t.Errorf("ErrKeyWeak is not distinct from %v", other)
		}
	}
}
