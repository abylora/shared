// SPDX-License-Identifier: AGPL-3.0-only

package signingcert

import "testing"

// backslash is spelled once, so no escape sequence below can be mistaken for a Go one.
const backslash = "\\"

// Invalid UTF-8 and a lone-surrogate escape are refused in the certificate under its existing
// strict rules (contract, Strict parsing: a document that is not valid UTF-8 or carries a
// lone-surrogate escape is a list-level violation, and the certificate is stricter than the
// list). encoding/json would silently replace either with U+FFFD; every value here is compared
// exactly, and any backslash at all is ErrEscape, so the replacement can never pass a check.
func TestDecodeRefusesInvalidUTF8AndLoneSurrogates(t *testing.T) {
	cases := []struct {
		name     string
		old, new string
		want     error
	}{
		{"an invalid byte in a value", `"env":"staging"`, "\"env\":\"stag\xffing\"", ErrEnvUnknown},
		{"an overlong encoding in a value", `"env":"staging"`, "\"env\":\"stag\xc0\xafing\"", ErrEnvUnknown},
		{"an invalid byte in a key", `"env":"staging"`, "\"e\xffnv\":\"staging\"", ErrUnknownField},
		{"an invalid byte in _type", `"_type":"abylora.relay-list.signing-certificate"`,
			"\"_type\":\"abylora.relay-list.signing-certificate\xff\"", ErrTypeUnknown},
		{"a lone high-surrogate escape", `"env":"staging"`, `"env":"staging` + backslash + `ud800"`, ErrEscape},
		{"a lone low-surrogate escape", `"env":"staging"`, `"env":"staging` + backslash + `udc00"`, ErrEscape},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode([]byte(replaceOnce(t, tc.old, tc.new))); err != tc.want {
				t.Errorf("Decode() error = %v, want %v", err, tc.want)
			}
		})
	}
}
