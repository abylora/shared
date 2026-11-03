// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"bytes"
	"encoding/json"
)

// scan walks the whole token stream once. It refuses anything that is not one JSON object, a
// duplicate key in any object at any depth, and a second value after the object.
//
// A COPY of pkg/signingcert/decode.go's scan, deliberately: this package's guard admits only the
// standard library and transport, and a shared internal package's dotted path would need that
// guard relaxed. It differs in two ways: its sentinels, and insignificant JSON whitespace is
// allowed, after the object too. The list's rule is lenient, and the octets were verified before
// they are parsed, so leniency opens no signature differential. A duplicate key is still refused
// at every depth: encoding/json keeps the last occurrence and other languages differ. Keys are
// compared after unescaping, as every decoder will see them.
func scan(octets []byte) error {
	dec := json.NewDecoder(bytes.NewReader(octets))
	// Numbers stay text, so an out-of-range literal is not a syntax error here.
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrDecodeMalformed
	}
	if err := scanObject(dec); err != nil {
		return err
	}
	if len(trimJSONSpace(octets[dec.InputOffset():])) != 0 {
		return ErrDecodeMalformed
	}

	return nil
}

// scanObject scans an object's members after its opening brace, through its closing brace.
func scanObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ErrDecodeMalformed
		}
		key, ok := tok.(string)
		if !ok {
			return ErrDecodeMalformed
		}
		if seen[key] {
			return ErrDecodeDuplicateKey
		}
		seen[key] = true

		if err := scanValue(dec); err != nil {
			return err
		}
	}

	return closing(dec, '}')
}

// scanValue scans one value of any kind. encoding/json bounds the nesting depth.
func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrDecodeMalformed
	}

	switch tok {
	case json.Delim('{'):
		return scanObject(dec)
	case json.Delim('['):
		for dec.More() {
			if err := scanValue(dec); err != nil {
				return err
			}
		}

		return closing(dec, ']')
	}

	return nil
}

func closing(dec *json.Decoder, want json.Delim) error {
	if tok, err := dec.Token(); err != nil || tok != want {
		return ErrDecodeMalformed
	}

	return nil
}

// trimJSONSpace trims JSON's four whitespace bytes and nothing else. bytes.TrimSpace would also
// trim Unicode spaces such as U+0085 and U+00A0, which JSON does not permit.
func trimJSONSpace(b []byte) []byte { return bytes.Trim(b, " \t\r\n") }

// hasLoneSurrogate reports whether a string in octets, already known to be valid JSON, carries a
// \u escape of a UTF-16 surrogate that is not one half of a high-then-low pair. encoding/json
// would decode it as U+FFFD; the contract refuses the list instead (Strict parsing). An escaped
// backslash followed by "u" is not an escape, and is skipped as one.
func hasLoneSurrogate(octets []byte) bool {
	inString := false
	for i := 0; i < len(octets); i++ {
		c := octets[i]
		switch {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\' && octets[i+1] != 'u':
			i++ // A one-character escape, \\ included.
		case c == '\\':
			u := hex4(octets[i+2 : i+6])
			i += 5
			switch {
			case u >= 0xDC00 && u <= 0xDFFF:
				return true
			case u >= 0xD800 && u <= 0xDBFF:
				if i+6 >= len(octets) || octets[i+1] != '\\' || octets[i+2] != 'u' {
					return true
				}
				if l := hex4(octets[i+3 : i+7]); l < 0xDC00 || l > 0xDFFF {
					return true
				}
				i += 6
			}
		}
	}

	return false
}

// hex4 parses four hexadecimal digits, which valid JSON guarantees after \u.
func hex4(b []byte) uint32 {
	var n uint32
	for _, c := range b {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			n |= uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n |= uint32(c-'A') + 10
		}
	}

	return n
}
