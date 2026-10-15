package signingcert

import (
	"bytes"
	"encoding/json"
)

// The contract's seven fields. The names are spelled here for reading and in certificateJSON's
// tags for writing; TestEncodeOfVectorCOptsIsVectorC and TestDecodeOfVectorCYieldsItsFields
// hold the two spellings to the same vector.
const (
	fieldType        = "_type"
	fieldSpecVersion = "spec_version"
	fieldEnv         = "env"
	fieldRoot        = "root"
	fieldKey         = "key"
	fieldNotBefore   = "not_before"
	fieldNotAfter    = "not_after"
)

var fields = []string{fieldType, fieldSpecVersion, fieldEnv, fieldRoot, fieldKey, fieldNotBefore, fieldNotAfter}

// Decode parses a certificate's octets, STRICTLY: a parser differential between this and any
// client's decoder is a hole (contract, Strict parsing). It verifies no signature.
//
// It refuses, each with its own sentinel and in this order: anything that is not one JSON
// object; a duplicate key at any depth; any byte after the object, whitespace included; an
// unknown or a missing field; a _type other than Type; a spec_version other than the JSON
// number 1; an env outside the two; a root that is not a fingerprint; a key that is not 64
// lowercase hex characters; a timestamp not exactly YYYY-MM-DDTHH:MM:SSZ; and not_before not
// before not_after.
func Decode(octets []byte) (Certificate, error) {
	if err := scan(octets); err != nil {
		return Certificate{}, err
	}

	// A map, not struct tags: encoding/json matches struct fields case-insensitively. scan
	// has already refused duplicates, so the map loses nothing.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(octets, &raw); err != nil {
		return Certificate{}, ErrMalformed
	}
	for k := range raw {
		if !isField(k) {
			return Certificate{}, ErrUnknownField
		}
	}
	for _, f := range fields {
		if _, ok := raw[f]; !ok {
			return Certificate{}, ErrFieldMissing
		}
	}

	if s, ok := jsonString(raw[fieldType]); !ok || s != Type {
		return Certificate{}, ErrTypeUnknown
	}
	// The raw literal, not a parsed number: 1.0 and 1e0 parse to 1.
	if string(raw[fieldSpecVersion]) != "1" {
		return Certificate{}, ErrSpecVersionUnsupported
	}

	env, ok := jsonString(raw[fieldEnv])
	if !ok || !Env(env).Valid() {
		return Certificate{}, ErrEnvUnknown
	}
	root, ok := jsonString(raw[fieldRoot])
	if !ok || !validRoot(root) {
		return Certificate{}, ErrRootMalformed
	}
	keyHex, _ := jsonString(raw[fieldKey])
	key, ok := parseKey(keyHex)
	if !ok {
		return Certificate{}, ErrKeyMalformed
	}

	notBeforeText, _ := jsonString(raw[fieldNotBefore])
	notBefore, ok := parseTimestamp(notBeforeText)
	if !ok {
		return Certificate{}, ErrTimestampMalformed
	}
	notAfterText, _ := jsonString(raw[fieldNotAfter])
	notAfter, ok := parseTimestamp(notAfterText)
	if !ok {
		return Certificate{}, ErrTimestampMalformed
	}
	if !notBefore.Before(notAfter) {
		return Certificate{}, ErrValidityEmpty
	}

	return Certificate{env: Env(env), root: root, key: key, notBefore: notBefore, notAfter: notAfter}, nil
}

func isField(k string) bool {
	for _, f := range fields {
		if k == f {
			return true
		}
	}

	return false
}

// jsonString returns raw's value if raw is a JSON string. A null, which encoding/json would
// quietly decode as "", is not one.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}

	return s, true
}

// scan walks the whole token stream once. It refuses a document that is not one JSON object,
// a duplicate key in any object at any depth, and any byte after the object. Keys are
// compared after unescaping, so "env" and "env" are the same key, as every decoder
// will see them.
func scan(octets []byte) error {
	dec := json.NewDecoder(bytes.NewReader(octets))
	// Numbers stay text, so an out-of-range literal is not a syntax error here.
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrMalformed
	}
	if err := scanObject(dec); err != nil {
		return err
	}
	if dec.InputOffset() != int64(len(octets)) {
		return ErrTrailingBytes
	}

	return nil
}

// scanObject scans an object's members after its opening brace, through its closing brace.
func scanObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ErrMalformed
		}
		key, ok := tok.(string)
		if !ok {
			return ErrMalformed
		}
		if seen[key] {
			return ErrDuplicateKey
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
		return ErrMalformed
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
	tok, err := dec.Token()
	if err != nil || tok != want {
		return ErrMalformed
	}

	return nil
}
