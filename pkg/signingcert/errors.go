package signingcert

import "errors"

// EVERY ERROR THIS PACKAGE RETURNS IS ONE OF THESE SENTINELS, BARE. Nothing wraps them, and
// none carries a byte of the input: an error value is the easiest thing in the world to log,
// and the package cannot import fmt, which keeps that structural. A caller tells refusals
// apart with ==, or errors.Is.
var (
	// ErrMalformed: the octets are not one JSON object -- a syntax error, an empty input, or
	// a top-level array, string, number or null.
	ErrMalformed = errors.New("signingcert: not a JSON object")

	// ErrTrailingBytes: anything after the object's closing brace, whitespace and a newline
	// included. The certificate is signed as the exact octets served, so a byte after the
	// object is a byte the signature covers and no parser looks at.
	ErrTrailingBytes = errors.New("signingcert: bytes after the object")

	// ErrDuplicateKey: a key repeated in any object, at any depth. encoding/json keeps the
	// last occurrence and other languages differ, so a duplicate is a parser differential
	// (contract, Strict parsing).
	ErrDuplicateKey = errors.New("signingcert: duplicate key")

	// ErrUnknownField: a top-level key that is not one of the contract's seven, compared
	// exactly -- encoding/json would match "Env" to env.
	ErrUnknownField = errors.New("signingcert: unknown field")

	// ErrFieldMissing: one of the contract's seven fields is absent.
	ErrFieldMissing = errors.New("signingcert: missing field")

	// ErrTypeUnknown: _type is not Type. A relay list's _type lands here, which is the
	// point of the discriminator.
	ErrTypeUnknown = errors.New("signingcert: _type is not " + Type)

	// ErrSpecVersionUnsupported: spec_version is not the JSON number 1, written as exactly
	// that one digit. 1.0, 1e0 and "1" are refused.
	ErrSpecVersionUnsupported = errors.New("signingcert: spec_version is not 1")

	// ErrEnvUnknown: env is neither production nor staging.
	ErrEnvUnknown = errors.New("signingcert: env is neither production nor staging")

	// ErrRootMalformed: root is not standard, padded base64 of exactly 32 bytes, in its one
	// canonical spelling.
	ErrRootMalformed = errors.New("signingcert: root is not a fingerprint")

	// ErrKeyMalformed: key is not exactly 64 lowercase hexadecimal characters.
	ErrKeyMalformed = errors.New("signingcert: key is not 64 lowercase hex characters")

	// ErrTimestampMalformed: not_before or not_after is not exactly YYYY-MM-DDTHH:MM:SSZ
	// naming a real instant. On Encode: an instant with a fractional second, or a year
	// outside 0000..9999, which that form cannot carry.
	ErrTimestampMalformed = errors.New("signingcert: timestamp is not YYYY-MM-DDTHH:MM:SSZ")

	// ErrValidityEmpty: not_before is not before not_after.
	ErrValidityEmpty = errors.New("signingcert: not_before is not before not_after")
)
