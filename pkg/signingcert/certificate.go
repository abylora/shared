package signingcert

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"
)

// Type is the certificate's statement type, its _type. The relay list carries a different one,
// so an object signed by the wrong key can never parse as the other kind. WIRE CONTRACT.
const Type = "abylora.relay-list.signing-certificate"

// SpecVersion is the only spec_version this package writes or accepts.
const SpecVersion = 1

// Env says which trust domain a certificate belongs to. Staging has its own roots and its own
// log policy; env makes a staging certificate identifiable even if a log is ever shared.
type Env string

const (
	EnvProduction Env = "production"
	EnvStaging    Env = "staging"
)

// Valid reports whether e is one of the two environments.
func (e Env) Valid() bool { return e == EnvProduction || e == EnvStaging }

// Certificate is one decoded signing certificate. Decoding it verifies nothing: it is the
// root's statement, and whether the root made it is the signature's question, not this type's.
type Certificate struct {
	env       Env
	root      string
	key       [32]byte
	notBefore time.Time
	notAfter  time.Time
}

// Opts carries everything a certificate says. A parameter bag, copied at Encode and never
// retained.
type Opts struct {
	Env Env
	// Root is the issuing root's Fingerprint.
	Root string
	// Key is the signing public key, raw.
	Key       [32]byte
	NotBefore time.Time
	NotAfter  time.Time
}

// Env returns env.
func (c Certificate) Env() Env { return c.env }

// Root returns root: the issuing root's Fingerprint, as written.
func (c Certificate) Root() string { return c.root }

// Key returns key, the signing public key, as its raw 32 bytes.
func (c Certificate) Key() [32]byte { return c.key }

// NotBefore returns not_before, in UTC.
func (c Certificate) NotBefore() time.Time { return c.notBefore }

// NotAfter returns not_after, in UTC.
func (c Certificate) NotAfter() time.Time { return c.notAfter }

// LogValue makes a Certificate render as a placeholder through slog, relaylist's rule for
// every wire type.
func (Certificate) LogValue() slog.Value { return slog.StringValue(redacted) }

// redacted is what a Certificate renders as through slog.LogValuer.
const redacted = "REDACTED"

// spkiPrefix is the constant 12-byte DER prefix of an Ed25519 SubjectPublicKeyInfo, before
// the 32-byte key. Measured, not recalled (contract, Signing and trust).
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// Fingerprint returns pub's fingerprint: SHA-256 over its 44-byte DER SubjectPublicKeyInfo,
// in standard padded base64 (contract, Signing and trust).
//
// It panics if pub is not 32 bytes, as crypto/ed25519 does: such a value has no SPKI
// encoding, and hashing it would name something that is not a key.
func Fingerprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		panic("signingcert: Fingerprint of a public key that is not 32 bytes")
	}

	h := sha256.New()
	h.Write(spkiPrefix)
	h.Write(pub)

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// timestampLayout is the contract's only timestamp form. time.Parse also accepts a
// fractional second after the seconds field, so parseTimestamp checks the length first.
const timestampLayout = "2006-01-02T15:04:05Z"

// certificateJSON is the wire form, in the contract's field order. Unexported, so these tags
// are the only place a field name is spelled for writing.
type certificateJSON struct {
	Type        string `json:"_type"`
	SpecVersion int    `json:"spec_version"`
	Env         string `json:"env"`
	Root        string `json:"root"`
	Key         string `json:"key"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

// Encode returns the certificate's octets: compact JSON in the contract's field order, no
// trailing newline. What it returns is the artifact the root signs.
//
// It refuses everything Decode refuses, so it can never write bytes a client rejects: an
// unknown env, a root that is not a fingerprint, a key that is the root's own, a window that
// is empty, and an instant the
// timestamp form cannot carry -- a fractional second, or a year outside 0000..9999. It
// converts instants to UTC and never truncates them. It cannot write whitespace or an escape,
// which Decode also refuses: every value it writes has passed a check admitting neither.
// Every refusal returns nil bytes.
func Encode(o Opts) ([]byte, error) {
	if !o.Env.Valid() {
		return nil, ErrEnvUnknown
	}
	if !validRoot(o.Root) {
		return nil, ErrRootMalformed
	}
	if Fingerprint(o.Key[:]) == o.Root {
		return nil, ErrSelfCertificate
	}

	notBefore, notAfter := o.NotBefore.UTC(), o.NotAfter.UTC()
	if !encodable(notBefore) || !encodable(notAfter) {
		return nil, ErrTimestampMalformed
	}
	if !notBefore.Before(notAfter) {
		return nil, ErrValidityEmpty
	}

	octets, err := json.Marshal(certificateJSON{
		Type:        Type,
		SpecVersion: SpecVersion,
		Env:         string(o.Env),
		Root:        o.Root,
		Key:         hex.EncodeToString(o.Key[:]),
		NotBefore:   notBefore.Format(timestampLayout),
		NotAfter:    notAfter.Format(timestampLayout),
	})
	if err != nil {
		// These field types cannot fail to marshal.
		return nil, ErrMalformed
	}

	return octets, nil
}

// encodable reports whether t, in UTC, is an instant the timestamp form carries exactly.
func encodable(t time.Time) bool {
	return t.Nanosecond() == 0 && t.Year() >= 0 && t.Year() <= 9999
}

// validRoot reports whether s is standard padded base64 of exactly 32 bytes in its one
// canonical spelling. The re-encoding comparison is what refuses the forms the standard
// decoder forgives: an embedded newline, and non-zero padding bits.
func validRoot(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)

	return err == nil && len(b) == sha256.Size && base64.StdEncoding.EncodeToString(b) == s
}

// parseKey parses exactly 64 lowercase hexadecimal characters. encoding/hex alone would also
// accept uppercase.
func parseKey(s string) ([32]byte, bool) {
	var key [32]byte
	if len(s) != 2*len(key) {
		return key, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return key, false
		}
	}
	if _, err := hex.Decode(key[:], []byte(s)); err != nil {
		return key, false
	}

	return key, true
}

// parseTimestamp parses exactly YYYY-MM-DDTHH:MM:SSZ naming a real instant: no fractional
// second, no offset, no lowercase t or z, no 30 February and no leap second.
func parseTimestamp(s string) (time.Time, bool) {
	if len(s) != len(timestampLayout) {
		return time.Time{}, false
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil || t.Format(timestampLayout) != s {
		return time.Time{}, false
	}

	return t, true
}
