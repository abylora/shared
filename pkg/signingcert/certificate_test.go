package signingcert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The vectors below are copied from <workspace>/docs/contracts/relay-list.md, The signing
// certificate, Test vectors -- never computed here. They use RFC 8032 section 7.1's published
// test keys, never a real root.
const (
	// testRootPubHex is RFC 8032 TEST 1's public key: the root in vector C.
	testRootPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	// testSigningPubHex is RFC 8032 TEST 2's public key: the signing key in vector C.
	testSigningPubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	// testRootFingerprint is the contract's fingerprint(root).
	testRootFingerprint = "BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k="

	// vectorC is the contract's vector C: 281 octets, no trailing newline.
	vectorC = `{"_type":"abylora.relay-list.signing-certificate","spec_version":1,"env":"staging",` +
		`"root":"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=",` +
		`"key":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",` +
		`"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z"}`
)

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("fixture %q is not 32 bytes of hex", s)
	}

	return [32]byte(b)
}

// vectorCOpts are the options vector C was written from.
func vectorCOpts(t *testing.T) Opts {
	t.Helper()

	return Opts{
		Env:       EnvStaging,
		Root:      testRootFingerprint,
		Key:       mustHex32(t, testSigningPubHex),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
}

// The literals are the contract's, not this package's constants, so a renamed constant fails
// here rather than silently changing the wire.
func TestTheConstantsAreTheContractValues(t *testing.T) {
	if Type != "abylora.relay-list.signing-certificate" {
		t.Errorf("Type = %q", Type)
	}
	if SpecVersion != 1 {
		t.Errorf("SpecVersion = %d", SpecVersion)
	}
	if EnvProduction != "production" || EnvStaging != "staging" {
		t.Errorf("EnvProduction = %q, EnvStaging = %q", EnvProduction, EnvStaging)
	}
}

func TestVectorCIs281Octets(t *testing.T) {
	// A guard on the fixture itself: a transcription slip would otherwise make every test
	// below agree with the wrong bytes.
	if len(vectorC) != 281 {
		t.Fatalf("len(vectorC) = %d, want 281", len(vectorC))
	}
}

func TestFingerprintOfTheTestRootIsTheContractValue(t *testing.T) {
	root := mustHex32(t, testRootPubHex)

	if got := Fingerprint(ed25519.PublicKey(root[:])); got != testRootFingerprint {
		t.Errorf("Fingerprint(TEST 1 pub) = %q, want %q", got, testRootFingerprint)
	}
}

// A wrong-length key has no SPKI encoding, so it has no fingerprint. Fingerprint panics, as
// crypto/ed25519 does on a wrong-length key, rather than return the hash of something that is
// not a key.
func TestFingerprintPanicsOnAWrongLengthKey(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Fingerprint of a %d-byte key did not panic", n)
				}
			}()
			Fingerprint(make(ed25519.PublicKey, n))
		}()
	}
}

func TestEncodeOfVectorCOptsIsVectorC(t *testing.T) {
	got, err := Encode(vectorCOpts(t))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if string(got) != vectorC {
		t.Errorf("Encode() =\n%s\nwant\n%s", got, vectorC)
	}
}

func TestDecodeOfVectorCYieldsItsFields(t *testing.T) {
	c, err := Decode([]byte(vectorC))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	want := vectorCOpts(t)
	if c.Env() != want.Env {
		t.Errorf("Env() = %q, want %q", c.Env(), want.Env)
	}
	if c.Root() != want.Root {
		t.Errorf("Root() = %q, want %q", c.Root(), want.Root)
	}
	if c.Key() != want.Key {
		t.Errorf("Key() = %x, want %x", c.Key(), want.Key)
	}
	if !c.NotBefore().Equal(want.NotBefore) || c.NotBefore().Location() != time.UTC {
		t.Errorf("NotBefore() = %v, want %v in UTC", c.NotBefore(), want.NotBefore)
	}
	if !c.NotAfter().Equal(want.NotAfter) || c.NotAfter().Location() != time.UTC {
		t.Errorf("NotAfter() = %v, want %v in UTC", c.NotAfter(), want.NotAfter)
	}
}

// Encode takes any location and writes the same instant in UTC.
func TestEncodeWritesTheInstantInUTC(t *testing.T) {
	o := vectorCOpts(t)
	east := time.FixedZone("east", 3*60*60)
	o.NotBefore = o.NotBefore.In(east)
	o.NotAfter = o.NotAfter.In(east)

	got, err := Encode(o)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if string(got) != vectorC {
		t.Errorf("Encode() =\n%s\nwant\n%s", got, vectorC)
	}
}

// Encode refuses everything Decode refuses, so it can never produce bytes no client accepts.
// Each case is one refusal, and the error is the bare sentinel.
func TestEncodeRefuses(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Opts)
		want   error
	}{
		"an env outside the two values": {func(o *Opts) { o.Env = "Production" }, ErrEnvUnknown},
		"an empty env":                  {func(o *Opts) { o.Env = "" }, ErrEnvUnknown},
		"a root that is not base64":     {func(o *Opts) { o.Root = "not a fingerprint" }, ErrRootMalformed},
		"a root that is not 32 bytes": {
			func(o *Opts) { o.Root = "BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k" }, ErrRootMalformed,
		},
		"a root with a newline inside": {
			// The standard library's base64 decoder skips newlines; the contract's form does not.
			func(o *Opts) { o.Root = "BuP9j9opu2CrWVV95h7b\nCuzbIxE0vjDnW0Vfjht5L6k=" }, ErrRootMalformed,
		},
		"a key equal to the root's own key": {
			func(o *Opts) { o.Key = mustHex32(t, testRootPubHex) }, ErrSelfCertificate,
		},
		"a not_before with a fractional second": {
			func(o *Opts) { o.NotBefore = o.NotBefore.Add(time.Millisecond) }, ErrTimestampMalformed,
		},
		"a not_after with a fractional second": {
			func(o *Opts) { o.NotAfter = o.NotAfter.Add(time.Nanosecond) }, ErrTimestampMalformed,
		},
		"a year beyond four digits": {
			func(o *Opts) { o.NotAfter = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrTimestampMalformed,
		},
		"a negative year": {
			func(o *Opts) { o.NotBefore = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrTimestampMalformed,
		},
		"not_before equal to not_after": {
			func(o *Opts) { o.NotAfter = o.NotBefore }, ErrValidityEmpty,
		},
		"not_before after not_after": {
			func(o *Opts) { o.NotBefore, o.NotAfter = o.NotAfter, o.NotBefore }, ErrValidityEmpty,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := vectorCOpts(t)
			tc.mutate(&o)

			got, err := Encode(o)
			if err != tc.want {
				t.Errorf("Encode() error = %v, want exactly %v", err, tc.want)
			}
			if got != nil {
				t.Errorf("Encode() returned %d bytes alongside a refusal", len(got))
			}
		})
	}
}

func TestDecodeOfEncodeIsTheOpts(t *testing.T) {
	want := vectorCOpts(t)
	want.Env = EnvProduction
	want.Key = [32]byte(bytes.Repeat([]byte{0x07}, 32))

	octets, err := Encode(want)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	c, err := Decode(octets)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if c.Env() != want.Env || c.Root() != want.Root || c.Key() != want.Key ||
		!c.NotBefore().Equal(want.NotBefore) || !c.NotAfter().Equal(want.NotAfter) {
		t.Errorf("Decode(Encode(o)) disagrees with o")
	}
}

// replaceOnce returns vector C with old replaced by new exactly once, and fails the test if
// old does not occur exactly once: a mutation that silently did nothing would let a refusal
// test pass against the valid vector's error, which is nil, only by accident.
func replaceOnce(t *testing.T, old, new string) string {
	t.Helper()

	if n := strings.Count(vectorC, old); n != 1 {
		t.Fatalf("%q occurs %d times in vector C, want 1", old, n)
	}

	return strings.Replace(vectorC, old, new, 1)
}

// ONE CASE PER REFUSAL, and each error must be the bare sentinel: identity, not errors.Is, so
// no refusal can ever wrap something carrying the input's bytes.
func TestDecodeRefuses(t *testing.T) {
	const (
		typeField   = `"_type":"abylora.relay-list.signing-certificate"`
		specField   = `"spec_version":1`
		envField    = `"env":"staging"`
		rootValue   = `"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k="`
		keyValue    = `"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"`
		notBefore   = `"2026-01-01T00:00:00Z"`
		notAfter    = `"2026-04-01T00:00:00Z"`
		notAfterKey = `,"not_after":` + notAfter
	)

	cases := []struct {
		name  string
		input func(t *testing.T) string
		want  error
	}{
		// Not one JSON object.
		{"empty input", func(*testing.T) string { return "" }, ErrMalformed},
		{"a truncated object", func(*testing.T) string { return vectorC[:len(vectorC)-1] }, ErrMalformed},
		{"an array", func(*testing.T) string { return "[" + vectorC + "]" }, ErrMalformed},
		{"null", func(*testing.T) string { return "null" }, ErrMalformed},
		{"a string", func(*testing.T) string { return `"x"` }, ErrMalformed},

		// Trailing bytes, including whitespace and a newline.
		{"a trailing newline", func(*testing.T) string { return vectorC + "\n" }, ErrTrailingBytes},
		{"a trailing space", func(*testing.T) string { return vectorC + " " }, ErrTrailingBytes},
		{"a second object", func(*testing.T) string { return vectorC + "{}" }, ErrTrailingBytes},
		{"trailing garbage", func(*testing.T) string { return vectorC + "x" }, ErrTrailingBytes},

		// Duplicate keys, at any depth. encoding/json keeps the last occurrence; other
		// languages keep the first, which is exactly a parser differential.
		{"a duplicate top-level key", func(t *testing.T) string {
			return replaceOnce(t, envField, envField+`,"env":"production"`)
		}, ErrDuplicateKey},
		{"a duplicate key spelled with an escape", func(t *testing.T) string {
			return replaceOnce(t, envField, envField+`,"env":"production"`)
		}, ErrDuplicateKey},
		{"a duplicate key in a nested object", func(t *testing.T) string {
			return replaceOnce(t, envField, envField+`,"x":[{"a":1,"a":2}]`)
		}, ErrDuplicateKey},

		// One spelling: no insignificant whitespace anywhere (ruled 2026-10-15). Trailing
		// whitespace is ErrTrailingBytes above, which scan finds first.
		{"a leading space", func(*testing.T) string { return " " + vectorC }, ErrWhitespace},
		{"a leading newline", func(*testing.T) string { return "\n" + vectorC }, ErrWhitespace},
		{"a space after a colon", func(t *testing.T) string {
			return replaceOnce(t, envField, `"env": "staging"`)
		}, ErrWhitespace},
		{"a tab between members", func(t *testing.T) string {
			return replaceOnce(t, envField+",", envField+",\t")
		}, ErrWhitespace},
		{"a carriage return before the closing brace", func(*testing.T) string {
			return vectorC[:len(vectorC)-1] + "\r}"
		}, ErrWhitespace},

		// No backslash anywhere (ruled 2026-10-15): no value can legitimately need an escape.
		{"an escape in a value", func(t *testing.T) string {
			return replaceOnce(t, envField, `"env":"st\u0061ging"`)
		}, ErrEscape},
		{"an escape in a key", func(t *testing.T) string {
			return replaceOnce(t, typeField, `"\u005ftype":"abylora.relay-list.signing-certificate"`)
		}, ErrEscape},
		{"an escaped solidus", func(t *testing.T) string {
			return replaceOnce(t, typeField, `"_type":"abylora.relay-list.signing\/certificate"`)
		}, ErrEscape},
		{"an escaped newline in root", func(t *testing.T) string {
			return replaceOnce(t, rootValue, `"BuP9j9opu2CrWVV95h7b\nCuzbIxE0vjDnW0Vfjht5L6k="`)
		}, ErrEscape},

		// The field set.
		{"an unknown field", func(t *testing.T) string {
			return replaceOnce(t, envField, envField+`,"serial":1`)
		}, ErrUnknownField},
		{"a field differing only in case", func(t *testing.T) string {
			// encoding/json matches field names case-insensitively, so this would silently
			// become env if the decoder leaned on struct tags.
			return replaceOnce(t, envField, `"Env":"staging"`)
		}, ErrUnknownField},
		{"a missing field", func(t *testing.T) string { return replaceOnce(t, notAfterKey, "") }, ErrFieldMissing},
		{"an empty object", func(*testing.T) string { return "{}" }, ErrFieldMissing},

		// _type.
		{"the relay list's _type", func(t *testing.T) string {
			return replaceOnce(t, typeField, `"_type":"abylora.relay-list"`)
		}, ErrTypeUnknown},
		{"a _type that is not a string", func(t *testing.T) string {
			return replaceOnce(t, typeField, `"_type":null`)
		}, ErrTypeUnknown},

		// spec_version: the JSON number 1 and nothing else.
		{"spec_version 1.0", func(t *testing.T) string { return replaceOnce(t, specField, `"spec_version":1.0`) }, ErrSpecVersionUnsupported},
		{"spec_version 1e0", func(t *testing.T) string { return replaceOnce(t, specField, `"spec_version":1e0`) }, ErrSpecVersionUnsupported},
		{`spec_version "1"`, func(t *testing.T) string { return replaceOnce(t, specField, `"spec_version":"1"`) }, ErrSpecVersionUnsupported},
		{"spec_version 2", func(t *testing.T) string { return replaceOnce(t, specField, `"spec_version":2`) }, ErrSpecVersionUnsupported},

		// env.
		{"an env outside the two values", func(t *testing.T) string {
			return replaceOnce(t, envField, `"env":"Staging"`)
		}, ErrEnvUnknown},
		{"a null env", func(t *testing.T) string { return replaceOnce(t, envField, `"env":null`) }, ErrEnvUnknown},

		// root: standard padded base64 of exactly 32 bytes.
		{"a root without padding", func(t *testing.T) string {
			return replaceOnce(t, rootValue, `"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k"`)
		}, ErrRootMalformed},
		{"a root in the URL-safe alphabet", func(t *testing.T) string {
			// 32 bytes of 0xff: "//////////////////////////////////////////8=" in the standard
			// alphabet, which is also accepted below, so only the alphabet differs.
			return replaceOnce(t, rootValue, `"`+base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))+`"`)
		}, ErrRootMalformed},
		{"a root with non-zero padding bits", func(t *testing.T) string {
			return replaceOnce(t, rootValue, `"BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6l="`)
		}, ErrRootMalformed},
		{"a root of 33 bytes", func(t *testing.T) string {
			return replaceOnce(t, rootValue, `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`)
		}, ErrRootMalformed},
		{"a root that is not a string", func(t *testing.T) string { return replaceOnce(t, rootValue, `32`) }, ErrRootMalformed},

		// key: exactly 64 lowercase hex characters.
		{"a key in uppercase hex", func(t *testing.T) string {
			return replaceOnce(t, keyValue, strings.ToUpper(keyValue))
		}, ErrKeyMalformed},
		{"a key of 62 hex characters", func(t *testing.T) string {
			return replaceOnce(t, keyValue, keyValue[:63]+`"`)
		}, ErrKeyMalformed},
		{"a key of 66 hex characters", func(t *testing.T) string {
			return replaceOnce(t, keyValue, keyValue[:65]+`00"`)
		}, ErrKeyMalformed},
		{"a key with a non-hex character", func(t *testing.T) string {
			return replaceOnce(t, keyValue, `"g`+keyValue[2:])
		}, ErrKeyMalformed},
		{"a key that is not a string", func(t *testing.T) string { return replaceOnce(t, keyValue, `[]`) }, ErrKeyMalformed},

		// A self-certificate: key is the root that issued it (ruled 2026-10-15).
		{"a key equal to the root's own key", func(t *testing.T) string {
			return replaceOnce(t, keyValue, `"`+testRootPubHex+`"`)
		}, ErrSelfCertificate},

		// Timestamps: exactly YYYY-MM-DDTHH:MM:SSZ.
		{"a numeric offset", func(t *testing.T) string {
			return replaceOnce(t, notBefore, `"2026-01-01T00:00:00+00:00"`)
		}, ErrTimestampMalformed},
		{"a fractional second", func(t *testing.T) string {
			return replaceOnce(t, notBefore, `"2026-01-01T00:00:00.000Z"`)
		}, ErrTimestampMalformed},
		{"a lowercase z", func(t *testing.T) string {
			return replaceOnce(t, notBefore, `"2026-01-01T00:00:00z"`)
		}, ErrTimestampMalformed},
		{"a lowercase t", func(t *testing.T) string {
			return replaceOnce(t, notBefore, `"2026-01-01t00:00:00Z"`)
		}, ErrTimestampMalformed},
		{"a space for T", func(t *testing.T) string {
			return replaceOnce(t, notAfter, `"2026-04-01 00:00:00Z"`)
		}, ErrTimestampMalformed},
		{"a day that does not exist", func(t *testing.T) string {
			return replaceOnce(t, notAfter, `"2026-02-30T00:00:00Z"`)
		}, ErrTimestampMalformed},
		{"a leap second", func(t *testing.T) string {
			return replaceOnce(t, notAfter, `"2026-03-31T23:59:60Z"`)
		}, ErrTimestampMalformed},
		{"a timestamp that is not a string", func(t *testing.T) string {
			return replaceOnce(t, notAfter, `1775001600`)
		}, ErrTimestampMalformed},

		// The window.
		{"not_before equal to not_after", func(t *testing.T) string {
			return replaceOnce(t, notAfter, notBefore)
		}, ErrValidityEmpty},
		{"not_before after not_after", func(t *testing.T) string {
			return replaceOnce(t, notAfter, `"2025-12-31T23:59:59Z"`)
		}, ErrValidityEmpty},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.input(t)

			_, err := Decode([]byte(input))
			if err != tc.want {
				t.Errorf("Decode() error = %v, want exactly %v", err, tc.want)
			}
		})
	}
}

// No refusal may carry the input: every sentinel is a constant string. This holds the rule
// for any error the table above did not think of, by refusing a value planted in each field.
func TestNoDecodeErrorCarriesTheInput(t *testing.T) {
	const planted = "PLANTED"

	for _, field := range []string{"_type", "env", "root", "key", "not_before", "not_after"} {
		input := strings.Replace(vectorC, `"`+field+`":"`, `"`+field+`":"`+planted, 1)

		_, err := Decode([]byte(input))
		if err == nil {
			t.Fatalf("%s: Decode() accepted a planted value", field)
		}
		if strings.Contains(err.Error(), planted) {
			t.Errorf("%s: the error carries the input: %v", field, err)
		}
	}
}

func TestEverySentinelIsDistinct(t *testing.T) {
	all := []error{ErrMalformed, ErrTrailingBytes, ErrDuplicateKey, ErrUnknownField, ErrFieldMissing,
		ErrTypeUnknown, ErrSpecVersionUnsupported, ErrEnvUnknown, ErrRootMalformed, ErrKeyMalformed,
		ErrTimestampMalformed, ErrValidityEmpty, ErrWhitespace, ErrEscape, ErrSelfCertificate}

	for i, a := range all {
		for _, b := range all[i+1:] {
			if errors.Is(a, b) || a.Error() == b.Error() {
				t.Errorf("%v and %v are not distinct", a, b)
			}
		}
	}
}

// The URL-safe refusal above differs from this only in its alphabet, so it is refused for the
// alphabet and nothing else.
func TestDecodeAcceptsARootUsingTheStandardAlphabetsSymbols(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
	if !strings.ContainsAny(root, "+/") {
		t.Fatalf("fixture %q exercises neither + nor /", root)
	}

	c, err := Decode([]byte(strings.Replace(vectorC, testRootFingerprint, root, 1)))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if c.Root() != root {
		t.Errorf("Root() = %q, want %q", c.Root(), root)
	}
}

// A reflexive slog.Any of a Certificate prints the placeholder. Nothing in a certificate is
// secret, but the type follows relaylist's rule that a wire type never renders its fields, so
// a log line cannot become the place a document's contents end up.
func TestACertificateRendersAsThePlaceholder(t *testing.T) {
	c, err := Decode([]byte(vectorC))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", slog.Any("value", c))
	line := buf.String()

	i := strings.Index(line, "value=")
	if i < 0 || !strings.HasPrefix(line[i:], "value="+redacted) {
		t.Fatalf("the line does not carry the placeholder: %s", line)
	}
	// Only after value=: the handler's own time= attribute carries a year.
	for _, f := range []string{"staging", testRootFingerprint, "3d4017c3", "2026"} {
		if strings.Contains(line[i:], f) {
			t.Errorf("the line carries %q: %s", f, line)
		}
	}
}

// Member order is not part of the format (ruled 2026-10-15): no verifier depends on it, as
// with the relay list's _type. Vector C with its members reversed decodes to the same fields.
func TestDecodeAcceptsMembersInAnyOrder(t *testing.T) {
	members := strings.Split(strings.TrimSuffix(strings.TrimPrefix(vectorC, "{"), "}"), `,"`)
	if len(members) != 7 {
		t.Fatalf("split vector C into %d members, want 7", len(members))
	}
	reversed := make([]string, 0, len(members))
	for i := len(members) - 1; i >= 0; i-- {
		reversed = append(reversed, strings.TrimPrefix(members[i], `"`))
	}
	input := `{"` + strings.Join(reversed, `,"`) + "}"

	c, err := Decode([]byte(input))
	if err != nil {
		t.Fatalf("Decode(%s) error = %v", input, err)
	}
	want, _ := Decode([]byte(vectorC))
	if c != want {
		t.Errorf("Decode of the reordered vector disagrees with vector C")
	}
}

// Encode can produce neither insignificant whitespace nor an escape: every value it writes
// has passed a check that admits neither. This pins that, since the two Decode refusals have
// no reachable Encode counterpart to test.
func TestEncodeWritesNoWhitespaceAndNoEscape(t *testing.T) {
	octets, err := Encode(vectorCOpts(t))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if i := bytes.IndexAny(octets, " \t\r\n\\"); i >= 0 {
		t.Errorf("Encode() wrote %q at offset %d", octets[i], i)
	}
}
