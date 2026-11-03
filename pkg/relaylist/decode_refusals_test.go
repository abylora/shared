// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"encoding/json"
	"strings"
	"testing"
)

// withoutTopLevel removes key from the golden document's top level and re-marshals it; member
// order is free.
func withoutTopLevel(t *testing.T, key string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(goldenDocument), &doc); err != nil {
		t.Fatalf("failed to parse the golden document: %v", err)
	}
	if _, ok := doc[key]; !ok {
		t.Fatalf("the golden document has no member %s", key)
	}
	delete(doc, key)

	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to re-marshal: %v", err)
	}

	return string(b)
}

// Every TOP-LEVEL field of the contract's Shape is required. A field missing inside a relay is
// relay-level, and inside an endpoint or api_endpoints entry endpoint-level (decode_scope_test.go).
func TestDecodeRefusesAMissingField(t *testing.T) {
	for _, k := range []string{"version", "generated_at", "expires_at", "api_endpoints", "relays"} {
		if _, err := Decode([]byte(withoutTopLevel(t, k))); err != ErrDecodeFieldMissing {
			t.Errorf("without %s: Decode() error = %v, want ErrDecodeFieldMissing", k, err)
		}
	}
	if _, err := Decode([]byte(withoutTopLevel(t, "_type"))); err != ErrDecodeTypeUnknown {
		t.Errorf("without _type: Decode() error = %v, want ErrDecodeTypeUnknown", err)
	}
}

// One row per LIST-LEVEL refusal, each compared with ==: Decode returns its sentinels BARE. A
// relay-level or endpoint-level violation refuses nothing; decode_scope_test.go holds those.
func TestDecodeRefuses(t *testing.T) {
	g := goldenDocument
	noAPIEndpoint := g[:strings.Index(g, `"api_endpoints":[`)] + `"api_endpoints":[],` + g[strings.Index(g, `"relays":`):]
	noRelay := g[:strings.Index(g, `"relays":[`)] + `"relays":[]}`

	cases := []struct {
		name     string
		old, new string
		in       string
		want     error
	}{
		{name: "empty", in: "", want: ErrDecodeMalformed},
		{name: "null", in: "null", want: ErrDecodeMalformed},
		{name: "an array", in: "[" + g + "]", want: ErrDecodeMalformed},
		{name: "truncated", in: g[:len(g)-1], want: ErrDecodeMalformed},
		{name: "trailing garbage", in: g + "x", want: ErrDecodeMalformed},
		{name: "a second object", in: g + "{}", want: ErrDecodeMalformed},
		{name: "a trailing no-break space", in: g + "\u00a0", want: ErrDecodeMalformed},
		{name: "the certificate's _type", old: `"abylora.relay-list"`, new: `"abylora.relay-list.signing-certificate"`, want: ErrDecodeTypeUnknown},
		{name: "_type a number", old: `"abylora.relay-list"`, new: `1`, want: ErrDecodeTypeUnknown},
		{name: "version a string", old: `"version":42`, new: `"version":"42"`, want: ErrDecodeMalformed},
		{name: "version 42.0", old: `"version":42`, new: `"version":42.0`, want: ErrDecodeMalformed},
		{name: "version 0", old: `"version":42`, new: `"version":0`, want: ErrVersionNotPositive},
		{name: "generated_at not RFC 3339", old: `"2026-10-10T12:00:00Z"`, new: `"10 October 2026"`, want: ErrDecodeMalformed},
		{name: "expiry equal to generation", old: `"2026-10-11T12:00:00Z"`, new: `"2026-10-10T12:00:00Z"`, want: ErrExpiryNotAfterGeneration},
		{name: "no api endpoint", in: noAPIEndpoint, want: ErrNoAPIEndpoints},
		{name: "no relay", in: noRelay, want: ErrNoRelays},
		{name: "relays an object", old: `"relays":[`, new: `"relays":{"x":[`, want: ErrDecodeMalformed},
		{name: "api_endpoints null", in: g[:strings.Index(g, `"api_endpoints":[`)] + `"api_endpoints":null,` + g[strings.Index(g, `"relays":`):], want: ErrDecodeMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			if tc.old != "" {
				in = replaceOnce(t, g, tc.old, tc.new)
			}
			if _, err := Decode([]byte(in)); err != tc.want {
				t.Errorf("Decode() error = %v, want %v (bare)", err, tc.want)
			}
		})
	}
}

// A marker planted in a refused field never reaches the error text, nor does any address of the
// document: an error value is the easiest thing in the world to log (D19).
func TestNoDecodeErrorCarriesTheInput(t *testing.T) {
	const marker = "planted-marker-9f2c"
	for _, m := range [][2]string{
		{`"version":42`, `"version":"` + marker + `"`},
		{`"node_id":"3f0c6a51-0000-4000-8000-000000000001"`, `"node_id":"` + marker + `","node_id":"x"`},
		{`"generated_at":"2026-10-10T12:00:00Z"`, `"generated_at":"` + marker + `"`},
		{`"capacity_weight":50`, `"capacity_weight":"` + marker + `"`},
	} {
		in := strings.Replace(goldenDocument, m[0], m[1], 1)
		_, err := Decode([]byte(in))
		if err == nil {
			t.Fatalf("Decode() of %q accepted it", m[1])
		}
		for _, f := range []string{marker, "192.0.2", "relay-1.test.example", "3f0c6a51"} {
			if strings.Contains(err.Error(), f) {
				t.Errorf("error %q carries %q", err, f)
			}
		}
	}
}

func TestEveryDecodeSentinelIsDistinct(t *testing.T) {
	all := []error{ErrDecodeMalformed, ErrDecodeDuplicateKey, ErrDecodeTypeUnknown, ErrDecodeFieldMissing}
	for i := range all {
		for j := range all {
			if i != j && (all[i] == all[j] || all[i].Error() == all[j].Error()) {
				t.Errorf("%v and %v are not distinct", all[i], all[j])
			}
		}
	}
}
