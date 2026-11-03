// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/transport"
)

func mustDecode(t *testing.T, s string) Document {
	t.Helper()
	d, err := Decode([]byte(s))
	if err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	return d
}

func mustEncode(t *testing.T, d Document) string {
	t.Helper()
	b, err := d.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	return string(b)
}

// replaceOnce fails unless old occurs exactly once, so a mutation can never silently miss.
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if n := strings.Count(s, old); n != 1 {
		t.Fatalf("%q occurs %d times, want 1", old, n)
	}

	return strings.Replace(s, old, new, 1)
}

// Decode is the inverse of Encode on every document Encode can produce. This test also holds
// decode.go's read spelling of every field name to the wire structs' tags: a misspelt read name
// fails here as a missing field.
func TestDecodeOfTheGoldenDocumentReEncodesToTheGoldenBytes(t *testing.T) {
	if got := mustEncode(t, mustDecode(t, goldenDocument)); got != goldenDocument {
		t.Errorf("Encode(Decode(golden)) =\n%s\nwant\n%s", got, goldenDocument)
	}
}

// The contract's vector L, copied verbatim from <workspace>/docs/contracts/relay-list.md.
const contractVectorL = `{"_type":"abylora.relay-list","version":1,"generated_at":"2026-01-02T00:00:00Z","expires_at":"2026-01-03T00:00:00Z","api_endpoints":[{"host":"192.0.2.1","port":443,"transports":["https"]}],"relays":[{"node_id":"00000000-0000-4000-8000-000000000001","hostname":"test-1.example","ipv4":"192.0.2.10","ipv6":null,"wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","country":"SE","city":"Stockholm","capacity_weight":100,"status":"active","ownership":"owned","provider":"Example","endpoints":[{"kind":"plain","port":51820,"params":{}}]}]}`

func TestDecodeOfVectorLYieldsItsFields(t *testing.T) {
	d := mustDecode(t, contractVectorL)
	if len(d.Relays()) != 1 || len(d.APIEndpoints()) != 1 {
		t.Fatalf("decoded %d relays and %d API endpoints, want 1 and 1", len(d.Relays()), len(d.APIEndpoints()))
	}
	r := d.Relays()[0]

	if d.Version() != 1 || !d.GeneratedAt().Equal(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) ||
		!d.ExpiresAt().Equal(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)) {
		t.Error("a document field disagrees with vector L")
	}
	if r.NodeID() != "00000000-0000-4000-8000-000000000001" || r.Hostname() != "test-1.example" ||
		r.IPv4() != netip.MustParseAddr("192.0.2.10") || r.IPv6().IsValid() ||
		r.WGPublicKey() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || r.Country() != "SE" ||
		r.City() != "Stockholm" || r.CapacityWeight() != 100 || r.Status() != StatusActive ||
		r.Ownership() != OwnershipOwned || r.Provider() != "Example" || !r.Pickable() {
		t.Error("a relay field disagrees with vector L")
	}
	if eps := r.Endpoints(); len(eps) != 1 || eps[0].Kind() != transport.KindPlain || eps[0].Port() != 51820 || len(eps[0].Params()) != 0 {
		t.Errorf("Endpoints() = %v, want plain/51820 with no params", eps)
	}
	if a := d.APIEndpoints()[0]; a.Host() != "192.0.2.1" || a.Port() != 443 || len(a.Transports()) != 1 || a.Transports()[0] != FetchTransportHTTPS {
		t.Error("the API endpoint disagrees with vector L")
	}
}

// encoding/json matches struct fields case-insensitively: decoded into documentJSON,
// {"version":42,"Version":99} yields 99 -- a parser differential. Decode matches exactly, so
// "Version" is an unknown field and is ignored.
func TestDecodeMatchesFieldNamesExactly(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, `"version":42,`, `"version":42,"Version":99,`))
	if d.Version() != 42 {
		t.Errorf("Version() = %d, want 42", d.Version())
	}
}

// Contract, Strict parsing: in both documents a duplicate key is refused, at any depth. Keys are
// compared after unescaping, as every decoder will see them.
func TestDecodeRefusesADuplicateKeyAtAnyDepth(t *testing.T) {
	cases := map[string][2]string{
		"top level":       {`"version":42,`, `"version":42,"version":42,`},
		"escaped":         {`"version":42,`, `"version":42,"\u0076ersion":42,`},
		"an unknown key":  {`"version":42,`, `"version":42,"x":1,"x":1,`},
		"api endpoint":    {`"host":"192.0.2.1","port":443,`, `"host":"192.0.2.1","port":443,"port":443,`},
		"relay":           {`"ipv4":"192.0.2.10",`, `"ipv4":"192.0.2.10","ipv4":"192.0.2.66",`},
		"endpoint":        {`"kind":"plain","port":51820,`, `"kind":"plain","port":51820,"port":51820,`},
		"endpoint params": {`{"a":"first",`, `{"a":"first","a":"first",`},
	}

	for name, m := range cases {
		if _, err := Decode([]byte(replaceOnce(t, goldenDocument, m[0], m[1]))); err != ErrDecodeDuplicateKey {
			t.Errorf("%s: Decode() error = %v, want ErrDecodeDuplicateKey", name, err)
		}
	}
}

// Contract, Strict parsing: an unknown field is ignored at every level.
func TestDecodeIgnoresAnUnknownFieldAtEveryLevel(t *testing.T) {
	cases := map[string][2]string{
		"top level":    {`"version":42,`, `"version":42,"future_field":{"nested":[1,2]},`},
		"api endpoint": {`"host":"192.0.2.1",`, `"host":"192.0.2.1","future_field":true,`},
		"relay":        {`"city":"Testville","capacity_weight":50,`, `"city":"Testville","future_field":null,"capacity_weight":50,`},
		"endpoint":     {`"kind":"plain","port":51820,`, `"kind":"plain","future_field":"x","port":51820,`},
	}

	for name, m := range cases {
		if got := mustEncode(t, mustDecode(t, replaceOnce(t, goldenDocument, m[0], m[1]))); got != goldenDocument {
			t.Errorf("%s: the unknown field was not simply ignored:\n%s", name, got)
		}
	}
}

const firstEndpoints = `"endpoints":[{"kind":"plain","port":51820,"params":{}},`

// Contract, Strict parsing: an endpoint of an unknown kind is skipped.
func TestDecodeSkipsAnEndpointOfUnknownKind(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, firstEndpoints, firstEndpoints+`{"kind":"future-kind","port":443,"params":{}},`))

	for _, e := range d.Relays()[0].Endpoints() {
		if e.Kind() == "future-kind" {
			t.Error("the unknown kind is among the relay's endpoints")
		}
	}
	if got := mustEncode(t, d); got != goldenDocument {
		t.Errorf("after skipping, Encode() =\n%s\nwant the golden document", got)
	}
}

// A future kind may define port and params differently, so this client does not read them.
func TestDecodeSkipsAnUnknownKindWithoutReadingItsPortOrParams(t *testing.T) {
	for _, e := range []string{`{"kind":"future-kind","port":0,"params":"x"},`, `{"kind":"future-kind"},`} {
		mustDecode(t, replaceOnce(t, goldenDocument, firstEndpoints, firstEndpoints+e))
	}
}

// Contract, Strict parsing: a relay left with no known endpoint stays in the list but cannot be
// picked.
func TestDecodeKeepsARelayWithNoKnownEndpointButItIsNotPickable(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, `"endpoints":[{"kind":"quic","port":443,"params":{}}]`,
		`"endpoints":[{"kind":"future-kind","port":443,"params":{}}]`))

	if len(d.Relays()) != 2 || len(d.Relays()[1].Endpoints()) != 0 || d.Relays()[1].Pickable() {
		t.Error("want the relay kept, with no endpoint, and not pickable")
	}
}

// Contract, Strict parsing: a relay whose status is unknown is not pickable.
// The second relay is made pickable, because a list that leaves no pickable relay is refused.
func TestDecodeKeepsAnUnknownStatusAndItIsNotPickable(t *testing.T) {
	in := replaceOnce(t, goldenDocument, `"capacity_weight":0,"status":"draining"`, `"capacity_weight":10,"status":"active"`)
	d := mustDecode(t, replaceOnce(t, in, `"status":"active","ownership":"owned"`, `"status":"future-status","ownership":"owned"`))

	if r := d.Relays()[0]; r.Status() != "future-status" || r.Pickable() {
		t.Errorf("Status() = %q, Pickable() = %v; want future-status, false", r.Status(), r.Pickable())
	}
}

const firstTransports = `"host":"192.0.2.1","port":443,"transports":["https"]`

// Contract, Strict parsing: an api_endpoints transport of unknown value is skipped.
func TestDecodeSkipsAFetchTransportOfUnknownValue(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, firstTransports,
		`"host":"192.0.2.1","port":443,"transports":["future-fetch","https"]`))

	if got := d.APIEndpoints()[0].Transports(); len(got) != 1 || got[0] != FetchTransportHTTPS {
		t.Errorf("Transports() = %v, want [https]", got)
	}
}

// Contract, Strict parsing (ruled 2026-11-01): an unknown value is lenient only where no client
// acts on it. ownership, published for transparency, is kept verbatim and shown as it is.
func TestDecodeKeepsAnUnknownOwnershipVerbatim(t *testing.T) {
	d := mustDecode(t, replaceOnce(t, goldenDocument, `"ownership":"owned"`, `"ownership":"future-ownership"`))

	if r := d.Relays()[0]; r.Ownership() != "future-ownership" || r.Ownership().Valid() || !r.Pickable() {
		t.Errorf("Ownership() = %q, Pickable() = %v; want future-ownership kept, and the relay still pickable",
			r.Ownership(), r.Pickable())
	}
}

// Contract, Strict parsing (ruled 2026-11-01): a client that receives a node_id on more than
// one relay makes every relay carrying it unpickable and keeps the rest, because two relays with
// one node_id make readiness ambiguous. The list stays valid.
func TestARelayWhoseNodeIDIsRepeatedIsNotPickableAndTheListStays(t *testing.T) {
	pickable := firstRelayOpts()
	other := firstRelayOpts()
	other.NodeID = secondNodeID
	other.IPv4 = netip.MustParseAddr("192.0.2.20")
	repeat := firstRelayOpts()
	repeat.NodeID = "3f0c6a51-0000-4000-8000-000000000003"
	repeat.IPv4 = netip.MustParseAddr("192.0.2.30")

	// Encode refuses a repeated node_id, so the repeat is written into the octets afterwards.
	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(pickable), NewRelay(other), NewRelay(repeat)}
	in := replaceOnce(t, mustEncode(t, NewDocument(opts)), `"node_id":"3f0c6a51-0000-4000-8000-000000000003"`,
		`"node_id":"`+string(firstNodeID)+`"`)
	d := mustDecode(t, in)

	relays := d.Relays()
	if len(relays) != 3 {
		t.Fatalf("decoded %d relays, want all 3 kept", len(relays))
	}
	if relays[0].Pickable() || relays[2].Pickable() {
		t.Error("a relay whose node_id is repeated is pickable")
	}
	if !relays[1].Pickable() {
		t.Error("the relay with its own node_id is not pickable")
	}
}
