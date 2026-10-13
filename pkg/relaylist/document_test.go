package relaylist

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/transport"
)

// Every value below is a fixture, and transparently so: addresses from the RFC 5737 / RFC 3849
// documentation ranges, hostnames under .example, a provider called test-provider. Nothing
// resembles inventory, which matters because this repository is public (D26).
const (
	firstNodeID  = NodeID("3f0c6a51-0000-4000-8000-000000000001")
	secondNodeID = NodeID("3f0c6a51-0000-4000-8000-000000000002")
)

var (
	testGeneratedAt = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	testExpiresAt   = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
)

func testKey(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func firstRelayOpts() RelayOpts {
	return RelayOpts{
		NodeID:         firstNodeID,
		Hostname:       "relay-1.test.example",
		IPv4:           netip.MustParseAddr("192.0.2.10"),
		IPv6:           netip.MustParseAddr("2001:db8::10"),
		WGPublicKey:    testKey(0x01),
		Country:        "ZZ",
		City:           "Testville",
		CapacityWeight: 50,
		Status:         StatusActive,
		Ownership:      OwnershipOwned,
		Provider:       "test-provider",
		Endpoints: []Endpoint{
			NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: 51820}),
			NewEndpoint(EndpointOpts{Kind: transport.KindShadowsocks, Port: 8443,
				Params: map[string]string{"z": "last", "a": "first"}}),
		},
	}
}

// The second relay has no IPv6 address: the zero netip.Addr, which must go on the wire as
// null.
func secondRelayOpts() RelayOpts {
	return RelayOpts{
		NodeID:         secondNodeID,
		Hostname:       "relay-2.test.example",
		IPv4:           netip.MustParseAddr("192.0.2.20"),
		WGPublicKey:    testKey(0x02),
		Country:        "ZZ",
		City:           "Testville",
		CapacityWeight: 0,
		Status:         StatusDraining,
		Ownership:      OwnershipRented,
		Provider:       "test-provider",
		Endpoints:      []Endpoint{NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 443})},
	}
}

func testAPIEndpoints() []APIEndpoint {
	return []APIEndpoint{
		NewAPIEndpoint(APIEndpointOpts{Host: "192.0.2.1", Port: 443, Transports: []FetchTransport{FetchTransportHTTPS}}),
		NewAPIEndpoint(APIEndpointOpts{Host: "2001:db8::1", Port: 443, Transports: []FetchTransport{FetchTransportHTTPS}}),
	}
}

func testRelays() []Relay {
	return []Relay{NewRelay(firstRelayOpts()), NewRelay(secondRelayOpts())}
}

func testDocumentOpts() DocumentOpts {
	return DocumentOpts{
		Version:      42,
		GeneratedAt:  testGeneratedAt,
		ExpiresAt:    testExpiresAt,
		APIEndpoints: testAPIEndpoints(),
		Relays:       testRelays(),
	}
}

// goldenDocument is the exact octet sequence for testDocumentOpts, written by hand from the
// contract's Shape. One line, compact, and NO TRAILING NEWLINE: what is encoded is what is
// stored, signed and served, so a stray byte here would be a stray byte in every list.
//
// It pins every rule the encoding has: field names and nesting; ipv6 as null rather than
// omitted ("string | null"); params as {} rather than null ("map[string]string"); RFC3339 in
// UTC at whole seconds; no signature field (a detached signature cannot sit inside the octets
// it signs); and endpoints[].kind as the data-plane kind string while transports[] is the
// fetch enum.
const goldenDocument = `{"version":42,"generated_at":"2026-10-10T12:00:00Z","expires_at":"2026-10-11T12:00:00Z",` +
	`"api_endpoints":[{"host":"192.0.2.1","port":443,"transports":["https"]},{"host":"2001:db8::1","port":443,"transports":["https"]}],` +
	`"relays":[{"node_id":"3f0c6a51-0000-4000-8000-000000000001","hostname":"relay-1.test.example","ipv4":"192.0.2.10","ipv6":"2001:db8::10",` +
	`"wg_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","country":"ZZ","city":"Testville","capacity_weight":50,` +
	`"status":"active","ownership":"owned","provider":"test-provider",` +
	`"endpoints":[{"kind":"plain","port":51820,"params":{}},{"kind":"shadowsocks","port":8443,"params":{"a":"first","z":"last"}}]},` +
	`{"node_id":"3f0c6a51-0000-4000-8000-000000000002","hostname":"relay-2.test.example","ipv4":"192.0.2.20","ipv6":null,` +
	`"wg_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","country":"ZZ","city":"Testville","capacity_weight":0,` +
	`"status":"draining","ownership":"rented","provider":"test-provider",` +
	`"endpoints":[{"kind":"quic","port":443,"params":{}}]}]}`

func TestEncodeProducesTheGoldenBytes(t *testing.T) {
	got, err := NewDocument(testDocumentOpts()).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}

	if string(got) != goldenDocument {
		t.Errorf("Encode() =\n%s\nwant\n%s", got, goldenDocument)
	}
}

// What a producer stores beside the artifact and the bytes must agree about when the list was
// generated, and the bytes are RFC3339 at whole seconds in UTC. So the
// document normalises both instants at construction and its getters return the normalised
// values -- the ones a caller then stores.
func TestNewDocumentNormalisesBothInstantsToWholeUTCSeconds(t *testing.T) {
	plusThree := time.FixedZone("UTC+3", 3*60*60)

	opts := testDocumentOpts()
	opts.GeneratedAt = time.Date(2026, 10, 10, 15, 0, 0, 999_999_999, plusThree)
	opts.ExpiresAt = time.Date(2026, 10, 11, 15, 0, 0, 500_000_000, plusThree)

	doc := NewDocument(opts)

	if want := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC); doc.GeneratedAt() != want {
		t.Errorf("GeneratedAt() = %v, want %v exactly", doc.GeneratedAt(), want)
	}
	if want := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC); doc.ExpiresAt() != want {
		t.Errorf("ExpiresAt() = %v, want %v exactly", doc.ExpiresAt(), want)
	}
	if doc.Version() != 42 {
		t.Errorf("Version() = %d, want 42", doc.Version())
	}

	got, err := doc.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}
	if string(got) != goldenDocument {
		t.Errorf("Encode() after normalisation =\n%s\nwant\n%s", got, goldenDocument)
	}
}

func TestEncodeRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DocumentOpts)
		want   error
	}{
		{"version zero", func(o *DocumentOpts) { o.Version = 0 }, ErrVersionNotPositive},
		{"expiry equal to generation", func(o *DocumentOpts) { o.ExpiresAt = o.GeneratedAt }, ErrExpiryNotAfterGeneration},
		{"expiry before generation", func(o *DocumentOpts) { o.ExpiresAt = o.GeneratedAt.Add(-time.Hour) }, ErrExpiryNotAfterGeneration},
		{"no api endpoint", func(o *DocumentOpts) { o.APIEndpoints = nil }, ErrNoAPIEndpoints},
		{"an invalid api endpoint", func(o *DocumentOpts) {
			o.APIEndpoints = append(o.APIEndpoints, NewAPIEndpoint(APIEndpointOpts{Host: "192.0.2.2", Port: 0,
				Transports: []FetchTransport{FetchTransportHTTPS}}))
		}, ErrAPIEndpointPortOutOfRange},
		{"no relay", func(o *DocumentOpts) { o.Relays = nil }, ErrNoRelays},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testDocumentOpts()
			tc.mutate(&opts)

			got, err := NewDocument(opts).Encode()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Encode() error = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
			}
		})
	}
}

// The encoder never emits "wg_public_key":"" or a relay a client cannot dial. The refusal
// names the node_id -- which D19 permits -- and NOTHING ELSE: the text is compared exactly,
// because a containment check would pass a message that also carried the hostname.
func TestEncodeRefusesAnIncompleteRelayNamingOnlyItsNodeID(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RelayOpts)
	}{
		{"no WireGuard public key", func(o *RelayOpts) { o.WGPublicKey = "" }},
		{"no IPv4 address", func(o *RelayOpts) { o.IPv4 = netip.Addr{} }},
		{"no endpoint", func(o *RelayOpts) { o.Endpoints = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ro := firstRelayOpts()
			tc.mutate(&ro)
			opts := testDocumentOpts()
			opts.Relays = []Relay{NewRelay(ro)}

			_, err := NewDocument(opts).Encode()
			if !errors.Is(err, ErrRelayIncomplete) {
				t.Fatalf("Encode() error = %v, want ErrRelayIncomplete", err)
			}

			var incomplete *RelayIncompleteError
			if !errors.As(err, &incomplete) {
				t.Fatal("errors.As cannot reach *RelayIncompleteError")
			}
			if incomplete.NodeID() != firstNodeID {
				t.Errorf("NodeID() = %q, want %q", incomplete.NodeID(), firstNodeID)
			}
			if want := "relaylist: relay is incomplete: node " + string(firstNodeID); err.Error() != want {
				t.Errorf("Error() = %q, want %q exactly", err.Error(), want)
			}
		})
	}
}

// A Relay copies its opts at construction; changing the endpoint slice it was given afterwards
// changes nothing it encodes.
func TestNewRelayClonesItsEndpoints(t *testing.T) {
	ro := secondRelayOpts()
	relay := NewRelay(ro)
	ro.Endpoints[0] = NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: 1})

	opts := testDocumentOpts()
	opts.Relays = []Relay{testRelays()[0], relay}

	got, err := NewDocument(opts).Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v, want nil", err)
	}
	if string(got) != goldenDocument {
		t.Errorf("Encode() after mutating the input slice =\n%s\nwant\n%s", got, goldenDocument)
	}
	if relay.NodeID() != secondNodeID {
		t.Errorf("NodeID() = %q, want %q", relay.NodeID(), secondNodeID)
	}
}
