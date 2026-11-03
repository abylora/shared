// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"net/netip"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/transport"
)

// THE ROUND-TRIP INVARIANT, for every document Encode accepts: Decode succeeds; every relay is
// pickable after decoding exactly as Pickable said before encoding; and Encode(Decode(x)) == x.
// Encode and Decode share their rules, so a document the producer can write is one every client
// reads back unchanged.
//
// `go test` runs only the seed corpus. Fuzzing is run by hand, bounded:
//
//	go test -run '^$' -fuzz FuzzEncodeDecodeRoundTrip -fuzztime 60s -parallel 2 ./pkg/relaylist/
func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	type seed struct {
		version, generated, lifetime             int64
		hostname, ipv4, ipv6, key, country, city string
		weight                                   int
		status, ownership, provider, kind        string
		port                                     int
		paramKey, paramValue, apiHost            string
		apiPort                                  int
		sibling                                  bool
	}
	add := func(s seed) {
		f.Add(s.version, s.generated, s.lifetime, s.hostname, s.ipv4, s.ipv6, s.key, s.country, s.city, s.weight,
			s.status, s.ownership, s.provider, s.kind, s.port, s.paramKey, s.paramValue, s.apiHost, s.apiPort, s.sibling)
	}
	golden := seed{
		version: 42, generated: 1760097600, lifetime: 86400, // generated_at and the lifetime in seconds
		hostname: "relay-1.test.example", ipv4: "192.0.2.10", ipv6: "2001:db8::10", key: testKey(0x01),
		country: "ZZ", city: "Testville", weight: 50, status: "active", ownership: "owned", provider: "test-provider",
		kind: "plain", port: 51820, paramKey: "a", paramValue: "first",
		apiHost: "192.0.2.1", apiPort: 443, sibling: true,
	}
	add(golden)
	for _, edit := range []func(*seed){
		func(s *seed) { s.status = "draining" },               // the fuzzed relay unpickable, a sibling pickable
		func(s *seed) { s.weight = 0 },                        // weight 0
		func(s *seed) { s.ipv6 = "" },                         // no IPv6
		func(s *seed) { s.city = "G\u00f6teborg <&> \u2028" }, // text encoding/json escapes
		func(s *seed) { s.ipv4 = "2001:db8::10" },             // an ipv4 that is IPv6: Encode refuses it
		func(s *seed) { s.sibling = false },                   // no sibling
		func(s *seed) { s.apiHost = "api.staging.example" },   // a bare hostname as the fetch host
	} {
		s := golden
		edit(&s)
		add(s)
	}

	f.Fuzz(func(t *testing.T, version, generated, lifetime int64, hostname, ipv4, ipv6, key, country, city string,
		weight int, status, ownership, provider, kind string, port int, paramKey, paramValue, apiHost string,
		apiPort int, sibling bool,
	) {
		v4, _ := netip.ParseAddr(ipv4)
		v6, _ := netip.ParseAddr(ipv6)
		fuzzed := NewRelay(RelayOpts{
			NodeID: firstNodeID, Hostname: hostname, IPv4: v4, IPv6: v6, WGPublicKey: key,
			Country: country, City: city, CapacityWeight: weight, Status: Status(status), Ownership: Ownership(ownership),
			Provider: provider,
			Endpoints: []Endpoint{NewEndpoint(EndpointOpts{
				Kind: transport.Kind(kind), Port: port, Params: map[string]string{paramKey: paramValue},
			})},
		})
		relays := []Relay{fuzzed}
		if sibling {
			relays = append(relays, NewRelay(secondRelayOpts()), siblingRelay())
		}

		doc := NewDocument(DocumentOpts{
			Version:      version,
			GeneratedAt:  time.Unix(generated, 0),
			ExpiresAt:    time.Unix(generated, 0).Add(time.Duration(lifetime) * time.Second),
			APIEndpoints: []APIEndpoint{NewAPIEndpoint(APIEndpointOpts{Host: apiHost, Port: apiPort, Transports: []FetchTransport{FetchTransportHTTPS}})},
			Relays:       relays,
		})
		x, err := doc.Encode()
		if err != nil {
			return // Only a document Encode accepts is in scope.
		}

		decoded, err := Decode(x)
		if err != nil {
			t.Fatalf("Encode accepted a document Decode refuses: %v\n%s", err, x)
		}
		after := decoded.Relays()
		if len(after) != len(relays) {
			t.Fatalf("decoded %d relays, want %d", len(after), len(relays))
		}
		for i := range relays {
			if after[i].Pickable() != relays[i].Pickable() {
				t.Errorf("relay %d: Pickable() = %v after decoding, %v before encoding\n%s",
					i, after[i].Pickable(), relays[i].Pickable(), x)
			}
		}
		again, err := decoded.Encode()
		if err != nil {
			t.Fatalf("Encode(Decode(x)) error = %v\n%s", err, x)
		}
		if string(again) != string(x) {
			t.Errorf("Encode(Decode(x)) != x\n got %s\nwant %s", again, x)
		}
	})
}

// siblingRelay is a pickable relay with its own node_id, so a document stays publishable when the
// fuzzed relay is not pickable.
func siblingRelay() Relay {
	o := firstRelayOpts()
	o.NodeID = "3f0c6a51-0000-4000-8000-000000000009"
	o.IPv4 = netip.MustParseAddr("192.0.2.90")

	return NewRelay(o)
}
