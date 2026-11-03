// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

// A relay with 20,000 distinct endpoints encodes and decodes, and the result is exactly what went
// in. The repeat check is a map keyed by (kind, port), so this stays linear; the assertion is on
// the result only, never on timing.
func TestARelayWithTwentyThousandEndpointsEncodesAndDecodes(t *testing.T) {
	const n = 20000
	eps := make([]Endpoint, 0, n)
	kinds := transport.Kinds()
	for i := range n {
		eps = append(eps, NewEndpoint(EndpointOpts{Kind: kinds[i%len(kinds)], Port: 1 + i/len(kinds)}))
	}
	ro := firstRelayOpts()
	ro.Endpoints = eps
	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(ro)}

	encoded := mustEncode(t, NewDocument(opts))
	got := mustDecode(t, encoded).Relays()[0].Endpoints()
	if len(got) != n {
		t.Fatalf("decoded %d endpoints, want %d", len(got), n)
	}
	for i, e := range got {
		if e.key() != eps[i].key() {
			t.Fatalf("endpoint %d = %v, want %v", i, e.key(), eps[i].key())
		}
	}
	if again := mustEncode(t, mustDecode(t, encoded)); again != encoded {
		t.Error("Encode(Decode(x)) != x for the 20,000-endpoint document")
	}
}
