// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

func TestTheRelayGettersReturnWhatItWasBuiltFrom(t *testing.T) {
	o := firstRelayOpts()
	r := NewRelay(o)

	if r.Hostname() != o.Hostname || r.IPv4() != o.IPv4 || r.IPv6() != o.IPv6 || r.WGPublicKey() != o.WGPublicKey ||
		r.Country() != o.Country || r.City() != o.City || r.CapacityWeight() != o.CapacityWeight ||
		r.Status() != o.Status || r.Ownership() != o.Ownership || r.Provider() != o.Provider {
		t.Error("a getter disagrees with the opts the relay was built from")
	}
	if got := r.Endpoints(); len(got) != 2 || got[1].Kind() != transport.KindShadowsocks || got[1].Port() != 8443 {
		t.Errorf("Endpoints() = %v, want the two endpoints of the opts", got)
	}
}

func TestEndpointsAndTheDocumentSlicesAreCopies(t *testing.T) {
	r := NewRelay(firstRelayOpts())
	r.Endpoints()[0] = NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 1})
	if r.Endpoints()[0].Kind() != transport.KindPlain {
		t.Error("mutating Endpoints() changed the relay")
	}

	d := NewDocument(testDocumentOpts())
	d.Relays()[0] = Relay{}
	d.APIEndpoints()[0] = APIEndpoint{}
	if d.Relays()[0].NodeID() != firstNodeID || d.APIEndpoints()[0].Host() != "192.0.2.1" {
		t.Error("mutating a document slice changed the document")
	}
}

// Each row is one contract sentence: draining means do not open new tunnels here;
// capacity_weight 0 means do not pick; a relay whose status is unknown is not pickable; a relay
// left with no known endpoint cannot be picked.
func TestPickable(t *testing.T) {
	unknownOnly := []Endpoint{NewEndpoint(EndpointOpts{Kind: "future-kind", Port: 443})}
	cases := []struct {
		name   string
		mutate func(*RelayOpts)
		want   bool
	}{
		{"active, weighted, with a known endpoint", func(*RelayOpts) {}, true},
		{"draining", func(o *RelayOpts) { o.Status = StatusDraining }, false},
		{"capacity_weight 0", func(o *RelayOpts) { o.CapacityWeight = 0 }, false},
		{"an unknown status", func(o *RelayOpts) { o.Status = "future-status" }, false},
		{"no endpoint", func(o *RelayOpts) { o.Endpoints = nil }, false},
		{"only an endpoint of unknown kind", func(o *RelayOpts) { o.Endpoints = unknownOnly }, false},
	}

	for _, tc := range cases {
		o := firstRelayOpts()
		tc.mutate(&o)
		if got := NewRelay(o).Pickable(); got != tc.want {
			t.Errorf("%s: Pickable() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
