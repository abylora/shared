// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"net/netip"
	"testing"
)

// Contract, Rules (relay-list.md at workspace root c2166da): the producer refuses a list with no
// pickable relay, as it refuses one with no relays. Adopting it would strand every client exactly
// as an empty list would, so "drain or zero-weight every node" cannot be published. Encode uses
// Relay.Pickable, the same predicate Decode does.
func TestEncodeRefusesADocumentWithNoPickableRelay(t *testing.T) {
	onlyWeightZero := firstRelayOpts()
	onlyWeightZero.CapacityWeight = 0

	firstDraining := firstRelayOpts()
	firstDraining.Status = StatusDraining

	cases := map[string][]Relay{
		"the only relay has weight 0": {NewRelay(onlyWeightZero)},
		"every relay is draining":     {NewRelay(firstDraining), NewRelay(secondRelayOpts())},
	}

	for name, relays := range cases {
		t.Run(name, func(t *testing.T) {
			opts := testDocumentOpts()
			opts.Relays = relays

			got, err := NewDocument(opts).Encode()
			if err != ErrNoPickableRelay {
				t.Fatalf("Encode() error = %v, want ErrNoPickableRelay (bare)", err)
			}
			if got != nil {
				t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
			}
		})
	}
}

// One pickable relay is enough, however many others are draining or weighted 0.
func TestEncodeAcceptsOnePickableRelayAmongUnpickableOnes(t *testing.T) {
	weightZero := firstRelayOpts()
	weightZero.NodeID = "3f0c6a51-0000-4000-8000-000000000003"
	weightZero.IPv4 = netip.MustParseAddr("192.0.2.30")
	weightZero.CapacityWeight = 0

	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(secondRelayOpts()), NewRelay(weightZero), NewRelay(firstRelayOpts())}

	if _, err := NewDocument(opts).Encode(); err != nil {
		t.Errorf("Encode() error = %v, want nil", err)
	}
}
