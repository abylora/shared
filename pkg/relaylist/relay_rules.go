// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"encoding/base64"
	"net/netip"
)

// THE RELAY-LEVEL RULES, ONE SPELLING EACH (contract, Strict parsing). Encode and Decode both
// classify a relay through classifyRelay: Decode records the reason and keeps the relay
// unpickable, and Encode refuses the relay, so the producer can never publish a relay a client
// would set aside. Decode's field sanitising calls the same predicates.

// ipv4Plain is the ipv4 rule: a plain IPv4 address (Is4). The invalid netip.Addr fails it.
func ipv4Plain(a netip.Addr) bool { return a.Is4() }

// ipv6Plain is the ipv6 rule: a plain IPv6 address -- Is6, not IPv4-mapped, no zone.
func ipv6Plain(a netip.Addr) bool { return a.Is6() && !a.Is4In6() && a.Zone() == "" }

// wireGuardKey is the wg_public_key rule: standard padded base64 of exactly 32 bytes, in its one
// canonical spelling. The re-encoding comparison refuses what the standard decoder forgives, an
// embedded newline and non-zero padding bits.
func wireGuardKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)

	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}

// capacityWeightInRange is the capacity_weight rule: 0..100. 0 is legitimate and means "do not
// pick".
func capacityWeightInRange(w int64) bool { return w >= 0 && w <= 100 }

// endpointRepeated is the duplicate rule: an exact (kind, port) twice among endpoints. Kinds may
// share a port. A map, so a relay with many endpoints costs linear time.
func endpointRepeated(endpoints []Endpoint) bool {
	seen := make(map[endpointKey]bool, len(endpoints))
	for _, e := range endpoints {
		if seen[e.key()] {
			return true
		}
		seen[e.key()] = true
	}

	return false
}

// relayFacts is what classifyRelay judges, as Decode read it or as Encode was given it.
type relayFacts struct {
	// fieldMalformed: a field of the relay was missing or of the wrong JSON type. Decode only.
	fieldMalformed bool
	nodeID         NodeID
	// endpointsEmpty: the endpoints list is empty -- on the wire, for Decode.
	endpointsEmpty bool
	ipv4           netip.Addr
	// ipv6Given: ipv6 is present (not null); only then is the ipv6 rule applied.
	ipv6Given      bool
	ipv6           netip.Addr
	wgPublicKey    string
	capacityWeight int64
	// endpoints are the usable endpoints, repeats included. A skipped endpoint is not an
	// endpoint, so it never counts towards a duplicate (contract, Strict parsing).
	endpoints []Endpoint
}

// classifyRelay returns the first relay-level rule f violates, or relayKept. The order is the
// order the contract lists them, and the first violation is the one recorded.
func classifyRelay(f relayFacts) relayRefusal {
	switch {
	case f.fieldMalformed:
		return relayRefusedFieldMalformed
	case f.nodeID == "":
		return relayRefusedNodeIDEmpty
	case f.endpointsEmpty:
		return relayRefusedNoEndpoint
	case !ipv4Plain(f.ipv4):
		return relayRefusedIPv4
	case f.ipv6Given && !ipv6Plain(f.ipv6):
		return relayRefusedIPv6
	case !wireGuardKey(f.wgPublicKey):
		return relayRefusedWGPublicKey
	case !capacityWeightInRange(f.capacityWeight):
		return relayRefusedCapacityWeight
	case endpointRepeated(f.endpoints):
		return relayRefusedEndpointRepeated
	}

	return relayKept
}

// repeatedNodeIDs is the document-level node_id rule, in one pass: repeated holds every node_id
// that more than one relay carries, and firstRepeat is the first repeat in relay order -- the
// node_id of the first relay that an earlier relay already carries -- or "" if none. An empty
// node_id is its own relay-level violation and is not counted here.
func repeatedNodeIDs(relays []Relay) (repeated map[NodeID]bool, firstRepeat NodeID) {
	seen := make(map[NodeID]bool, len(relays))
	repeated = map[NodeID]bool{}
	for _, r := range relays {
		if r.nodeID == "" {
			continue
		}
		if seen[r.nodeID] {
			repeated[r.nodeID] = true
			if firstRepeat == "" {
				firstRepeat = r.nodeID
			}
		}
		seen[r.nodeID] = true
	}

	return repeated, firstRepeat
}
