package relaylist

import (
	"log/slog"
	"net/netip"
	"slices"
)

// NodeID is a node's stable opaque id: the contract's relays[].node_id. The only field of a
// Relay that may be named in an error or a log line (D19).
type NodeID string

// Status is a relay's published status: the contract's relays[].status. The value set is
// exactly {active, draining}; Encode refuses anything else.
type Status string

const (
	// StatusActive: clients may open new tunnels here.
	StatusActive Status = "active"
	// StatusDraining: do not open new tunnels here. Existing tunnels move when the client
	// reconnects; there is no server-side migration.
	StatusDraining Status = "draining"
)

// Valid reports whether s is one of the published statuses.
func (s Status) Valid() bool { return s == StatusActive || s == StatusDraining }

// Ownership is whether we own or rent the machine a relay runs on: the contract's
// relays[].ownership, published for transparency. The value set is exactly {owned, rented};
// Encode refuses anything else.
type Ownership string

const (
	OwnershipOwned  Ownership = "owned"
	OwnershipRented Ownership = "rented"
)

// Valid reports whether o is one of the ownership values.
func (o Ownership) Valid() bool { return o == OwnershipOwned || o == OwnershipRented }

// Relay is one entry of the contract's relays[]: a published node and how to reach it.
type Relay struct {
	nodeID         NodeID
	hostname       string
	ipv4           netip.Addr
	ipv6           netip.Addr
	wgPublicKey    string
	country        string
	city           string
	capacityWeight int
	status         Status
	ownership      Ownership
	provider       string
	endpoints      []Endpoint
	// refused is set only by Decode: why it refused this relay at relay level, or relayKept.
	// A refused relay stays in the list and is not Pickable.
	refused relayRefusal
}

// relayRefusal is why Decode refused a relay at RELAY LEVEL (contract, Strict parsing): the relay
// stays in the list, the rest of the list is kept, and it is not Pickable. One bad relay is a
// producer defect, and refusing the list would strand every client on its last-known-good list
// for it. The first violation found is the one recorded.
type relayRefusal uint8

const (
	// relayKept: no relay-level violation. The zero value, so every relay NewRelay builds is kept.
	relayKept relayRefusal = iota
	// relayRefusedFieldMalformed: a field of the relay was missing or of the wrong JSON type.
	// Decode only, since Encode's wire types cannot carry one. Every such field is left at its
	// zero value.
	relayRefusedFieldMalformed
	// relayRefusedIPv4: ipv4 is not a plain IPv4 address (Is4). IPv4() is then invalid.
	relayRefusedIPv4
	// relayRefusedIPv6: ipv6 is not a plain IPv6 address -- Is6, not IPv4-mapped, no zone. IPv6()
	// is then invalid.
	relayRefusedIPv6
	// relayRefusedWGPublicKey: wg_public_key is not standard base64 of exactly 32 bytes, in its
	// one canonical spelling. WGPublicKey() is then "".
	relayRefusedWGPublicKey
	// relayRefusedCapacityWeight: capacity_weight is outside 0..100. CapacityWeight() is then 0.
	relayRefusedCapacityWeight
	// relayRefusedEndpointRepeated: a (kind, port) is repeated. Endpoints() then holds the first
	// occurrence only.
	relayRefusedEndpointRepeated
	// relayRefusedNodeIDRepeated: another relay of the document carries the same node_id, which
	// makes readiness ambiguous. Every relay carrying it is refused.
	relayRefusedNodeIDRepeated
	// relayRefusedNodeIDEmpty: node_id is empty, so the relay cannot be matched to a readiness
	// row. Empty node_ids are not counted as repeated: this is the reason recorded on each.
	relayRefusedNodeIDEmpty
	// relayRefusedNoEndpoint: the endpoints array is empty on the wire, the same case as a relay
	// left with no known endpoint.
	relayRefusedNoEndpoint
)

// RelayOpts carries everything a relay entry says. A parameter bag, copied at construction
// and never retained.
//
// IPv6 is optional: the zero netip.Addr, or any invalid one, means the relay has no IPv6
// address, and it is written as null -- never omitted -- because the contract's type is
// "string | null".
type RelayOpts struct {
	NodeID         NodeID
	Hostname       string
	IPv4           netip.Addr
	IPv6           netip.Addr
	WGPublicKey    string
	Country        string
	City           string
	CapacityWeight int
	Status         Status
	Ownership      Ownership
	Provider       string
	Endpoints      []Endpoint
}

// NewRelay builds a Relay. TOTAL: it validates nothing; Encode refuses a relay that cannot
// be published, naming its node_id and nothing else.
func NewRelay(o RelayOpts) Relay {
	return Relay{
		nodeID:         o.NodeID,
		hostname:       o.Hostname,
		ipv4:           o.IPv4,
		ipv6:           o.IPv6,
		wgPublicKey:    o.WGPublicKey,
		country:        o.Country,
		city:           o.City,
		capacityWeight: o.CapacityWeight,
		status:         o.Status,
		ownership:      o.Ownership,
		provider:       o.Provider,
		endpoints:      slices.Clone(o.Endpoints),
	}
}

// NodeID returns the node this relay publishes.
func (r Relay) NodeID() NodeID { return r.nodeID }

// LogValue makes a Relay refuse to render itself: it holds a hostname, two addresses and a
// provider, which D19 keeps out of a log line.
func (Relay) LogValue() slog.Value { return slog.StringValue(redacted) }

// Hostname returns hostname: a LABEL, never a name to resolve. Clients connect to IPv4 or IPv6
// and never look it up, and no per-node DNS record is published -- a resolvable name would hand a
// censor a blocklist entry, and a query for it would disclose which node a client chose
// (contract, Rules; D3).
func (r Relay) Hostname() string { return r.hostname }

// IPv4 returns the relay's IPv4 address, which a client dials. On a relay Decode refused because
// ipv4 was not a plain IPv4 address, it is the invalid netip.Addr, whose methods never panic.
func (r Relay) IPv4() netip.Addr { return r.ipv4 }

// IPv6 returns the relay's IPv6 address, or the invalid netip.Addr when the wire says null, or on
// a relay Decode refused because ipv6 was not a plain IPv6 address.
func (r Relay) IPv6() netip.Addr { return r.ipv6 }

// WGPublicKey returns the node's WireGuard public key, base64, which authenticates it in the
// handshake. On a relay Decode refused because the key was not standard base64 of 32 bytes, it is
// "".
func (r Relay) WGPublicKey() string { return r.wgPublicKey }

// Country returns the ISO 3166-1 alpha-2 country.
func (r Relay) Country() string { return r.country }

// City returns the city, free text.
func (r Relay) City() string { return r.city }

// CapacityWeight returns the client selection weight, 0..100; 0 means do not pick. On a relay
// Decode refused because the weight was outside 0..100, it is 0.
func (r Relay) CapacityWeight() int { return r.capacityWeight }

// Status returns the published status. On a decoded relay it may be a value outside {active,
// draining}, kept verbatim; such a relay is not Pickable.
func (r Relay) Status() Status { return r.status }

// Ownership returns ownership, published for transparency. On a decoded relay it may be a value
// outside {owned, rented}, kept verbatim and shown as it is: no client acts on it.
func (r Relay) Ownership() Ownership { return r.ownership }

// Provider returns the hosting provider, free text, published for transparency.
func (r Relay) Provider() string { return r.provider }

// Endpoints returns the endpoints, as a copy. On a decoded relay it holds only usable endpoints:
// an endpoint of unknown kind, or of a known kind with a bad port or params, is skipped at decode,
// and of a repeated (kind, port) only the first occurrence is kept.
func (r Relay) Endpoints() []Endpoint { return slices.Clone(r.endpoints) }

// Pickable reports whether a client may choose this relay for a NEW tunnel. It is THE predicate,
// in one place: Decode refuses a list in which no relay satisfies it. The contract's definition,
// verbatim (Rules, ruled 2026-11-01) -- a relay is pickable, judged from the list alone, when all
// of these hold:
//
//   - its status is active;
//   - its capacity_weight is greater than 0;
//   - it has at least one usable endpoint;
//   - no relay-level violation applies to it.
//
// A usable endpoint is one of a known kind; Decode has already skipped every endpoint-level
// violation. A relay-level violation is recorded only by Decode, a node_id carried by another
// relay included. Readiness is applied on top by the client and never feeds this predicate.
func (r Relay) Pickable() bool {
	return r.status == StatusActive && r.capacityWeight > 0 && r.refused == relayKept &&
		slices.ContainsFunc(r.endpoints, func(e Endpoint) bool { return e.kind.Valid() })
}
