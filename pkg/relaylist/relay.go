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
}

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
