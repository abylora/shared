package relaylist

import (
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"
)

// Document is one relay list: the contract's relay_list, minus the detached signature.
//
// THERE IS NO SIGNATURE FIELD. The contract's Shape lists "signature: detached signature over
// the exact octets served", and a detached signature cannot sit inside the octets it signs. It
// travels beside the bytes, and producing it is the signing slice's.
type Document struct {
	version      int64
	generatedAt  time.Time
	expiresAt    time.Time
	apiEndpoints []APIEndpoint
	relays       []Relay
}

// DocumentOpts carries everything a document says. A parameter bag, copied at construction
// and never retained.
type DocumentOpts struct {
	Version      int64
	GeneratedAt  time.Time
	ExpiresAt    time.Time
	APIEndpoints []APIEndpoint
	Relays       []Relay
}

// NewDocument builds a Document. TOTAL: it validates nothing; Encode refuses what cannot be
// served.
//
// BOTH INSTANTS ARE NORMALISED TO UTC AND TRUNCATED TO WHOLE SECONDS. The contract says
// RFC3339 and Encode writes time.RFC3339, which has no fractional part -- so the getters
// return exactly the instants the bytes carry, and a producer storing GeneratedAt() and
// ExpiresAt() beside the artifact stores what the document says, not something that
// disagrees with it by a fraction of a second. UTC also strips the monotonic clock reading
// time.Now carries.
func NewDocument(o DocumentOpts) Document {
	return Document{
		version:      o.Version,
		generatedAt:  o.GeneratedAt.UTC().Truncate(time.Second),
		expiresAt:    o.ExpiresAt.UTC().Truncate(time.Second),
		apiEndpoints: slices.Clone(o.APIEndpoints),
		relays:       slices.Clone(o.Relays),
	}
}

// Version returns the version the document carries.
func (d Document) Version() int64 { return d.version }

// GeneratedAt returns generated_at, normalised.
func (d Document) GeneratedAt() time.Time { return d.generatedAt }

// ExpiresAt returns expires_at, normalised. Advisory under the contract's Freshness rule.
func (d Document) ExpiresAt() time.Time { return d.expiresAt }

// LogValue makes a Document refuse to render itself: it is every published node's hostname,
// addresses and provider at once (D19).
func (Document) LogValue() slog.Value { return slog.StringValue(redacted) }

// The wire structs. Unexported, so the JSON tags below are the ONLY place a field name is
// spelled, and they are the contract's names in the contract's order. The order is for a
// reader; under Reading A nothing depends on it being stable across versions.
type documentJSON struct {
	Version      int64             `json:"version"`
	GeneratedAt  string            `json:"generated_at"`
	ExpiresAt    string            `json:"expires_at"`
	APIEndpoints []apiEndpointJSON `json:"api_endpoints"`
	Relays       []relayJSON       `json:"relays"`
}

type apiEndpointJSON struct {
	Host       string           `json:"host"`
	Port       int              `json:"port"`
	Transports []FetchTransport `json:"transports"`
}

type relayJSON struct {
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	// IPv6 is a pointer with no omitempty: the contract says "string | null", so an absent
	// address is written as null rather than left out.
	IPv6           *string        `json:"ipv6"`
	WGPublicKey    string         `json:"wg_public_key"`
	Country        string         `json:"country"`
	City           string         `json:"city"`
	CapacityWeight int            `json:"capacity_weight"`
	Status         string         `json:"status"`
	Ownership      string         `json:"ownership"`
	Provider       string         `json:"provider"`
	Endpoints      []endpointJSON `json:"endpoints"`
}

type endpointJSON struct {
	// Kind is the DATA-PLANE kind, transport.Kind's string -- correctly, because this field
	// is the data plane. It is the fetch transports above that are a different enum.
	Kind   string            `json:"kind"`
	Port   int               `json:"port"`
	Params map[string]string `json:"params"`
}

// Encode returns the exact octets to store, sign and serve: compact JSON, NO TRAILING
// NEWLINE. What it returns is the artifact; nothing downstream re-encodes it.
//
// It refuses, before encoding anything, a document no client should ever receive: a version
// below 1; expires_at not after generated_at; no API endpoint, or an invalid one; no relay;
// and a relay that cannot be published -- no node_id, no WireGuard public key, no IPv4
// address or no endpoint; a status outside {active, draining}; an ownership outside {owned,
// rented}; a capacity_weight outside 0..100; or an
// endpoint whose kind is not transport.Kind.Valid, whose port is outside 1..65535, or whose
// (kind, port) repeats an earlier one. A relay refusal is a carrier type naming that relay's
// node_id and nothing else, wrapping its sentinel. Every refusal returns nil bytes.
func (d Document) Encode() ([]byte, error) {
	if d.version < 1 {
		return nil, ErrVersionNotPositive
	}
	if !d.expiresAt.After(d.generatedAt) {
		return nil, ErrExpiryNotAfterGeneration
	}
	if len(d.apiEndpoints) == 0 {
		return nil, ErrNoAPIEndpoints
	}
	if len(d.relays) == 0 {
		return nil, ErrNoRelays
	}

	wire := documentJSON{
		Version:      d.version,
		GeneratedAt:  d.generatedAt.Format(time.RFC3339),
		ExpiresAt:    d.expiresAt.Format(time.RFC3339),
		APIEndpoints: make([]apiEndpointJSON, 0, len(d.apiEndpoints)),
		Relays:       make([]relayJSON, 0, len(d.relays)),
	}

	for _, e := range d.apiEndpoints {
		if err := e.Validate(); err != nil {
			return nil, err
		}
		wire.APIEndpoints = append(wire.APIEndpoints, apiEndpointJSON{Host: e.host, Port: e.port, Transports: e.transports})
	}

	for _, r := range d.relays {
		rj, err := r.wire()
		if err != nil {
			return nil, err
		}
		wire.Relays = append(wire.Relays, rj)
	}

	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, errors.Join(ErrEncodeFailed, err)
	}

	return encoded, nil
}

// wire converts a relay to its wire form, or refuses an incomplete one.
func (r Relay) wire() (relayJSON, error) {
	if r.nodeID == "" || r.wgPublicKey == "" || !r.ipv4.IsValid() || len(r.endpoints) == 0 {
		return relayJSON{}, &RelayIncompleteError{nodeID: r.nodeID}
	}
	if !r.status.Valid() {
		return relayJSON{}, &StatusUnknownError{nodeID: r.nodeID}
	}
	if !r.ownership.Valid() {
		return relayJSON{}, &OwnershipUnknownError{nodeID: r.nodeID}
	}
	if r.capacityWeight < 0 || r.capacityWeight > 100 {
		return relayJSON{}, &CapacityWeightOutOfRangeError{nodeID: r.nodeID}
	}

	var ipv6 *string
	if r.ipv6.IsValid() {
		s := r.ipv6.String()
		ipv6 = &s
	}

	endpoints := make([]endpointJSON, 0, len(r.endpoints))
	for i, e := range r.endpoints {
		if !e.kind.Valid() {
			return relayJSON{}, &EndpointKindUnknownError{nodeID: r.nodeID}
		}
		if e.port < 1 || e.port > 65535 {
			return relayJSON{}, &EndpointPortOutOfRangeError{nodeID: r.nodeID}
		}
		// Only an exact (kind, port) repeat: kinds may share a port (contract, Rules).
		if slices.ContainsFunc(r.endpoints[:i], func(p Endpoint) bool { return p.kind == e.kind && p.port == e.port }) {
			return relayJSON{}, &EndpointRepeatedError{nodeID: r.nodeID}
		}

		params := e.params
		if params == nil {
			// The contract's type is map[string]string; an endpoint with none is {} on the
			// wire, never null. NewEndpoint preserves a nil map faithfully, so the
			// substitution happens here, at the one place the wire form is decided.
			params = map[string]string{}
		}
		endpoints = append(endpoints, endpointJSON{Kind: string(e.kind), Port: e.port, Params: params})
	}

	return relayJSON{
		NodeID:         string(r.nodeID),
		Hostname:       r.hostname,
		IPv4:           r.ipv4.String(),
		IPv6:           ipv6,
		WGPublicKey:    r.wgPublicKey,
		Country:        r.country,
		City:           r.city,
		CapacityWeight: r.capacityWeight,
		Status:         string(r.status),
		Ownership:      string(r.ownership),
		Provider:       r.provider,
		Endpoints:      endpoints,
	}, nil
}
