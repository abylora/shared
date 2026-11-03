package relaylist

import (
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"time"
	"unicode/utf8"
)

// DocumentType is the relay list's statement type, written as the document's first field,
// _type. The signing certificate carries a different _type, so an object signed by the wrong
// key can never parse as the other kind (contract, The signing certificate). WIRE CONTRACT:
// changing it breaks every deployed client.
const DocumentType = "abylora.relay-list"

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

// The wire structs. Unexported, so the JSON tags below are the only place a field name is
// spelled for WRITING, and they are the contract's names in the contract's order. decode.go
// spells them for reading, and TestDecodeOfTheGoldenDocumentReEncodesToTheGoldenBytes holds the
// two spellings together. The order is for a
// reader; under Reading A nothing depends on it being stable across versions. That includes
// _type: it is first by convention, for a reader; no verifier may depend on its position. A
// decoder finds it by key. encoding/json writes fields in declaration order, so Type stays the
// first field here, and the golden test keeps it first.
type documentJSON struct {
	Type         string            `json:"_type"`
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
// node_id and nothing else, wrapping its sentinel. The relay-level rules are classifyRelay's,
// the ones Decode scopes with: an empty node_id, no endpoint, a zero ipv4 or an empty key are
// *RelayIncompleteError as in v0.3.0; an ipv4 that is not plain IPv4, an ipv6 that is not plain
// IPv6 and a malformed key have carriers of their own. Any string that is not valid UTF-8 is
// ErrTextNotUTF8, bare. Then the document-level rules: a node_id carried by more than one relay,
// as a *RelayRepeatedError naming the first repeat in relay order; and a document in which no
// relay is Pickable, with ErrNoPickableRelay, bare: "drain or zero-weight every node" cannot be
// published.
// Every refusal returns nil bytes.
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
		Type:         DocumentType,
		Version:      d.version,
		GeneratedAt:  d.generatedAt.Format(time.RFC3339),
		ExpiresAt:    d.expiresAt.Format(time.RFC3339),
		APIEndpoints: make([]apiEndpointJSON, 0, len(d.apiEndpoints)),
		Relays:       make([]relayJSON, 0, len(d.relays)),
	}

	for _, e := range d.apiEndpoints {
		if !utf8.ValidString(e.host) {
			return nil, ErrTextNotUTF8
		}
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
	// The document-level rules, after every relay's own: a repeated node_id (repeatedNodeIDs,
	// the rule Decode scopes with), then no pickable relay (Pickable, the one predicate).
	if _, first := repeatedNodeIDs(d.relays); first != "" {
		return nil, &RelayRepeatedError{nodeID: first}
	}
	if !slices.ContainsFunc(d.relays, Relay.Pickable) {
		return nil, ErrNoPickableRelay
	}

	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, errors.Join(ErrEncodeFailed, err)
	}

	return encoded, nil
}

// wire converts a relay to its wire form, or refuses it. The relay-level rules are classifyRelay's,
// the same function Decode scopes with; then the producer-only rules (status and ownership, which
// a client keeps verbatim) and the endpoint-level ones (a kind or port no client can use).
func (r Relay) wire() (relayJSON, error) {
	if !r.textValid() {
		return relayJSON{}, ErrTextNotUTF8
	}
	if err := r.relayLevelRefusal(); err != nil {
		return relayJSON{}, err
	}
	if !r.status.Valid() {
		return relayJSON{}, &StatusUnknownError{nodeID: r.nodeID}
	}
	if !r.ownership.Valid() {
		return relayJSON{}, &OwnershipUnknownError{nodeID: r.nodeID}
	}

	var ipv6 *string
	if r.ipv6.IsValid() {
		s := r.ipv6.String()
		ipv6 = &s
	}

	endpoints := make([]endpointJSON, 0, len(r.endpoints))
	for _, e := range r.endpoints {
		if !e.kind.Valid() {
			return relayJSON{}, &EndpointKindUnknownError{nodeID: r.nodeID}
		}
		if e.port < 1 || e.port > 65535 {
			return relayJSON{}, &EndpointPortOutOfRangeError{nodeID: r.nodeID}
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

// APIEndpoints returns where to fetch the next list, as a copy.
func (d Document) APIEndpoints() []APIEndpoint { return slices.Clone(d.apiEndpoints) }

// Relays returns the published nodes, as a copy.
func (d Document) Relays() []Relay { return slices.Clone(d.relays) }

// relayLevelRefusal classifies the relay with classifyRelay and maps the reason to its named
// carrier. The cases v0.3.0 already refused -- an empty node_id, no endpoint, a zero ipv4 and an
// empty wg_public_key -- keep their *RelayIncompleteError, so a consumer matching ErrRelayIncomplete
// sees no change; only a present but invalid address or key gets a carrier of its own.
func (r Relay) relayLevelRefusal() error {
	why := classifyRelay(relayFacts{
		nodeID:         r.nodeID,
		endpointsEmpty: len(r.endpoints) == 0,
		ipv4:           r.ipv4,
		ipv6Given:      r.ipv6.IsValid(),
		ipv6:           r.ipv6,
		wgPublicKey:    r.wgPublicKey,
		capacityWeight: int64(r.capacityWeight),
		endpoints:      r.endpoints,
	})

	switch {
	case why == relayKept:
		return nil
	case why == relayRefusedIPv4 && r.ipv4.IsValid():
		return &RelayIPv4InvalidError{nodeID: r.nodeID}
	case why == relayRefusedIPv6:
		return &RelayIPv6InvalidError{nodeID: r.nodeID}
	case why == relayRefusedWGPublicKey && r.wgPublicKey != "":
		return &RelayWGPublicKeyInvalidError{nodeID: r.nodeID}
	case why == relayRefusedCapacityWeight:
		return &CapacityWeightOutOfRangeError{nodeID: r.nodeID}
	case why == relayRefusedEndpointRepeated:
		return &EndpointRepeatedError{nodeID: r.nodeID}
	}

	// relayRefusedNodeIDEmpty, relayRefusedNoEndpoint, a zero ipv4 or an empty key. The two
	// Decode-only reasons, a malformed field and a repeated node_id, cannot be produced from a
	// Relay's own values, and a repeated node_id is refused at document level.
	return &RelayIncompleteError{nodeID: r.nodeID}
}

// textValid reports whether every string the relay carries is valid UTF-8. encoding/json would
// write an invalid one as U+FFFD, and then the artifact would not say what the producer was given.
func (r Relay) textValid() bool {
	for _, s := range []string{string(r.nodeID), r.hostname, r.wgPublicKey, r.country, r.city, string(r.status),
		string(r.ownership), r.provider} {
		if !utf8.ValidString(s) {
			return false
		}
	}
	for _, e := range r.endpoints {
		for k, v := range e.params {
			if !utf8.ValidString(k) || !utf8.ValidString(v) {
				return false
			}
		}
	}

	return true
}
