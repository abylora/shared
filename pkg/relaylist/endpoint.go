package relaylist

import (
	"log/slog"
	"maps"

	"github.com/abylora/shared/pkg/transport"
)

// Endpoint is one entry of the contract's relays[].endpoints[]: a data-plane transport a
// relay listens on, and on which port.
//
// IT IS DELIBERATELY NOT transport.Endpoint. The list carries no per-endpoint host -- every
// endpoint of a relay is reached at that relay's ipv4 or ipv6 -- so a client composes a
// transport.Endpoint from the relay's address plus this entry's kind, port and params. A
// host field here would let two sources disagree about where a relay is.
type Endpoint struct {
	kind   transport.Kind
	port   int
	params map[string]string
}

// EndpointOpts carries the three facts an endpoint is. A parameter bag, copied at
// construction and never retained.
//
// PORT IS AN int, NOT A uint16, for APIEndpointOpts's reason: the range refusal is a check
// in Encode, not a silent conversion.
type EndpointOpts struct {
	Kind   transport.Kind
	Port   int
	Params map[string]string
}

// NewEndpoint builds an Endpoint. TOTAL: it validates nothing; Encode refuses an unknown
// kind, an out-of-range port and a repeated (kind, port) within one relay.
//
// A nil Params is preserved as nil; it goes on the wire as {}, never null.
func NewEndpoint(o EndpointOpts) Endpoint {
	return Endpoint{kind: o.Kind, port: o.Port, params: maps.Clone(o.Params)}
}

// Kind returns the data-plane transport kind.
func (e Endpoint) Kind() transport.Kind { return e.kind }

// Port returns the port the relay listens on for this kind.
func (e Endpoint) Port() int { return e.port }

// Params returns the transport-specific parameters, as a copy. Opaque to the list, and never
// a secret (contract, Rules).
func (e Endpoint) Params() map[string]string { return maps.Clone(e.params) }

// LogValue makes an Endpoint refuse to render itself, for APIEndpoint's reason: one rule with
// no exceptions is the one nobody has to re-derive per type.
func (Endpoint) LogValue() slog.Value { return slog.StringValue(redacted) }
