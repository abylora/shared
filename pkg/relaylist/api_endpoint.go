package relaylist

import (
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

// APIEndpoint is one entry of the contract's api_endpoints[]: a place a client fetches the
// next relay list from. It is what makes the list self-healing (D18 item 3) -- a working
// client learns new fetch addresses as old ones are blocked, without an update.
//
// Immutable: unexported fields, value-receiver getters, Transports cloned on the way in and
// on the way out.
type APIEndpoint struct {
	host       string
	port       int
	transports []FetchTransport
}

// APIEndpointOpts carries the three facts an API endpoint is. A parameter bag, copied at
// construction and never retained.
//
// PORT IS AN int, NOT A uint16: a uint16 moves the range refusal from a check to a
// conversion, and uint16(65537) is silently 1. EndpointOpts.Port, for the same reason.
type APIEndpointOpts struct {
	Host       string
	Port       int
	Transports []FetchTransport
}

// NewAPIEndpoint builds an APIEndpoint. TOTAL: it validates nothing, following NewEndpoint;
// Validate is the separate step a caller runs on a value built from configuration, and
// Encode runs again before writing one.
func NewAPIEndpoint(o APIEndpointOpts) APIEndpoint {
	return APIEndpoint{host: o.Host, port: o.Port, transports: slices.Clone(o.Transports)}
}

// Host returns the host exactly as configured. It is never re-canonicalised: an IPv6 literal
// keeps the spelling the operator wrote, which is what the list publishes.
func (e APIEndpoint) Host() string { return e.host }

// Port returns the TCP port.
func (e APIEndpoint) Port() int { return e.port }

// Transports returns the fetch transports, as a copy.
func (e APIEndpoint) Transports() []FetchTransport { return slices.Clone(e.transports) }

// Validate reports the first problem with the endpoint, as one of this package's sentinels.
//
// THE HOST RULES REFUSE OPERATOR MISTAKES THAT WOULD PUBLISH AN UNREACHABLE FETCH ADDRESS into
// every list, which is the silent loss of self-healing (D18 item 3). Whitespace, brackets and slashes are a pasted URL or a stray newline. A
// colon means an IPv6 literal, and then the host must be exactly one -- bare, with no zone --
// which refuses "192.0.2.1:443" and "api.example:443", a port folded into the host that the
// one-JSON-value design exists to keep separate. A hostname without a colon is accepted with
// no further syntax check: the contract says "host", and api_endpoints may carry names as
// well as raw IPs (D18 mandates raw IPs for the client's shipped bootstrap set, not here).
func (e APIEndpoint) Validate() error {
	if e.host == "" {
		return ErrAPIEndpointHostAbsent
	}
	if strings.ContainsFunc(e.host, unicode.IsSpace) || strings.ContainsAny(e.host, "[]/") {
		return ErrAPIEndpointHostMalformed
	}
	if strings.Contains(e.host, ":") {
		addr, err := netip.ParseAddr(e.host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return ErrAPIEndpointHostMalformed
		}
	}

	if e.port < 1 || e.port > 65535 {
		return ErrAPIEndpointPortOutOfRange
	}

	if len(e.transports) == 0 {
		return ErrAPIEndpointTransportsAbsent
	}
	for i, t := range e.transports {
		if !t.Valid() {
			return ErrAPIEndpointTransportUnknown
		}
		if slices.Contains(e.transports[:i], t) {
			return ErrAPIEndpointTransportRepeated
		}
	}

	return nil
}

// LogValue makes an APIEndpoint refuse to render itself, so a reflexive slog.Any prints a
// placeholder instead of an address. These addresses are published (D18), but D19 draws the
// line at an address in a log line regardless, and one rule with no exceptions is the one
// nobody has to re-derive per type.
func (APIEndpoint) LogValue() slog.Value { return slog.StringValue(redacted) }
