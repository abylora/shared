package relaylist

import "slices"

// FetchTransport is how a client FETCHES the relay list from an API endpoint: the contract's
// api_endpoints[].transports[].
//
// IT IS NOT transport.Kind, and must never be merged with it. transport.Kind describes how
// WireGuard's own datagrams travel -- the data plane, the type of Endpoint.Kind -- and
// KindPlain is documented as vanilla WireGuard over UDP, which is not a way to fetch a
// document. This enum's only required value today is https, a direct TLS fetch. A value for
// an obfuscated fetch wrapper (D18 item 2) is added when such a wrapper exists, and a name
// coinciding with a data-plane kind does not make it the same value.
type FetchTransport string

// FetchTransportHTTPS is a direct TLS fetch.
const FetchTransportHTTPS FetchTransport = "https"

// fetchTransports is the whole value set. A package-level var cloned by FetchTransports, so
// no caller can rewrite the set for every other caller in the process.
var fetchTransports = []FetchTransport{FetchTransportHTTPS}

// FetchTransports returns the value set, as a copy.
func FetchTransports() []FetchTransport { return slices.Clone(fetchTransports) }

// Valid reports whether t is one of the fetch transports.
func (t FetchTransport) Valid() bool { return slices.Contains(fetchTransports, t) }
