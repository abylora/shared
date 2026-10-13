package relaylist

import (
	"errors"
	"testing"
)

func validAPIEndpointOpts() APIEndpointOpts {
	return APIEndpointOpts{Host: "192.0.2.1", Port: 443, Transports: []FetchTransport{FetchTransportHTTPS}}
}

// One row per refusal, each asserting its OWN sentinel: a check that is dropped, or two that
// collapse into one, fails a row. The addresses are RFC 5737 / RFC 3849 documentation ranges.
func TestAPIEndpointValidateRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*APIEndpointOpts)
		want   error
	}{
		{"no host", func(o *APIEndpointOpts) { o.Host = "" }, ErrAPIEndpointHostAbsent},
		{"leading whitespace", func(o *APIEndpointOpts) { o.Host = " 192.0.2.1" }, ErrAPIEndpointHostMalformed},
		{"trailing newline", func(o *APIEndpointOpts) { o.Host = "192.0.2.1\n" }, ErrAPIEndpointHostMalformed},
		{"a port folded into an IPv4 host", func(o *APIEndpointOpts) { o.Host = "192.0.2.1:443" }, ErrAPIEndpointHostMalformed},
		{"a port folded into a hostname", func(o *APIEndpointOpts) { o.Host = "api.example:443" }, ErrAPIEndpointHostMalformed},
		{"URL brackets around IPv6", func(o *APIEndpointOpts) { o.Host = "[2001:db8::1]" }, ErrAPIEndpointHostMalformed},
		{"a URL", func(o *APIEndpointOpts) { o.Host = "https://api.example/" }, ErrAPIEndpointHostMalformed},
		{"an IPv6 zone", func(o *APIEndpointOpts) { o.Host = "fe80::1%eth0" }, ErrAPIEndpointHostMalformed},
		{"port zero", func(o *APIEndpointOpts) { o.Port = 0 }, ErrAPIEndpointPortOutOfRange},
		{"port above 65535", func(o *APIEndpointOpts) { o.Port = 65536 }, ErrAPIEndpointPortOutOfRange},
		{"no transports", func(o *APIEndpointOpts) { o.Transports = nil }, ErrAPIEndpointTransportsAbsent},
		{"a data-plane kind", func(o *APIEndpointOpts) { o.Transports = []FetchTransport{"plain"} }, ErrAPIEndpointTransportUnknown},
		{"https twice", func(o *APIEndpointOpts) {
			o.Transports = []FetchTransport{FetchTransportHTTPS, FetchTransportHTTPS}
		}, ErrAPIEndpointTransportRepeated},
	}

	all := []error{
		ErrAPIEndpointHostAbsent, ErrAPIEndpointHostMalformed, ErrAPIEndpointPortOutOfRange,
		ErrAPIEndpointTransportsAbsent, ErrAPIEndpointTransportUnknown, ErrAPIEndpointTransportRepeated,
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := validAPIEndpointOpts()
			tc.mutate(&opts)

			err := NewAPIEndpoint(opts).Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
			for _, other := range all {
				if other != tc.want && errors.Is(err, other) {
					t.Errorf("Validate() also matches %v", other)
				}
			}
		})
	}
}

// THE CASE THE ONE-JSON-VALUE DECISION EXISTS FOR. D18 makes raw IPv6 literals mandatory, and
// no colon-delimited encoding parses 2a01:4f8::1:443 unambiguously. A bare literal is accepted
// and its spelling is preserved exactly as the operator wrote it -- never re-canonicalised --
// so what was configured is what the list publishes.
func TestAPIEndpointAcceptsABareIPv6LiteralAndPreservesItsSpelling(t *testing.T) {
	for _, host := range []string{"2a01:4f8::1", "2001:DB8:0:0::1", "192.0.2.1", "api.example"} {
		opts := validAPIEndpointOpts()
		opts.Host = host

		e := NewAPIEndpoint(opts)
		if err := e.Validate(); err != nil {
			t.Errorf("Validate() for %q = %v, want nil", host, err)
		}
		if e.Host() != host {
			t.Errorf("Host() = %q, want %q exactly", e.Host(), host)
		}
	}
}

func TestAPIEndpointAcceptsTheBoundaryPorts(t *testing.T) {
	for _, port := range []int{1, 65535} {
		opts := validAPIEndpointOpts()
		opts.Port = port
		if err := NewAPIEndpoint(opts).Validate(); err != nil {
			t.Errorf("Validate() for port %d = %v, want nil", port, err)
		}
	}
}

func TestAPIEndpointClonesItsTransports(t *testing.T) {
	opts := validAPIEndpointOpts()
	e := NewAPIEndpoint(opts)

	opts.Transports[0] = "mutated"
	got := e.Transports()
	got[0] = "mutated"

	if e.Transports()[0] != FetchTransportHTTPS {
		t.Errorf("Transports()[0] = %q after mutating the input and the output, want https", e.Transports()[0])
	}
	if e.Port() != 443 {
		t.Errorf("Port() = %d, want 443", e.Port())
	}
}
