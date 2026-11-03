// SPDX-License-Identifier: AGPL-3.0-only

package relaylist

import (
	"errors"
	"net/netip"
	"testing"
)

// Encode refuses every relay-level violation Decode scopes (contract, Strict parsing: "Encode
// refuses every one of these"), through the same classifier, so the producer can never publish a
// relay a client would set aside. Each row is a value today's Encode accepted.
func TestEncodeRefusesARelayLevelViolation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RelayOpts)
		check  func(*testing.T, RelayOpts)
	}{
		{"ipv4 is an IPv6 address", func(o *RelayOpts) { o.IPv4 = netip.MustParseAddr("2001:db8::10") },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayIPv4InvalidError](t, o, ErrRelayIPv4Invalid)
			}},
		{"ipv4 is IPv4-mapped IPv6", func(o *RelayOpts) { o.IPv4 = netip.MustParseAddr("::ffff:192.0.2.10") },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayIPv4InvalidError](t, o, ErrRelayIPv4Invalid)
			}},
		{"ipv6 is an IPv4 address", func(o *RelayOpts) { o.IPv6 = netip.MustParseAddr("192.0.2.10") },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayIPv6InvalidError](t, o, ErrRelayIPv6Invalid)
			}},
		{"ipv6 is IPv4-mapped", func(o *RelayOpts) { o.IPv6 = netip.MustParseAddr("::ffff:192.0.2.10") },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayIPv6InvalidError](t, o, ErrRelayIPv6Invalid)
			}},
		{"ipv6 has a zone", func(o *RelayOpts) { o.IPv6 = netip.MustParseAddr("fe80::1%eth0") },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayIPv6InvalidError](t, o, ErrRelayIPv6Invalid)
			}},
		{"wg_public_key is not base64", func(o *RelayOpts) { o.WGPublicKey = "not base64" },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayWGPublicKeyInvalidError](t, o, ErrRelayWGPublicKeyInvalid)
			}},
		{"wg_public_key is 31 bytes", func(o *RelayOpts) { o.WGPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==" },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayWGPublicKeyInvalidError](t, o, ErrRelayWGPublicKeyInvalid)
			}},
		{"wg_public_key is unpadded", func(o *RelayOpts) { o.WGPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" },
			func(t *testing.T, o RelayOpts) {
				requireRelayRefusal[*RelayWGPublicKeyInvalidError](t, o, ErrRelayWGPublicKeyInvalid)
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := firstRelayOpts()
			tc.mutate(&o)
			tc.check(t, o)
		})
	}
}

// A node_id on more than one relay is refused at document level, after every relay's own checks,
// naming the FIRST REPEAT in relay order -- the first relay whose node_id an earlier relay already
// carries. Here relays [A, B, B', A'] name B, not A.
func TestEncodeRefusesARepeatedNodeIDNamingTheFirstRepeat(t *testing.T) {
	a, b := firstRelayOpts(), firstRelayOpts()
	b.NodeID = secondNodeID
	b.IPv4 = netip.MustParseAddr("192.0.2.20")
	bAgain, aAgain := b, a
	bAgain.IPv4 = netip.MustParseAddr("192.0.2.21")
	aAgain.IPv4 = netip.MustParseAddr("192.0.2.11")

	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(a), NewRelay(b), NewRelay(bAgain), NewRelay(aAgain)}

	got, err := NewDocument(opts).Encode()
	if !errors.Is(err, ErrRelayRepeated) {
		t.Fatalf("Encode() error = %v, want ErrRelayRepeated", err)
	}
	if got != nil {
		t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
	}
	var repeated *RelayRepeatedError
	if !errors.As(err, &repeated) {
		t.Fatal("errors.As cannot reach *RelayRepeatedError")
	}
	if repeated.NodeID() != secondNodeID {
		t.Errorf("NodeID() = %q, want the first repeat, %q", repeated.NodeID(), secondNodeID)
	}
	if want := ErrRelayRepeated.Error() + ": node " + string(secondNodeID); err.Error() != want {
		t.Errorf("Error() = %q, want %q exactly", err.Error(), want)
	}
}

// Every relay's own refusal is reported before the document-level ones.
func TestEncodeReportsARelaysOwnRefusalBeforeARepeatedNodeID(t *testing.T) {
	bad := firstRelayOpts()
	bad.IPv6 = netip.MustParseAddr("192.0.2.99")
	opts := testDocumentOpts()
	opts.Relays = []Relay{NewRelay(firstRelayOpts()), NewRelay(bad)}

	if _, err := NewDocument(opts).Encode(); !errors.Is(err, ErrRelayIPv6Invalid) {
		t.Errorf("Encode() error = %v, want ErrRelayIPv6Invalid before ErrRelayRepeated", err)
	}
}

// Found by FuzzEncodeDecodeRoundTrip (its input is kept in testdata/fuzz as a regression seed):
// encoding/json writes a string that is not valid UTF-8 as U+FFFD, so the signed artifact would not
// say what the producer was given, and Encode(Decode(x)) != x. Encode refuses it instead, in every
// string the document carries, with a document-level sentinel: the offending string may be the
// node_id itself, so no carrier names one.
func TestEncodeRefusesTextThatIsNotValidUTF8(t *testing.T) {
	const bad = "x\xffy"
	cases := map[string]func(*DocumentOpts){
		"an api endpoint host": func(o *DocumentOpts) {
			o.APIEndpoints = []APIEndpoint{NewAPIEndpoint(APIEndpointOpts{Host: bad, Port: 443, Transports: []FetchTransport{FetchTransportHTTPS}})}
		},
		"a node_id":     func(o *DocumentOpts) { r := firstRelayOpts(); r.NodeID = bad; o.Relays = []Relay{NewRelay(r)} },
		"a hostname":    func(o *DocumentOpts) { r := firstRelayOpts(); r.Hostname = bad; o.Relays = []Relay{NewRelay(r)} },
		"a country":     func(o *DocumentOpts) { r := firstRelayOpts(); r.Country = bad; o.Relays = []Relay{NewRelay(r)} },
		"a city":        func(o *DocumentOpts) { r := firstRelayOpts(); r.City = bad; o.Relays = []Relay{NewRelay(r)} },
		"a provider":    func(o *DocumentOpts) { r := firstRelayOpts(); r.Provider = bad; o.Relays = []Relay{NewRelay(r)} },
		"a param key":   func(o *DocumentOpts) { o.Relays = []Relay{relayWithParam(bad, "v")} },
		"a param value": func(o *DocumentOpts) { o.Relays = []Relay{relayWithParam("k", bad)} },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			opts := testDocumentOpts()
			mutate(&opts)
			got, err := NewDocument(opts).Encode()
			if err != ErrTextNotUTF8 {
				t.Fatalf("Encode() error = %v, want ErrTextNotUTF8 (bare)", err)
			}
			if got != nil {
				t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
			}
		})
	}
}

func relayWithParam(k, v string) Relay {
	r := firstRelayOpts()
	r.Endpoints = []Endpoint{NewEndpoint(EndpointOpts{Kind: "plain", Port: 51820, Params: map[string]string{k: v}})}

	return NewRelay(r)
}
