package relaylist

import (
	"errors"
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

// nodeIDError is what every relay refusal's carrier is: an error naming a node and nothing
// else.
type nodeIDError interface {
	error
	NodeID() NodeID
}

// requireRelayRefusal encodes a document whose only relay is built from opts, and requires
// the refusal to return nil bytes, match sentinel through errors.Is, reach a carrier of type
// E through errors.As, and read EXACTLY sentinel + ": node " + node_id. The text is compared
// exactly because a containment check would pass a message that also carried the hostname,
// the offending value or anything else of the relay (D19).
func requireRelayRefusal[E nodeIDError](t *testing.T, opts RelayOpts, sentinel error) {
	t.Helper()

	doc := testDocumentOpts()
	doc.Relays = []Relay{NewRelay(opts)}

	got, err := NewDocument(doc).Encode()
	if !errors.Is(err, sentinel) {
		t.Fatalf("Encode() error = %v, want %v", err, sentinel)
	}
	if got != nil {
		t.Errorf("Encode() returned %d bytes alongside its refusal, want none", len(got))
	}

	var carrier E
	if !errors.As(err, &carrier) {
		t.Fatalf("errors.As cannot reach %T", carrier)
	}
	if carrier.NodeID() != opts.NodeID {
		t.Errorf("NodeID() = %q, want %q", carrier.NodeID(), opts.NodeID)
	}
	if want := sentinel.Error() + ": node " + string(opts.NodeID); err.Error() != want {
		t.Errorf("Error() = %q, want %q exactly", err.Error(), want)
	}
}

func TestEncodeRefusesAnEndpointOfUnknownKind(t *testing.T) {
	for _, kind := range []transport.Kind{"", "https", "PLAIN", "wireguard"} {
		t.Run(string(kind), func(t *testing.T) {
			opts := firstRelayOpts()
			opts.Endpoints = append(opts.Endpoints, NewEndpoint(EndpointOpts{Kind: kind, Port: 9000}))
			requireRelayRefusal[*EndpointKindUnknownError](t, opts, ErrEndpointKindUnknown)
		})
	}
}

func TestEncodeRefusesAnEndpointPortOutOfRange(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		opts := firstRelayOpts()
		opts.Endpoints = []Endpoint{NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: port})}
		requireRelayRefusal[*EndpointPortOutOfRangeError](t, opts, ErrEndpointPortOutOfRange)
	}
}

func TestEncodeAcceptsTheBoundaryEndpointPorts(t *testing.T) {
	opts := firstRelayOpts()
	opts.Endpoints = []Endpoint{
		NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: 1}),
		NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 65535}),
	}
	doc := testDocumentOpts()
	doc.Relays = []Relay{NewRelay(opts)}

	if _, err := NewDocument(doc).Encode(); err != nil {
		t.Errorf("Encode() error = %v, want nil", err)
	}
}

// Only an EXACT repeat of (kind, port) is refused -- the params do not rescue it, since a
// client could not tell the two apart by where it dials.
func TestEncodeRefusesARepeatedKindAndPort(t *testing.T) {
	opts := firstRelayOpts()
	opts.Endpoints = []Endpoint{
		NewEndpoint(EndpointOpts{Kind: transport.KindShadowsocks, Port: 8443, Params: map[string]string{"a": "1"}}),
		NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: 51820}),
		NewEndpoint(EndpointOpts{Kind: transport.KindShadowsocks, Port: 8443, Params: map[string]string{"a": "2"}}),
	}
	requireRelayRefusal[*EndpointRepeatedError](t, opts, ErrEndpointRepeated)
}

// Ruled 2026-10-09 for ABY-38 (contract, Rules): kinds may share a port, and the list does
// not check whether the listeners can coexist. plain/51820 + quic/51820 is published as
// declared.
func TestEncodeAcceptsDifferentKindsSharingAPort(t *testing.T) {
	opts := firstRelayOpts()
	opts.Endpoints = []Endpoint{
		NewEndpoint(EndpointOpts{Kind: transport.KindPlain, Port: 51820}),
		NewEndpoint(EndpointOpts{Kind: transport.KindQUIC, Port: 51820}),
	}
	doc := testDocumentOpts()
	doc.Relays = []Relay{NewRelay(opts)}

	if _, err := NewDocument(doc).Encode(); err != nil {
		t.Errorf("Encode() error = %v, want nil", err)
	}
}

// LOAD-BEARING. control-plane converts its node status with a plain Status(n.Status()) and no
// switch, because its guard forbids spelling the publishable statuses a second time. This
// refusal is therefore the only thing that stops a staged or retired node reaching the wire,
// and those are the two strings tested.
func TestEncodeRefusesAStatusOutsideActiveAndDraining(t *testing.T) {
	for _, status := range []Status{"staged", "retired"} {
		t.Run(string(status), func(t *testing.T) {
			opts := firstRelayOpts()
			opts.Status = status
			requireRelayRefusal[*StatusUnknownError](t, opts, ErrStatusUnknown)
		})
	}
}

func TestEncodeRefusesAnOwnershipOutsideOwnedAndRented(t *testing.T) {
	for _, ownership := range []Ownership{"", "leased", "OWNED"} {
		t.Run(string(ownership), func(t *testing.T) {
			opts := firstRelayOpts()
			opts.Ownership = ownership
			requireRelayRefusal[*OwnershipUnknownError](t, opts, ErrOwnershipUnknown)
		})
	}
}
