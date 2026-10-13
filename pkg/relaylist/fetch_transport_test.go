package relaylist

import (
	"slices"
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

// The contract: the fetch enum's only required value today is https. A value added without
// this test changing is a value added without anyone deciding it.
func TestTheFetchTransportsAreExactlyHTTPS(t *testing.T) {
	want := []FetchTransport{"https"}
	if got := FetchTransports(); !slices.Equal(got, want) {
		t.Errorf("FetchTransports() = %v, want %v", got, want)
	}
	if !FetchTransportHTTPS.Valid() {
		t.Error("https is not Valid()")
	}
}

// A name coinciding with a data-plane kind does not make it a fetch transport: "plain" is
// vanilla WireGuard over UDP, which is not a way to fetch a document. transport.Kinds() is
// the source of truth the contract names, so this covers every data-plane kind there is.
func TestNoFetchTransportIsADataPlaneKind(t *testing.T) {
	for _, kind := range transport.Kinds() {
		if FetchTransport(kind).Valid() {
			t.Errorf("data-plane kind %q is a valid fetch transport", kind)
		}
	}
}

func TestFetchTransportsReturnsACopy(t *testing.T) {
	got := FetchTransports()
	got[0] = "mutated"

	if FetchTransports()[0] != FetchTransportHTTPS {
		t.Error("mutating FetchTransports()'s result changed the value set")
	}
}
