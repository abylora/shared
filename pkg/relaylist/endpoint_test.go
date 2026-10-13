package relaylist

import (
	"testing"

	"github.com/abylora/shared/pkg/transport"
)

// An Endpoint copies its params at construction and on the way out, so neither the caller's
// map nor a getter's result can change what it encodes.
func TestEndpointClonesItsParams(t *testing.T) {
	params := map[string]string{"cipher": "test"}
	e := NewEndpoint(EndpointOpts{Kind: transport.KindShadowsocks, Port: 8443, Params: params})

	params["cipher"] = "mutated"
	e.Params()["cipher"] = "mutated"

	if got := e.Params()["cipher"]; got != "test" {
		t.Errorf("Params()[cipher] = %q after mutating the input and the output, want test", got)
	}
	if e.Kind() != transport.KindShadowsocks {
		t.Errorf("Kind() = %q, want shadowsocks", e.Kind())
	}
	if e.Port() != 8443 {
		t.Errorf("Port() = %d, want 8443", e.Port())
	}
}
