package relaylist

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// A reflexive slog.Any of any of these types must print the placeholder, never a hostname, an
// address, a provider or a param (D19). A TextHandler: it renders an unguarded struct with
// %+v, which walks unexported fields -- a JSON handler happens to render such a struct as {},
// and relying on that would make the guarantee a property of the handler rather than of the
// type.
func TestEveryWireTypeRendersAsThePlaceholder(t *testing.T) {
	values := map[string]any{
		"document":     NewDocument(testDocumentOpts()),
		"relay":        testRelays()[0],
		"api_endpoint": testAPIEndpoints()[1],
		"endpoint":     firstRelayOpts().Endpoints[1],
	}
	forbidden := []string{"relay-1.test.example", "192.0.2.10", "2001:db8::1", "test-provider", "Testville",
		"shadowsocks", "8443", "first"}

	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("m", slog.Any("value", value))
			line := buf.String()

			if !strings.Contains(line, "value="+redacted) {
				t.Errorf("the line does not carry the placeholder: %s", line)
			}
			for _, f := range forbidden {
				if strings.Contains(line, f) {
					t.Errorf("the line carries %q: %s", f, line)
				}
			}
		})
	}
}
