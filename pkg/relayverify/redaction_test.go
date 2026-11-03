// SPDX-License-Identifier: AGPL-3.0-only

package relayverify

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// A reflexive slog.Any of any of these types must print the placeholder, never a hostname, an
// address, a city or a provider (D19). A TextHandler: it renders an unguarded struct with %+v,
// which walks unexported fields and byte slices.
func TestEveryVerifierTypeRendersAsThePlaceholder(t *testing.T) {
	values := map[string]any{
		"bundle":   baseBundle(t),
		"pins":     fixturePins(t),
		"verifier": fixtureVerifier(t),
		"verified": requireAccepted(t, baseBundle(t)),
	}
	forbidden := []string{"test-1.example", "192.0.2.10", "Stockholm", "Example"}

	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("m", slog.Any("value", value))
			line := buf.String()

			if !strings.Contains(line, "value="+redacted) {
				t.Errorf("the line does not carry the placeholder: %.200s", line)
			}
			for _, f := range forbidden {
				if strings.Contains(line, f) {
					t.Errorf("the line carries %q", f)
				}
			}
		})
	}
}
