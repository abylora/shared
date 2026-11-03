// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/keyset"
	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

const placeholder = "keyset.[redacted]"

// Rule 11: the consumer never logs an entry. Every type that holds one renders as the
// placeholder through the fmt verbs a log line uses and through slog's handlers, so a careless
// line in a consumer prints no key and no address.
func TestEveryTypeRendersAsThePlaceholder(t *testing.T) {
	set := heldOne(t)
	a, _ := keyset.New(own, 4242, set)
	a.Hello()
	delta := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Delta{Delta: &keysetpb.Delta{
		FromVersion: 4242, ToVersion: 4300,
		Ops: []*keysetpb.DeltaOp{{Op: &keysetpb.DeltaOp_Upsert{Upsert: &keysetpb.Upsert{Entry: entry(0x22, 3)}}}},
	}}}
	out := a.Receive(delta, succeed)
	material := append(append(entryMaterial(entry(0x11, 2)), entryMaterial(entry(0x22, 3))...), own[:])

	for name, v := range map[string]any{"entry": set.Entries()[0], "set": set, "applier": a, "outcome": out} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(verb, v); !strings.Contains(text, placeholder) {
				t.Errorf("%s through %s does not carry the placeholder: %s", name, verb, text)
			}
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q"} {
			if found := keyMaterialIn(fmt.Sprintf(verb, v), material); len(found) > 0 {
				t.Errorf("%s through %s carries %q", name, verb, found)
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", slog.Any("v", v))
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", slog.Any("v", v))
		if found := keyMaterialIn(buf.String(), material); len(found) > 0 {
			t.Errorf("%s through slog carries %q: %s", name, found, buf.String())
		}
	}
}
