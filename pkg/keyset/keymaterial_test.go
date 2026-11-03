// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
	"github.com/abylora/shared/pkg/keyset/keysetvectors"
)

// keyMaterialIn returns every encoding of every value in material that text contains: hex in
// either case, the four base64 alphabets, the raw bytes, and the address text of a 4- or 16-byte
// value. Values shorter than 4 bytes are skipped; their encodings are too short to mean anything.
func keyMaterialIn(text string, material [][]byte) []string {
	var found []string
	for _, b := range material {
		if len(b) < 4 {
			continue
		}
		forms := []string{
			hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
			base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
			string(b),
		}
		switch len(b) {
		case 4:
			forms = append(forms, netip.AddrFrom4([4]byte(b)).String())
		case 16:
			forms = append(forms, netip.AddrFrom16([16]byte(b)).String())
		}
		for _, f := range forms {
			if strings.Contains(text, f) {
				found = append(found, f)
			}
		}
	}

	return found
}

func assertNoKeyMaterial(t *testing.T, err error, material [][]byte) {
	t.Helper()
	if err == nil {
		t.Fatal("no error to check")
	}
	if found := keyMaterialIn(err.Error(), material); len(found) > 0 {
		t.Errorf("error %q carries key material %q", err, found)
	}
}

func entryMaterial(e *keysetpb.KeySetEntry) [][]byte {
	return [][]byte{e.GetPublicKey(), e.GetTunnelIp(), e.GetTunnelIp6()}
}

func messageMaterial(m *keysetpb.ControlPlaneMessage) [][]byte {
	out := entryMaterial(m.GetUpsert().GetEntry())
	for _, op := range m.GetDelta().GetOps() {
		out = append(out, entryMaterial(op.GetUpsert().GetEntry())...)
		out = append(out, op.GetRemove().GetPublicKey())
	}

	return out
}

func consumerMaterial(c keysetvectors.ConsumerCase) [][]byte {
	out := [][]byte{c.OwnPublicKey[:]}
	for _, e := range append(append([]*keysetpb.KeySetEntry{}, c.InitialSet...), c.Final.Set...) {
		out = append(out, entryMaterial(e)...)
	}
	for _, s := range c.Steps {
		if !s.Hello {
			out = append(out, messageMaterial(s.Message)...)
		}
	}

	return out
}

// The scan finds each encoding it claims to, so a clean result means something.
func TestKeyMaterialInFindsEveryEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	ip := []byte{10, 64, 1, 2}
	ip6 := []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	for _, form := range []string{
		hex.EncodeToString(key), strings.ToUpper(hex.EncodeToString(key)),
		base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key),
		string(key), "10.64.1.2", "0a400102", "fd00::1",
	} {
		if len(keyMaterialIn("keyset: x "+form+" y", [][]byte{key, ip, ip6})) == 0 {
			t.Errorf("found nothing in a text carrying %q", form)
		}
	}
	if found := keyMaterialIn("keyset: a delta's from_version is not the cursor", [][]byte{key, ip, ip6}); len(found) != 0 {
		t.Errorf("found %q in a text carrying none", found)
	}
}
