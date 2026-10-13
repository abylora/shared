package transport

import (
	"slices"
	"testing"
)

// The value set is wire contract: the signed relay list carries these strings verbatim, and
// control-plane drift-tests its OpenAPI enum and Postgres enum against Kinds(). A kind added
// or renamed without this test changing is one nobody decided.
func TestKindsIsExactlyTheFourKinds(t *testing.T) {
	want := []Kind{"plain", "udp2tcp", "shadowsocks", "quic"}
	if got := Kinds(); !slices.Equal(got, want) {
		t.Errorf("Kinds() = %v, want %v", got, want)
	}
}

func TestKindsReturnsACopy(t *testing.T) {
	got := Kinds()
	got[0] = "mutated"

	if Kinds()[0] != KindPlain {
		t.Error("mutating Kinds()'s result changed the value set")
	}
}

func TestValid(t *testing.T) {
	for _, k := range Kinds() {
		if !k.Valid() {
			t.Errorf("%q.Valid() = false, want true", k)
		}
	}
	for _, k := range []Kind{"", "https", "PLAIN", "plain ", "wireguard"} {
		if k.Valid() {
			t.Errorf("%q.Valid() = true, want false", k)
		}
	}
}
