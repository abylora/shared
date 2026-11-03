// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// THE RECORD IS FINAL, and these four fields are all of it (<workspace>/docs/contracts/
// key-set.md, Record). The entry is the only per-device record that reaches every node, so
// its field list is a privacy boundary. No account id is among the fields, which keeps the
// account a device belongs to off every node (invariant 2). No preshared key or other secret
// is among them, which keeps the key set a channel that carries no secret (key-set.md, No
// secrets; D16). A field is added by a contract ruling at the root, never by an edit here, and a
// fifth field fails this test.
//
// The encoding is ruled too: public_key is 32 raw bytes, tunnel_ip 4 and tunnel_ip6 16 raw
// address bytes, valid_until int64 Unix seconds. No field tracks presence, so tunnel_ip6 is
// absent exactly when it is empty, and a switch to `optional` fails here.
func TestKeySetEntryIsExactlyTheFourFieldRecordWithNoAccountIdAndNoSecret(t *testing.T) {
	md := (&KeySetEntry{}).ProtoReflect().Descriptor()
	if got := md.FullName(); got != "abylora.keyset.v1.KeySetEntry" {
		t.Errorf("the entry is %s, want abylora.keyset.v1.KeySetEntry", got)
	}

	assertExactFields(t, md, []wantField{
		{name: "public_key", number: 1, kind: protoreflect.BytesKind},
		{name: "tunnel_ip", number: 2, kind: protoreflect.BytesKind},
		{name: "tunnel_ip6", number: 3, kind: protoreflect.BytesKind},
		{name: "valid_until", number: 4, kind: protoreflect.Int64Kind},
	})
}

// TUNNEL_IP6 IS ABSENT EXACTLY WHEN IT IS EMPTY, and absence survives the wire as zero
// length, distinct from 16 zero bytes, which is the address ::. A consumer tests
// len(GetTunnelIp6()) == 0, never nil: a producer that sets []byte{} puts nothing on the wire.
func TestAnAbsentTunnelIp6StaysDistinctFromSixteenZeroBytesAcrossTheWire(t *testing.T) {
	base := func(ip6 []byte) *KeySetEntry {
		return &KeySetEntry{PublicKey: testKey(1), TunnelIp: []byte{10, 64, 1, 2}, TunnelIp6: ip6, ValidUntil: 20454 * 86400}
	}

	if got := roundTrip(t, base(nil)).GetTunnelIp6(); len(got) != 0 {
		t.Errorf("an absent tunnel_ip6 decoded as %d bytes, want 0", len(got))
	}
	if got := roundTrip(t, base([]byte{})).GetTunnelIp6(); len(got) != 0 {
		t.Errorf("an empty tunnel_ip6 decoded as %d bytes, want 0", len(got))
	}
	if got := roundTrip(t, base(make([]byte, 16))).GetTunnelIp6(); !bytes.Equal(got, make([]byte, 16)) {
		t.Errorf("tunnel_ip6 :: decoded as %x, want 16 zero bytes", got)
	}
}

// Every field of the record survives the wire unchanged.
func TestKeySetEntryRoundTripsEveryField(t *testing.T) {
	want := &KeySetEntry{
		PublicKey:  testKey(7),
		TunnelIp:   []byte{10, 64, 1, 2},
		TunnelIp6:  []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		ValidUntil: 20454 * 86400, // 2026-01-01T00:00:00Z
	}
	if got := roundTrip(t, want); !proto.Equal(got, want) {
		t.Errorf("round trip gave %v, want %v", got, want)
	}
}
