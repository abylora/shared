// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// NODE TO CONTROL PLANE IS HELLO AND APPLIED, AND NOTHING ELSE. Neither carries a key, an
// address or a time. A node reports versions and one aggregate gauge, never which entries it
// holds or refuses, so nothing it says can become a per-device, per-node record. D34 refused
// per-key acknowledgements for exactly that reason (invariant 5, D19, D22). An arm added here
// must never carry a key.
func TestNodeMessageIsHelloOrAppliedAndNothingElse(t *testing.T) {
	assertExactFields(t, (&NodeMessage{}).ProtoReflect().Descriptor(), []wantField{
		{name: "hello", number: 1, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Hello", oneof: "body", presence: true},
		{name: "applied", number: 2, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Applied", oneof: "body", presence: true},
	})
}

// HELLO IS THE CURSOR AND NOTHING ELSE, a uint64 where 0 means "holds nothing" (rule 9).
func TestHelloCarriesOnlyTheHeldVersion(t *testing.T) {
	assertExactFields(t, (&Hello{}).ProtoReflect().Descriptor(), []wantField{
		{name: "held_version", number: 1, kind: protoreflect.Uint64Kind},
	})
}

// APPLIED IS THE CURSOR AFTER AN APPLY AND ONE GAUGE. skipped is how many entries of the
// applied set the node currently refuses under rules 11 and 12: one aggregate number that
// never names an entry, and the only way a producer defect becomes visible.
func TestAppliedCarriesTheVersionAndAnAggregateSkippedGauge(t *testing.T) {
	assertExactFields(t, (&Applied{}).ProtoReflect().Descriptor(), []wantField{
		{name: "version", number: 1, kind: protoreflect.Uint64Kind},
		{name: "skipped", number: 2, kind: protoreflect.Uint64Kind},
	})
}

// A HELLO HOLDING NOTHING IS STILL A HELLO. held_version 0 is an empty Hello, and the arm is
// still on the wire: tag 1, length 0. It is never confused with no message.
func TestAHelloHoldingNothingIsStillAHelloOnTheWire(t *testing.T) {
	b, err := proto.Marshal(&NodeMessage{Body: &NodeMessage_Hello{Hello: &Hello{HeldVersion: 0}}})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if want := []byte{0x0a, 0x00}; !bytes.Equal(b, want) {
		t.Errorf("Hello{0} encoded as %x, want %x", b, want)
	}

	got := &NodeMessage{}
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if got.GetHello() == nil {
		t.Error("Hello{0} decoded with no hello arm")
	}
}

// Every node message survives the wire unchanged.
func TestEveryNodeMessageArmRoundTrips(t *testing.T) {
	for name, want := range map[string]*NodeMessage{
		"hello":   {Body: &NodeMessage_Hello{Hello: &Hello{HeldVersion: 41}}},
		"applied": {Body: &NodeMessage_Applied{Applied: &Applied{Version: 42, Skipped: 3}}},
	} {
		if got := roundTrip(t, want); !proto.Equal(got, want) {
			t.Errorf("%s: round trip gave %v, want %v", name, got, want)
		}
	}
}
