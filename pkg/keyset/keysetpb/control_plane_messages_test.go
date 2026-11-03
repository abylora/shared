// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// CONTROL PLANE TO NODE IS THE CONTRACT'S FIVE ARMS, numbered in the contract's order. The
// numbers are wire contract: a renumbering fails here.
func TestControlPlaneMessageIsTheFiveContractArms(t *testing.T) {
	arm := func(name protoreflect.Name, n protoreflect.FieldNumber, msg protoreflect.FullName) wantField {
		return wantField{name: name, number: n, kind: protoreflect.MessageKind, message: msg, oneof: "body", presence: true}
	}
	assertExactFields(t, (&ControlPlaneMessage{}).ProtoReflect().Descriptor(), []wantField{
		arm("snapshot_begin", 1, "abylora.keyset.v1.SnapshotBegin"),
		arm("upsert", 2, "abylora.keyset.v1.Upsert"),
		arm("snapshot_end", 3, "abylora.keyset.v1.SnapshotEnd"),
		arm("delta", 4, "abylora.keyset.v1.Delta"),
		arm("heartbeat", 5, "abylora.keyset.v1.Heartbeat"),
	})
}

func TestSnapshotBeginCarriesOnlyItsVersion(t *testing.T) {
	assertExactFields(t, (&SnapshotBegin{}).ProtoReflect().Descriptor(), []wantField{
		{name: "version", number: 1, kind: protoreflect.Uint64Kind},
	})
}

func TestUpsertCarriesOnlyAnEntry(t *testing.T) {
	assertExactFields(t, (&Upsert{}).ProtoReflect().Descriptor(), []wantField{
		{name: "entry", number: 1, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.KeySetEntry", presence: true},
	})
}

func TestSnapshotEndCarriesOnlyItsVersion(t *testing.T) {
	assertExactFields(t, (&SnapshotEnd{}).ProtoReflect().Descriptor(), []wantField{
		{name: "version", number: 1, kind: protoreflect.Uint64Kind},
	})
}

func TestDeltaCarriesTwoVersionsAndAnOrderedListOfOps(t *testing.T) {
	assertExactFields(t, (&Delta{}).ProtoReflect().Descriptor(), []wantField{
		{name: "from_version", number: 1, kind: protoreflect.Uint64Kind},
		{name: "to_version", number: 2, kind: protoreflect.Uint64Kind},
		{name: "ops", number: 3, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.DeltaOp", repeated: true},
	})
}

func TestDeltaOpIsUpsertOrRemove(t *testing.T) {
	assertExactFields(t, (&DeltaOp{}).ProtoReflect().Descriptor(), []wantField{
		{name: "upsert", number: 1, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Upsert", oneof: "op", presence: true},
		{name: "remove", number: 2, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Remove", oneof: "op", presence: true},
	})
}

func TestRemoveCarriesOnlyAPublicKey(t *testing.T) {
	assertExactFields(t, (&Remove{}).ProtoReflect().Descriptor(), []wantField{
		{name: "public_key", number: 1, kind: protoreflect.BytesKind},
	})
}

func TestHeartbeatCarriesOnlyTheCurrentVersion(t *testing.T) {
	assertExactFields(t, (&Heartbeat{}).ProtoReflect().Descriptor(), []wantField{
		{name: "current_version", number: 1, kind: protoreflect.Uint64Kind},
	})
}

// ONE UPSERT, TWO PLACES, ONE MEANING (rule 2). The snapshot arm and the delta op are the same
// message type, so the applier has one way to apply an upsert, and a field added to it cannot
// apply in one place and not the other. Where it may appear is the state machine's business,
// not the type's.
func TestDeltaOpUpsertIsTheSameUpsertAsTheSnapshotArm(t *testing.T) {
	snapshot := (&ControlPlaneMessage{}).ProtoReflect().Descriptor().Fields().ByName("upsert").Message()
	delta := (&DeltaOp{}).ProtoReflect().Descriptor().Fields().ByName("upsert").Message()
	if snapshot != delta {
		t.Errorf("the snapshot arm is a %s and the delta op a %s; they must be one type", snapshot.FullName(), delta.FullName())
	}
}

// THE FILE DEFINES THE CONTRACT'S MESSAGES AND NOTHING ELSE: no further message, no enum, no
// extension. A message added here is a contract change ruled at the root first.
func TestTheFileDefinesExactlyTheContractsMessagesAndNothingElse(t *testing.T) {
	fd := File_abylora_keyset_v1_keyset_proto
	if fd.Path() != "abylora/keyset/v1/keyset.proto" || fd.Package() != "abylora.keyset.v1" {
		t.Errorf("the file is %s in package %s", fd.Path(), fd.Package())
	}

	var got []string
	for i := range fd.Messages().Len() {
		got = append(got, string(fd.Messages().Get(i).Name()))
	}
	want := []string{
		"Applied", "ControlPlaneMessage", "Delta", "DeltaOp", "Heartbeat", "Hello",
		"KeySetEntry", "NodeMessage", "Remove", "SnapshotBegin", "SnapshotEnd", "Upsert",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the file defines %v, want %v", got, want)
	}
	if fd.Enums().Len() != 0 || fd.Extensions().Len() != 0 {
		t.Errorf("the file defines %d enums and %d extensions, want none", fd.Enums().Len(), fd.Extensions().Len())
	}
}

// The checker's one refusal that KeySetEntry cannot drive: a message-typed field of the wrong
// type.
func TestAssertExactFieldsReportsAWrongMessageTypeOnce(t *testing.T) {
	r := &recorder{}
	assertExactFields(r, (&DeltaOp{}).ProtoReflect().Descriptor(), []wantField{
		{name: "upsert", number: 1, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Remove", oneof: "op", presence: true},
		{name: "remove", number: 2, kind: protoreflect.MessageKind, message: "abylora.keyset.v1.Remove", oneof: "op", presence: true},
	})
	if len(r.errors) != 1 {
		t.Errorf("reported %d times, want once: %q", len(r.errors), r.errors)
	}
}

func begin(v uint64) *ControlPlaneMessage {
	return &ControlPlaneMessage{Body: &ControlPlaneMessage_SnapshotBegin{SnapshotBegin: &SnapshotBegin{Version: v}}}
}

func end(v uint64) *ControlPlaneMessage {
	return &ControlPlaneMessage{Body: &ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &SnapshotEnd{Version: v}}}
}

// AN EMPTY SNAPSHOT'S TWO MESSAGES ARE EACH REPRESENTABLE AND ON THE WIRE. An empty snapshot is
// SnapshotBegin followed by SnapshotEnd with the same version (rule 1), and it means "the set
// is empty", never "no change". This proves each of the two messages survives the wire as
// itself; that nothing comes between them is the stream's state machine, which this package
// does not hold.
func TestAnEmptySnapshotsTwoMessagesAreEachRepresentableAndOnTheWire(t *testing.T) {
	sequence := []*ControlPlaneMessage{begin(5), end(5)}

	if got := roundTrip(t, sequence[0]).GetSnapshotBegin(); got == nil || got.GetVersion() != 5 {
		t.Errorf("SnapshotBegin{5} decoded as %v", got)
	}
	if got := roundTrip(t, sequence[1]).GetSnapshotEnd(); got == nil || got.GetVersion() != 5 {
		t.Errorf("SnapshotEnd{5} decoded as %v", got)
	}
}

// AN ARM IS ON THE WIRE EVEN WHEN EVERY FIELD IN IT IS ZERO, because every arm is a message:
// tag, then length 0. A message carrying an arm is therefore never mistaken for no message,
// which encodes as nothing at all.
func TestAnArmIsOnTheWireEvenWhenEveryFieldInItIsZero(t *testing.T) {
	for name, tc := range map[string]struct {
		m    *ControlPlaneMessage
		want []byte
	}{
		"no message":      {&ControlPlaneMessage{}, []byte{}},
		"SnapshotBegin{}": {begin(0), []byte{0x0a, 0x00}},
		"SnapshotEnd{}":   {end(0), []byte{0x1a, 0x00}},
		"an empty Delta":  {&ControlPlaneMessage{Body: &ControlPlaneMessage_Delta{Delta: &Delta{}}}, []byte{0x22, 0x00}},
		"Heartbeat{}":     {&ControlPlaneMessage{Body: &ControlPlaneMessage_Heartbeat{Heartbeat: &Heartbeat{}}}, []byte{0x2a, 0x00}},
	} {
		b, err := proto.Marshal(tc.m)
		if err != nil {
			t.Fatalf("%s: failed to marshal: %v", name, err)
		}
		if !bytes.Equal(b, tc.want) {
			t.Errorf("%s encoded as %x, want %x", name, b, tc.want)
		}
	}
}

// AN UNSET OR UNKNOWN ARM DECODES AS NO BODY (rule 13 makes both a violation). An arm number
// this code does not know, as a newer producer might send, is kept as an unknown field, and
// the body stays nil. So a consumer detects both cases with one nil check, and the oneof is
// what makes that possible.
func TestAnUnsetOrUnknownArmDecodesAsNoBody(t *testing.T) {
	for name, tc := range map[string]struct {
		into    proto.Message
		wire    []byte
		body    func(proto.Message) bool
		unknown int
	}{
		"an unset control plane arm": {&ControlPlaneMessage{}, []byte{}, func(m proto.Message) bool { return m.(*ControlPlaneMessage).GetBody() != nil }, 0},
		"control plane arm 6":        {&ControlPlaneMessage{}, []byte{0x32, 0x00}, func(m proto.Message) bool { return m.(*ControlPlaneMessage).GetBody() != nil }, 2},
		"an unset node arm":          {&NodeMessage{}, []byte{}, func(m proto.Message) bool { return m.(*NodeMessage).GetBody() != nil }, 0},
		"node arm 3":                 {&NodeMessage{}, []byte{0x1a, 0x00}, func(m proto.Message) bool { return m.(*NodeMessage).GetBody() != nil }, 2},
		"an unset delta op":          {&DeltaOp{}, []byte{}, func(m proto.Message) bool { return m.(*DeltaOp).GetOp() != nil }, 0},
		"delta op arm 3":             {&DeltaOp{}, []byte{0x1a, 0x00}, func(m proto.Message) bool { return m.(*DeltaOp).GetOp() != nil }, 2},
	} {
		if err := proto.Unmarshal(tc.wire, tc.into); err != nil {
			t.Fatalf("%s: failed to unmarshal: %v", name, err)
		}
		if tc.body(tc.into) {
			t.Errorf("%s decoded with a body, want none", name)
		}
		if got := len(tc.into.ProtoReflect().GetUnknown()); got != tc.unknown {
			t.Errorf("%s kept %d unknown bytes, want %d", name, got, tc.unknown)
		}
	}
}

// THE NIL CHECK DETECTS A MESSAGE WITH NO KNOWN ARM, AND ONLY THAT. A message carrying a known
// arm beside an unknown field decodes with that arm as its body, and the unknown bytes are kept.
// A message carrying two known arms decodes with the LAST one as its body. A consumer cannot
// detect either case, and the contract does not ask it to. This measures protobuf-go v1.36.12's
// decoder rather than recalling it, so it was expected to pass when written. It fails if a
// runtime upgrade changes that behaviour, and then the ControlPlaneMessage comment and doc.go
// must change with it.
func TestTheNilCheckDoesNotDetectAKnownArmBesideAnUnknownFieldOrTwoKnownArms(t *testing.T) {
	// snapshot_begin{version: 5}, then field 6 (unknown), length 0.
	beside := &ControlPlaneMessage{}
	if err := proto.Unmarshal([]byte{0x0a, 0x02, 0x08, 0x05, 0x32, 0x00}, beside); err != nil {
		t.Fatalf("failed to unmarshal a known arm beside an unknown field: %v", err)
	}
	if got := beside.GetSnapshotBegin(); got == nil || got.GetVersion() != 5 {
		t.Errorf("a known arm beside an unknown field decoded with body %v, want SnapshotBegin{5}", beside.GetBody())
	}
	if got := len(beside.ProtoReflect().GetUnknown()); got != 2 {
		t.Errorf("a known arm beside an unknown field kept %d unknown bytes, want 2", got)
	}

	// snapshot_begin{version: 5}, then heartbeat{current_version: 9}.
	two := &ControlPlaneMessage{}
	if err := proto.Unmarshal([]byte{0x0a, 0x02, 0x08, 0x05, 0x2a, 0x02, 0x08, 0x09}, two); err != nil {
		t.Fatalf("failed to unmarshal two known arms: %v", err)
	}
	if got := two.GetHeartbeat(); got == nil || got.GetCurrentVersion() != 9 {
		t.Errorf("two known arms decoded with body %v, want the last arm, Heartbeat{9}", two.GetBody())
	}
}

// A DELTA MAY CARRY ZERO OPS (Readiness): a version bump that changes nothing in the set,
// which the consumer applies by advancing its cursor. It survives the wire with both versions.
func TestADeltaMayCarryZeroOps(t *testing.T) {
	got := roundTrip(t, &Delta{FromVersion: 3, ToVersion: 4})
	if got.GetFromVersion() != 3 || got.GetToVersion() != 4 || len(got.GetOps()) != 0 {
		t.Errorf("a zero-op Delta decoded as %v", got)
	}
}

// OPS KEEP THEIR ORDER (rule 10). The producer puts every Remove before every Upsert, so an
// address freed by a purge and handed to a new device arrives as Remove(old) then Upsert(new)
// without tripping rule 12, and the order on the wire is the order applied.
func TestDeltaOpsKeepTheirOrder(t *testing.T) {
	want := &Delta{FromVersion: 8, ToVersion: 9, Ops: []*DeltaOp{
		{Op: &DeltaOp_Remove{Remove: &Remove{PublicKey: testKey(1)}}},
		{Op: &DeltaOp_Upsert{Upsert: &Upsert{Entry: &KeySetEntry{PublicKey: testKey(2), TunnelIp: []byte{10, 64, 1, 2}, ValidUntil: 20454 * 86400}}}},
	}}
	got := roundTrip(t, want)
	if !proto.Equal(got, want) {
		t.Fatalf("round trip gave %v, want %v", got, want)
	}
	if got.GetOps()[0].GetRemove() == nil || got.GetOps()[1].GetUpsert() == nil {
		t.Errorf("ops decoded out of order: %v", got.GetOps())
	}
}

// Every control plane message survives the wire unchanged.
func TestEveryControlPlaneMessageArmRoundTrips(t *testing.T) {
	entry := &KeySetEntry{PublicKey: testKey(3), TunnelIp: []byte{10, 64, 1, 3}, ValidUntil: 20454 * 86400}
	for name, want := range map[string]*ControlPlaneMessage{
		"snapshot_begin": begin(7),
		"upsert":         {Body: &ControlPlaneMessage_Upsert{Upsert: &Upsert{Entry: entry}}},
		"snapshot_end":   end(7),
		"delta": {Body: &ControlPlaneMessage_Delta{Delta: &Delta{FromVersion: 7, ToVersion: 8, Ops: []*DeltaOp{
			{Op: &DeltaOp_Upsert{Upsert: &Upsert{Entry: entry}}},
		}}}},
		"heartbeat": {Body: &ControlPlaneMessage_Heartbeat{Heartbeat: &Heartbeat{CurrentVersion: 8}}},
	} {
		if got := roundTrip(t, want); !proto.Equal(got, want) {
			t.Errorf("%s: round trip gave %v, want %v", name, got, want)
		}
	}
}
