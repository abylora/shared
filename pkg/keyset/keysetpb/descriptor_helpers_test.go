// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// wantField is one field as the contract rules it. message is set for MessageKind only;
// oneof is "" when the field is in none; presence is whether the field tracks presence on the
// wire (a message-typed field or a oneof arm does, an implicit proto3 scalar does not).
type wantField struct {
	name     protoreflect.Name
	number   protoreflect.FieldNumber
	kind     protoreflect.Kind
	message  protoreflect.FullName
	repeated bool
	oneof    protoreflect.Name
	presence bool
}

// reporter is the part of testing.TB that assertExactFields needs, so that a test can watch
// each of its refusals fire.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// assertExactFields reports every way md's fields differ from want: a wanted field that is
// missing, a field that is not wanted, and a field whose number, kind, message type,
// cardinality, oneof or presence differs. Each difference is reported once.
func assertExactFields(r reporter, md protoreflect.MessageDescriptor, want []wantField) {
	r.Helper()

	wanted := make(map[protoreflect.Name]bool, len(want))
	for _, w := range want {
		wanted[w.name] = true

		fd := md.Fields().ByName(w.name)
		if fd == nil {
			r.Errorf("%s has no field %s", md.FullName(), w.name)
			continue
		}
		if fd.Number() != w.number {
			r.Errorf("%s.%s is field %d, want %d", md.FullName(), w.name, fd.Number(), w.number)
		}
		if fd.Kind() != w.kind {
			r.Errorf("%s.%s is %v, want %v", md.FullName(), w.name, fd.Kind(), w.kind)
		} else if fd.Kind() == protoreflect.MessageKind && fd.Message().FullName() != w.message {
			r.Errorf("%s.%s is a %s, want a %s", md.FullName(), w.name, fd.Message().FullName(), w.message)
		}
		if got := fd.Cardinality() == protoreflect.Repeated; got != w.repeated {
			r.Errorf("%s.%s repeated is %v, want %v", md.FullName(), w.name, got, w.repeated)
		}
		var oneof protoreflect.Name
		if od := fd.ContainingOneof(); od != nil {
			oneof = od.Name()
		}
		if oneof != w.oneof {
			r.Errorf("%s.%s is in oneof %q, want %q", md.FullName(), w.name, oneof, w.oneof)
		}
		if fd.HasPresence() != w.presence {
			r.Errorf("%s.%s presence is %v, want %v", md.FullName(), w.name, fd.HasPresence(), w.presence)
		}
	}

	fields := md.Fields()
	for i := range fields.Len() {
		if fd := fields.Get(i); !wanted[fd.Name()] {
			r.Errorf("%s has field %s (number %d), which the contract does not define", md.FullName(), fd.Name(), fd.Number())
		}
	}
}

// roundTrip marshals m and unmarshals the bytes into a new message of the same type.
func roundTrip[M proto.Message](t *testing.T, m M) M {
	t.Helper()

	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal %T: %v", m, err)
	}
	got := m.ProtoReflect().New().Interface().(M)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("failed to unmarshal %T: %v", m, err)
	}

	return got
}

// testKey returns a 32-byte stand-in for a public key, every byte b.
func testKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

// recorder collects what assertExactFields reports, so a test can watch each refusal fire.
type recorder struct{ errors []string }

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

// A CHECKER IS ONLY AS GOOD AS ITS REFUSALS. Every descriptor test in this package rests on
// assertExactFields, so each kind of mismatch it exists to catch is driven here against a real
// descriptor and must be reported exactly once, and the truth must be reported never. A
// refusal not driven here is one nobody has seen fire.
func TestAssertExactFieldsReportsEachKindOfMismatchOnce(t *testing.T) {
	md := (&KeySetEntry{}).ProtoReflect().Descriptor()
	truth := []wantField{
		{name: "public_key", number: 1, kind: protoreflect.BytesKind},
		{name: "tunnel_ip", number: 2, kind: protoreflect.BytesKind},
		{name: "tunnel_ip6", number: 3, kind: protoreflect.BytesKind},
		{name: "valid_until", number: 4, kind: protoreflect.Int64Kind},
	}
	edit := func(f func([]wantField) []wantField) []wantField { return f(slices.Clone(truth)) }

	r := &recorder{}
	assertExactFields(r, md, truth)
	if len(r.errors) != 0 {
		t.Fatalf("the truth was reported: %q", r.errors)
	}

	cases := map[string][]wantField{
		"a missing field": edit(func(w []wantField) []wantField {
			return append(w, wantField{name: "account_id", number: 5, kind: protoreflect.StringKind})
		}),
		"an extra field":     edit(func(w []wantField) []wantField { return w[:3] }),
		"a renumbered field": edit(func(w []wantField) []wantField { w[3].number = 5; return w }),
		"a retyped field":    edit(func(w []wantField) []wantField { w[3].kind = protoreflect.Uint64Kind; return w }),
		"a repeated field":   edit(func(w []wantField) []wantField { w[0].repeated = true; return w }),
		"presence":           edit(func(w []wantField) []wantField { w[2].presence = true; return w }),
		"a oneof":            edit(func(w []wantField) []wantField { w[2].oneof = "_tunnel_ip6"; return w }),
	}
	for name, want := range cases {
		r := &recorder{}
		assertExactFields(r, md, want)
		if len(r.errors) != 1 {
			t.Errorf("%s: reported %d times, want once: %q", name, len(r.errors), r.errors)
		}
	}
}
