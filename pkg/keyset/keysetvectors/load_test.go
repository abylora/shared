// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"google.golang.org/protobuf/proto"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

func TestLoadFileDecodesConsumerVector01(t *testing.T) {
	v, err := LoadFile("consumer-01-empty-snapshot.json")
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if len(v.Consumer) != 1 {
		t.Fatalf("got %d consumer cases, want 1", len(v.Consumer))
	}
	c := v.Consumer[0]
	if c.File != "consumer-01-empty-snapshot.json" || c.ID != "01-an-empty-snapshot-empties-the-held-set" || c.Description == "" {
		t.Errorf("file %q, id %q, description %q", c.File, c.ID, c.Description)
	}
	if c.OwnPublicKey != [32]byte(bytes.Repeat([]byte{0xee}, 32)) {
		t.Errorf("own key %x", c.OwnPublicKey)
	}
	want := []*keysetpb.KeySetEntry{
		{PublicKey: bytes.Repeat([]byte{0x11}, 32), TunnelIp: []byte{10, 64, 1, 2}, ValidUntil: 1798761600},
		{PublicKey: bytes.Repeat([]byte{0x22}, 32), TunnelIp: []byte{10, 64, 1, 3}, ValidUntil: 1798761600},
	}
	if c.InitialCursor != 3 || len(c.InitialSet) != 2 || !proto.Equal(c.InitialSet[0], want[0]) || !proto.Equal(c.InitialSet[1], want[1]) {
		t.Errorf("initial cursor %d, set %v", c.InitialCursor, c.InitialSet)
	}
	if len(c.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(c.Steps))
	}
	if s := c.Steps[0]; !s.Hello || s.HeldVersion != 3 {
		t.Errorf("step 0 = %+v, want hello 3", s)
	}
	if s := c.Steps[1]; s.Hello || s.Message.GetSnapshotBegin().GetVersion() != 5 || s.Expect.Outcome != OutcomeAccumulating || !s.ApplySucceeds {
		t.Errorf("step 1 = %+v", s)
	}
	if s := c.Steps[2]; s.Message.GetSnapshotEnd().GetVersion() != 5 || s.Expect.Outcome != OutcomeApplied ||
		s.Expect.Applied.GetVersion() != 5 || s.Expect.Applied.GetSkipped() != 0 || !s.ApplySucceeds {
		t.Errorf("step 2 = %+v", s)
	}
	if f := c.Final; f.Cursor != 5 || !f.SetAsserted || len(f.Set) != 0 || !f.SkippedAsserted || f.Skipped != 0 {
		t.Errorf("final = %+v", f)
	}
}

// base is the smallest valid consumer file. Each refusal row edits it in one place.
const base = `{"schema": "abylora.keyset.vectors.v1", "kind": "consumer", "rules": ["1"], "cases": [{
"id": "01-x", "description": "d", "own_public_key": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
"initial": {"cursor": "3", "set": [{"public_key": "1111111111111111111111111111111111111111111111111111111111111111", "tunnel_ip": "0a400102", "tunnel_ip6": "", "valid_until": "1798761600"}]},
"steps": [{"hello": {"held_version": "3"}},
{"receive": {"snapshot_begin": {"version": "5"}}, "expect": {"outcome": "accumulating"}},
{"receive": {"snapshot_end": {"version": "5"}}, "expect": {"outcome": "applied", "applied": {"version": "5", "skipped": "0"}}}],
"final": {"cursor": "5", "set": [], "skipped": "0"}}]}`

func loadFiles(files map[string]string) error {
	fsys := fstest.MapFS{}
	for name, doc := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(doc)}
	}
	_, err := load(fsys)

	return err
}

func TestTheBaseDocumentLoads(t *testing.T) {
	if err := loadFiles(map[string]string{"consumer-01-x.json": base}); err != nil {
		t.Fatalf("failed to load the base document: %v", err)
	}
}

func TestTheLoaderRefuses(t *testing.T) {
	const closingSnapshotEnd = `{"receive": {"snapshot_end": {"version": "5"}}, "expect": {"outcome": "applied", "applied": {"version": "5", "skipped": "0"}}}`
	for _, r := range []struct {
		name, old, new string
		want           error
	}{
		{"an unknown top-level key", `"rules": ["1"]`, `"rules": ["1"], "extra": "x"`, ErrJSON},
		{"an unknown key in an entry", `"valid_until": "1798761600"}`, `"valid_until": "1798761600", "account": "x"}`, ErrJSON},
		{"a repeated key", `"kind": "consumer"`, `"kind": "consumer", "kind": "consumer"`, ErrDuplicateKey},
		{"another schema", `vectors.v1`, `vectors.v2`, ErrSchema},
		{"an unknown kind", `"kind": "consumer"`, `"kind": "producer.other"`, ErrKindUnknown},
		{"no rules", `"rules": ["1"], `, ``, ErrFieldMissing},
		{"an entry without valid_until", `, "valid_until": "1798761600"}`, `}`, ErrFieldMissing},
		{"uppercase hex", `"tunnel_ip": "0a400102"`, `"tunnel_ip": "0A400102"`, ErrHexInvalid},
		{"odd-length hex", `"tunnel_ip": "0a400102"`, `"tunnel_ip": "0a40010"`, ErrHexInvalid},
		{"a leading zero", `"cursor": "3"`, `"cursor": "03"`, ErrDecimalInvalid},
		{"a plus sign", `"cursor": "3"`, `"cursor": "+3"`, ErrDecimalInvalid},
		{"a uint64 overflow", `"cursor": "3"`, `"cursor": "18446744073709551616"`, ErrDecimalInvalid},
		{"a JSON number for a version", `"cursor": "3"`, `"cursor": 3`, ErrJSON},
		{"a null message", `{"snapshot_begin": {"version": "5"}}`, `null`, ErrNull},
		{"a null description", `"description": "d"`, `"description": null`, ErrFieldMissing},
		{"two arms", `{"snapshot_begin": {"version": "5"}}`, `{"snapshot_begin": {"version": "5"}, "heartbeat": {"current_version": "5"}}`, ErrArmsRepeated},
		{"an unknown arm", `{"snapshot_begin":`, `{"snapshot_start":`, ErrArmUnknown},
		{"an invalid wire message", `{"snapshot_begin": {"version": "5"}}`, `{"wire": "ff"}`, ErrWireInvalid},
		{"a first step that is not a hello", `{"hello": {"held_version": "3"}},`, ``, ErrStepWithoutHello},
		{"a receive with no expect", `, "expect": {"outcome": "accumulating"}`, ``, ErrStepShape},
		{"a hello and a receive in one step", `{"hello": {"held_version": "3"}}`, `{"hello": {"held_version": "3"}, "receive": {}}`, ErrStepShape},
		{"applied without its report", `, "applied": {"version": "5", "skipped": "0"}`, ``, ErrExpectShape},
		{"an unknown outcome", `"outcome": "accumulating"`, `"outcome": "buffering"`, ErrWordUnknown},
		{"an unknown violation", closingSnapshotEnd, `{"receive": {"snapshot_end": {"version": "6"}}, "expect": {"outcome": "violation", "violation": "bad_luck"}}`, ErrWordUnknown},
		{"apply_succeeds false on an applied step", `{"receive": {"snapshot_end": {"version": "5"}},`, `{"receive": {"snapshot_end": {"version": "5"}}, "apply_succeeds": false,`, ErrApplySucceedsInconsistent},
		{"apply_failed with apply_succeeds left true", closingSnapshotEnd, `{"receive": {"snapshot_end": {"version": "5"}}, "expect": {"outcome": "apply_failed"}}`, ErrApplySucceedsInconsistent},
		{"a receive after a violation with no hello", closingSnapshotEnd, `{"receive": {"snapshot_end": {"version": "6"}}, "expect": {"outcome": "violation", "violation": "snapshot_end_version_mismatch"}}, {"receive": {"heartbeat": {"current_version": "5"}}, "expect": {"outcome": "unchanged"}}`, ErrStepWithoutHello},
		{"an unasserted final set", `"final": {"cursor": "5", "set": [], "skipped": "0"}`, `"final": {"cursor": "5", "skipped": "0"}`, ErrFinalUnasserted},
		{"an id without its file's number", `"id": "01-x"`, `"id": "02-x"`, ErrCaseIDPrefix},
		{"an own key of 31 bytes", `"own_public_key": "ee`, `"own_public_key": "`, ErrOwnKeyLength},
		{"trailing data", `"skipped": "0"}}]}`, `"skipped": "0"}}]} []`, ErrTrailingData},
		{"an unasserted final set after an apply failure", `{"receive": {"snapshot_end": {"version": "5"}}, "expect": {"outcome": "applied", "applied": {"version": "5", "skipped": "0"}}}],
"final": {"cursor": "5", "set": [], "skipped": "0"}`, `{"receive": {"snapshot_end": {"version": "5"}}, "apply_succeeds": false, "expect": {"outcome": "apply_failed"}}],
"final": {"cursor": "0"}`, ErrFinalUnasserted},
	} {
		t.Run(r.name, func(t *testing.T) {
			if strings.Count(base, r.old) != 1 {
				t.Fatalf("the row's text occurs %d times in the base document, want 1", strings.Count(base, r.old))
			}
			err := loadFiles(map[string]string{"consumer-01-x.json": strings.Replace(base, r.old, r.new, 1)})
			if !errors.Is(err, r.want) {
				t.Errorf("err = %v, want %v", err, r.want)
			}
		})
	}
}

func TestTheLoaderRefusesAFileWithNoCase(t *testing.T) {
	doc := `{"schema": "abylora.keyset.vectors.v1", "kind": "consumer", "rules": ["1"], "cases": []}`
	if err := loadFiles(map[string]string{"consumer-01-x.json": doc}); !errors.Is(err, ErrNoCases) {
		t.Errorf("err = %v, want %v", err, ErrNoCases)
	}
}

func TestTheLoaderRefusesAFileNameThatIsNotAVectorName(t *testing.T) {
	for _, name := range []string{"vectors-01.json", "producer-01-x.json", "consumer--x.json"} {
		if err := loadFiles(map[string]string{name: base}); !errors.Is(err, ErrFileName) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrFileName)
		}
	}
}

func TestTheLoaderRefusesACaseIDRepeatedAcrossFiles(t *testing.T) {
	err := loadFiles(map[string]string{"consumer-01-x.json": base, "consumer-01-y.json": base})
	if !errors.Is(err, ErrCaseIDRepeated) {
		t.Errorf("err = %v, want %v", err, ErrCaseIDRepeated)
	}
}

// The wire form decodes through the generated types, so an unknown arm arrives exactly as a
// consumer receives it: no known body, the unknown field kept.
func TestTheWireFormDecodesToTheEncodedMessage(t *testing.T) {
	m, err := decodeControlPlaneMessage([]byte(`{"wire": "3200"}`))
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if m.GetBody() != nil || len(m.ProtoReflect().GetUnknown()) != 2 {
		t.Errorf("body %v, %d unknown bytes; want no body and 2", m.GetBody(), len(m.ProtoReflect().GetUnknown()))
	}

	m, err = decodeControlPlaneMessage([]byte(`{"wire": "220a0892211093211a021a00"}`))
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	d := m.GetDelta()
	if d.GetFromVersion() != 4242 || d.GetToVersion() != 4243 || len(d.GetOps()) != 1 {
		t.Fatalf("delta %v, want 4242 to 4243 with one op", d)
	}
	if op := d.GetOps()[0]; op.GetOp() != nil || len(op.ProtoReflect().GetUnknown()) != 2 {
		t.Errorf("op %v, want no arm and 2 unknown bytes", op)
	}
}

// SCHEMA.md names every word the loader accepts, so the document a non-Go consumer reads cannot
// fall behind the loader.
func TestTheSchemaDocumentNamesEveryWord(t *testing.T) {
	doc, err := os.ReadFile("SCHEMA.md")
	if err != nil {
		t.Fatalf("failed to read SCHEMA.md: %v", err)
	}
	words := []string{Schema, string(KindConsumer)}
	for w := range knownOutcomes {
		words = append(words, string(w))
	}
	for w := range consumerViolations {
		words = append(words, string(w))
	}
	words = append(words, string(KindConformance))
	words = append(words, string(KindResume))
	words = append(words, string(KindNodeDirection))
	for w := range nodeViolations {
		words = append(words, string(w))
	}
	for w := range knownNodeOutcomes {
		words = append(words, string(w))
	}
	for w := range knownFailures {
		words = append(words, string(w))
	}
	for _, w := range words {
		if !strings.Contains(string(doc), "`"+w+"`") && !strings.Contains(string(doc), "`\""+w+"\"`") {
			t.Errorf("SCHEMA.md does not name `%s`", w)
		}
	}
}

const conformanceDoc = `{"schema": "abylora.keyset.vectors.v1", "kind": "producer.conformance", "rules": ["10"], "cases": [{
"id": "15-x", "description": "d",
"old": {"version": "40000", "set": [{"public_key": "1111111111111111111111111111111111111111111111111111111111111111", "tunnel_ip": "0a400102", "tunnel_ip6": "", "valid_until": "1798761600"}]},
"new": {"version": "40060", "set": []},
"delta": {"from_version": "40000", "to_version": "40060", "ops": [{"remove": {"public_key": "1111111111111111111111111111111111111111111111111111111111111111"}}]},
"expect": {"conforms": false, "failure": "result_differs"}}]}`

func TestLoadDecodesAConformanceCase(t *testing.T) {
	fsys := fstest.MapFS{"producer-15-x.json": &fstest.MapFile{Data: []byte(conformanceDoc)}}
	v, err := load(fsys)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if len(v.Conformance) != 1 {
		t.Fatalf("got %d conformance cases, want 1", len(v.Conformance))
	}
	c := v.Conformance[0]
	if c.OldVersion != 40000 || len(c.Old) != 1 || c.NewVersion != 40060 || len(c.New) != 0 ||
		c.Delta.GetFromVersion() != 40000 || len(c.Delta.GetOps()) != 1 || c.Conforms || c.Failure != FailureResultDiffers {
		t.Errorf("case = %+v", c)
	}
}

func TestTheLoaderRefusesAConformanceCaseWhoseVerdictDisagreesWithItself(t *testing.T) {
	for old, repl := range map[string]string{
		`"expect": {"conforms": false, "failure": "result_differs"}`: `"expect": {"conforms": false}`,
		`"conforms": false, "failure": "result_differs"`:             `"conforms": true, "failure": "result_differs"`,
		`"failure": "result_differs"`:                                `"failure": "felt_wrong"`,
	} {
		_, err := load(fstest.MapFS{"producer-15-x.json": &fstest.MapFile{Data: []byte(strings.Replace(conformanceDoc, old, repl, 1))}})
		if !errors.Is(err, ErrExpectShape) && !errors.Is(err, ErrWordUnknown) {
			t.Errorf("%s: err = %v, want %v or %v", repl, err, ErrExpectShape, ErrWordUnknown)
		}
	}
}

func TestLoadDecodesAResumeCase(t *testing.T) {
	doc := `{"schema": "abylora.keyset.vectors.v1", "kind": "producer.resume", "rules": ["3"], "cases": [
{"id": "14-x", "description": "d", "held_version": "95000",
 "log": [{"from_version": "94000", "to_version": "95000"}, {"from_version": "95000", "to_version": "96000"}],
 "published": "96000", "expect": {"send": "deltas", "deltas": [{"from_version": "95000", "to_version": "96000"}]}},
{"id": "14-y", "description": "d", "held_version": "0", "log": [], "published": "96000",
 "expect": {"send": "snapshot", "snapshot_version": "96000"}}]}`
	v, err := load(fstest.MapFS{"producer-14-x.json": &fstest.MapFile{Data: []byte(doc)}})
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if len(v.Resume) != 2 {
		t.Fatalf("got %d resume cases, want 2", len(v.Resume))
	}
	if c := v.Resume[0]; c.HeldVersion != 95000 || len(c.Log) != 2 || c.Published != 96000 || c.Snapshot ||
		len(c.Deltas) != 1 || c.Deltas[0] != (LogDelta{From: 95000, To: 96000}) {
		t.Errorf("deltas case = %+v", c)
	}
	if c := v.Resume[1]; !c.Snapshot || c.SnapshotVersion != 96000 || len(c.Log) != 0 {
		t.Errorf("snapshot case = %+v", c)
	}
}

func TestLoadDecodesANodeDirectionCase(t *testing.T) {
	doc := `{"schema": "abylora.keyset.vectors.v1", "kind": "producer.node_direction", "rules": ["16"], "cases": [{
"id": "18-x", "description": "d", "steps": [
 {"received": {"hello": {"held_version": "0"}}, "expect": {"outcome": "record", "record": {"applied_version": "0"}}},
 {"sent": {"snapshot_end": {"version": "120000"}}},
 {"received": {"applied": {"version": "120000", "skipped": "2"}}, "expect": {"outcome": "record", "record": {"applied_version": "120000", "skipped": "2"}}},
 {"received": {"wire": "1a00"}, "expect": {"outcome": "violation", "violation": "node_message_no_arm"}},
 {"received": {}, "expect": {"outcome": "closed"}}],
"records": [{"applied_version": "0"}, {"applied_version": "120000", "skipped": "2"}]}]}`
	v, err := load(fstest.MapFS{"producer-18-x.json": &fstest.MapFile{Data: []byte(doc)}})
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if len(v.NodeDirection) != 1 || len(v.NodeDirection[0].Steps) != 5 || len(v.NodeDirection[0].Records) != 2 {
		t.Fatalf("got %+v", v.NodeDirection)
	}
	s := v.NodeDirection[0].Steps
	if s[0].Received.GetHello() == nil || s[0].Expect.Record != (NodeRecord{AppliedVersion: 0}) {
		t.Errorf("step 0 = %+v", s[0])
	}
	if s[1].Sent.GetSnapshotEnd().GetVersion() != 120000 {
		t.Errorf("step 1 = %+v", s[1])
	}
	if s[2].Expect.Record != (NodeRecord{AppliedVersion: 120000, Skipped: 2, HasSkipped: true}) {
		t.Errorf("step 2 = %+v", s[2])
	}
	if s[3].Received.GetBody() != nil || len(s[3].Received.ProtoReflect().GetUnknown()) != 2 || s[3].Expect.Violation != ViolationNodeMessageNoArm {
		t.Errorf("step 3 = %+v", s[3])
	}
	if s[4].Expect.Outcome != NodeOutcomeClosed {
		t.Errorf("step 4 = %+v", s[4])
	}
}
