// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import (
	"slices"
	"testing"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

func messageVersions(m *keysetpb.ControlPlaneMessage) []uint64 {
	var out []uint64
	if b := m.GetSnapshotBegin(); b != nil {
		out = append(out, b.GetVersion())
	}
	if e := m.GetSnapshotEnd(); e != nil {
		out = append(out, e.GetVersion())
	}
	if d := m.GetDelta(); d != nil {
		out = append(out, d.GetFromVersion(), d.GetToVersion())
	}
	if h := m.GetHeartbeat(); h != nil {
		out = append(out, h.GetCurrentVersion())
	}

	return out
}

// versionsOf returns every version-valued field of every case, by case id. A message given in
// the wire form is already decoded, so its versions are read too.
func versionsOf(v Vectors) map[string][]uint64 {
	out := map[string][]uint64{}
	for _, c := range v.Consumer {
		vs := []uint64{c.InitialCursor, c.Final.Cursor}
		for _, s := range c.Steps {
			if s.Hello {
				vs = append(vs, s.HeldVersion)
				continue
			}
			vs = append(vs, messageVersions(s.Message)...)
			if s.Expect.Applied != nil {
				vs = append(vs, s.Expect.Applied.GetVersion())
			}
		}
		out[c.ID] = vs
	}
	for _, c := range v.Conformance {
		out[c.ID] = []uint64{c.OldVersion, c.NewVersion, c.Delta.GetFromVersion(), c.Delta.GetToVersion()}
	}
	for _, c := range v.Resume {
		vs := []uint64{c.HeldVersion, c.Published}
		if c.Snapshot {
			vs = append(vs, c.SnapshotVersion)
		}
		for _, d := range append(append([]LogDelta{}, c.Log...), c.Deltas...) {
			vs = append(vs, d.From, d.To)
		}
		out[c.ID] = vs
	}
	for _, c := range v.NodeDirection {
		var vs []uint64
		for _, s := range c.Steps {
			if s.Sent != nil {
				vs = append(vs, messageVersions(s.Sent)...)
				continue
			}
			if h := s.Received.GetHello(); h != nil {
				vs = append(vs, h.GetHeldVersion())
			}
			if a := s.Received.GetApplied(); a != nil {
				vs = append(vs, a.GetVersion())
			}
			if s.Expect.Outcome == NodeOutcomeRecord {
				vs = append(vs, s.Expect.Record.AppliedVersion)
			}
		}
		for _, r := range c.Records {
			vs = append(vs, r.AppliedVersion)
		}
		out[c.ID] = vs
	}

	return out
}

func TestVersionsOfReadsEveryVersionField(t *testing.T) {
	sb := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotBegin{SnapshotBegin: &keysetpb.SnapshotBegin{Version: 13}}}
	se := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: 14}}}
	d := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Delta{Delta: &keysetpb.Delta{FromVersion: 16, ToVersion: 17}}}
	hb := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Heartbeat{Heartbeat: &keysetpb.Heartbeat{CurrentVersion: 18}}}
	c := ConsumerCase{ID: "x", InitialCursor: 11, Final: ConsumerState{Cursor: 19}, Steps: []ConsumerStep{
		{Hello: true, HeldVersion: 12},
		{Message: sb},
		{Message: se, Expect: ConsumerExpect{Applied: &keysetpb.Applied{Version: 15}}},
		{Message: d},
		{Message: hb},
	}}
	got := versionsOf(Vectors{Consumer: []ConsumerCase{c}})["x"]
	slices.Sort(got)
	if want := []uint64{11, 12, 13, 14, 15, 16, 17, 18, 19}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	cc := ConformanceCase{ID: "y", OldVersion: 21, NewVersion: 22, Delta: &keysetpb.Delta{FromVersion: 23, ToVersion: 24}}
	got = versionsOf(Vectors{Conformance: []ConformanceCase{cc}})["y"]
	slices.Sort(got)
	if want := []uint64{21, 22, 23, 24}; !slices.Equal(got, want) {
		t.Errorf("conformance: got %v, want %v", got, want)
	}

	rc := ResumeCase{ID: "z", HeldVersion: 31, Log: []LogDelta{{32, 33}}, Published: 34, Snapshot: true, SnapshotVersion: 35, Deltas: []LogDelta{{36, 37}}}
	got = versionsOf(Vectors{Resume: []ResumeCase{rc}})["z"]
	slices.Sort(got)
	if want := []uint64{31, 32, 33, 34, 35, 36, 37}; !slices.Equal(got, want) {
		t.Errorf("resume: got %v, want %v", got, want)
	}

	hello := &keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Hello{Hello: &keysetpb.Hello{HeldVersion: 41}}}
	applied := &keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Applied{Applied: &keysetpb.Applied{Version: 42}}}
	sent := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: 43}}}
	nc := NodeDirectionCase{ID: "w", Steps: []NodeStep{
		{Received: hello, Expect: NodeExpect{Outcome: NodeOutcomeRecord, Record: NodeRecord{AppliedVersion: 44}}},
		{Sent: sent},
		{Received: applied},
	}, Records: []NodeRecord{{AppliedVersion: 45}}}
	got = versionsOf(Vectors{NodeDirection: []NodeDirectionCase{nc}})["w"]
	slices.Sort(got)
	if want := []uint64{41, 42, 43, 44, 45}; !slices.Equal(got, want) {
		t.Errorf("node direction: got %v, want %v", got, want)
	}
}

// RULE 9: the counter is seeded at a random value of at least 1, so no vector may assume that 1
// is the first version. No version field anywhere is 1, and every case uses some version above 1.
func TestNoVectorUsesVersionOne(t *testing.T) {
	v, err := Load()
	if err != nil {
		t.Fatalf("failed to load the vectors: %v", err)
	}
	for id, vs := range versionsOf(v) {
		if slices.Contains(vs, 1) {
			t.Errorf("%s uses version 1", id)
		}
		if !slices.ContainsFunc(vs, func(x uint64) bool { return x > 1 }) {
			t.Errorf("%s uses no version above 1", id)
		}
	}
}
