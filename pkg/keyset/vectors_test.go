// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/abylora/shared/pkg/keyset"
	"github.com/abylora/shared/pkg/keyset/keysetpb"
	"github.com/abylora/shared/pkg/keyset/keysetvectors"
)

// outcomeWords maps the reference's outcomes to the vectors' words. It lives here, not in the
// reference, so that the vectors' vocabulary never becomes a property of the reference's types.
var outcomeWords = map[keyset.OutcomeKind]keysetvectors.Outcome{
	keyset.OutcomeAccumulating: keysetvectors.OutcomeAccumulating,
	keyset.OutcomeUnchanged:    keysetvectors.OutcomeUnchanged,
	keyset.OutcomeApplied:      keysetvectors.OutcomeApplied,
	keyset.OutcomeApplyFailed:  keysetvectors.OutcomeApplyFailed,
	keyset.OutcomeViolation:    keysetvectors.OutcomeViolation,
}

// violationWords maps every consumer sentinel to the vectors' word. An error the map does not
// hold maps to "", which matches no word, so a wrapped or formatted error fails the runner.
var violationWords = map[error]keysetvectors.Violation{
	keyset.ErrMessageNoArm:               keysetvectors.ViolationMessageNoArm,
	keyset.ErrOpNoArm:                    keysetvectors.ViolationOpNoArm,
	keyset.ErrUpsertNoEntry:              keysetvectors.ViolationUpsertNoEntry,
	keyset.ErrSnapshotVersionZero:        keysetvectors.ViolationSnapshotBeginVersionZero,
	keyset.ErrSnapshotNested:             keysetvectors.ViolationSnapshotNested,
	keyset.ErrSnapshotEndWithoutBegin:    keysetvectors.ViolationSnapshotEndWithoutBegin,
	keyset.ErrSnapshotEndVersionMismatch: keysetvectors.ViolationSnapshotEndVersionMismatch,
	keyset.ErrUpsertOutsideSnapshot:      keysetvectors.ViolationUpsertOutsideSnapshot,
	keyset.ErrDeltaInsideSnapshot:        keysetvectors.ViolationDeltaInsideSnapshot,
	keyset.ErrHeartbeatInsideSnapshot:    keysetvectors.ViolationHeartbeatInsideSnapshot,
	keyset.ErrDeltaFromVersionZero:       keysetvectors.ViolationDeltaFromVersionZero,
	keyset.ErrDeltaVersionsNotIncreasing: keysetvectors.ViolationDeltaVersionsNotIncreasing,
	keyset.ErrDeltaGap:                   keysetvectors.ViolationDeltaGap,
	keyset.ErrHeartbeatBelowCursor:       keysetvectors.ViolationHeartbeatBelowCursor,
}

func runFile(t *testing.T, name string) {
	t.Helper()
	v, err := keysetvectors.LoadFile(name)
	if err != nil {
		t.Fatalf("failed to load %s: %v", name, err)
	}
	runVectors(t, v)
}

// runVectors runs every case and refuses to run none: a vector file that ran nothing would pass
// vacuously.
func runVectors(t *testing.T, v keysetvectors.Vectors) {
	t.Helper()
	ran := 0
	for _, c := range v.Consumer {
		ran++
		t.Run(c.ID, func(t *testing.T) { runConsumerCase(t, c) })
	}
	for _, c := range v.Conformance {
		ran++
		t.Run(c.ID, func(t *testing.T) { runConformanceCase(t, c) })
	}
	for _, c := range v.Resume {
		ran++
		t.Run(c.ID, func(t *testing.T) { runResumeCase(t, c) })
	}
	for _, c := range v.NodeDirection {
		ran++
		t.Run(c.ID, func(t *testing.T) { runNodeDirectionCase(t, c) })
	}
	if ran == 0 {
		t.Fatal("no case ran")
	}
}

// describe renders a set for a failure message: the first four bytes of each key and the
// address, in hex. The vectors' keys are synthetic.
func describe(s keyset.Set) string {
	parts := []string{}
	for _, e := range s.Entries() {
		k, ip := e.PublicKey(), e.TunnelIP()
		parts = append(parts, hex.EncodeToString(k[:4])+"@"+hex.EncodeToString(ip[:]))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

// holdsExactly reports whether s holds exactly the entries want, comparing all four fields. It
// does not build want with SetOf, which is the producer's check: a consumer's held set may
// legitimately hold two entries sharing a tunnel_ip6, because the consumer checks tunnel_ip only.
func holdsExactly(s keyset.Set, want []*keysetpb.KeySetEntry) bool {
	if s.Len() != len(want) {
		return false
	}
	for _, w := range want {
		if len(w.GetPublicKey()) != 32 {
			return false
		}
		e, ok := s.Find([32]byte(w.GetPublicKey()))
		if !ok {
			return false
		}
		ip := e.TunnelIP()
		got6, has6 := e.TunnelIP6()
		if !bytes.Equal(ip[:], w.GetTunnelIp()) || has6 != (len(w.GetTunnelIp6()) > 0) ||
			(has6 && !bytes.Equal(got6[:], w.GetTunnelIp6())) || e.ValidUntil() != w.GetValidUntil() {
			return false
		}
	}

	return true
}

func describeEntries(entries []*keysetpb.KeySetEntry) string {
	parts := []string{}
	for _, e := range entries {
		k := e.GetPublicKey()
		if len(k) > 4 {
			k = k[:4]
		}
		parts = append(parts, hex.EncodeToString(k)+"@"+hex.EncodeToString(e.GetTunnelIp()))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

func runConsumerCase(t *testing.T, c keysetvectors.ConsumerCase) {
	initial, err := keyset.SetOf(c.InitialSet)
	if err != nil {
		t.Fatalf("the initial set is not a set: %v", err)
	}
	a, err := keyset.New(c.OwnPublicKey, c.InitialCursor, initial)
	if err != nil {
		t.Fatalf("failed to construct the applier: %v", err)
	}

	for i, step := range c.Steps {
		if step.Hello {
			if got := a.Hello().GetHeldVersion(); got != step.HeldVersion {
				t.Fatalf("step %d: Hello.held_version = %d, want %d", i, got, step.HeldVersion)
			}
			continue
		}
		var target keyset.Set
		called := false
		out := a.Receive(step.Message, func(s keyset.Set) bool {
			target, called = s, true
			return step.ApplySucceeds
		})
		checkConsumerOutcome(t, i, c, step.Expect, out, a, called, target)
	}

	if a.Cursor() != c.Final.Cursor {
		t.Errorf("final cursor = %d, want %d", a.Cursor(), c.Final.Cursor)
	}
	if c.Final.SetAsserted && !holdsExactly(a.Held(), c.Final.Set) {
		t.Errorf("final set = %s, want %d entries %s", describe(a.Held()), len(c.Final.Set), describeEntries(c.Final.Set))
	}
	if c.Final.SkippedAsserted && a.Skipped() != c.Final.Skipped {
		t.Errorf("final skipped = %d, want %d", a.Skipped(), c.Final.Skipped)
	}
}

func checkConsumerOutcome(t *testing.T, i int, c keysetvectors.ConsumerCase, e keysetvectors.ConsumerExpect,
	out keyset.Outcome, a *keyset.Applier, called bool, target keyset.Set) {
	t.Helper()
	if got := outcomeWords[out.Kind()]; got != e.Outcome {
		t.Fatalf("step %d: outcome %q, want %q", i, got, e.Outcome)
	}
	if e.Outcome == keysetvectors.OutcomeApplied {
		got := out.Applied()
		if got.GetVersion() != e.Applied.GetVersion() || got.GetSkipped() != e.Applied.GetSkipped() {
			t.Fatalf("step %d: Applied{version: %d, skipped: %d}, want {version: %d, skipped: %d}",
				i, got.GetVersion(), got.GetSkipped(), e.Applied.GetVersion(), e.Applied.GetSkipped())
		}
		// Rule 5: the cursor advances only after a successful apply of exactly the set reported.
		if !called || !target.Equal(out.Set()) || !out.Set().Equal(a.Held()) {
			t.Fatalf("step %d: applied %s, but apply called = %v with %s", i, describe(out.Set()), called, describe(target))
		}
	}
	switch e.Outcome {
	case keysetvectors.OutcomeViolation:
		if got := violationWords[out.Err()]; got != e.Violation {
			t.Fatalf("step %d: violation %q (%v), want %q", i, got, out.Err(), e.Violation)
		}
		assertNoKeyMaterial(t, out.Err(), consumerMaterial(c))
	case keysetvectors.OutcomeApplyFailed:
		if out.Err() != keyset.ErrApplyFailed {
			t.Fatalf("step %d: err = %v, want %v", i, out.Err(), keyset.ErrApplyFailed)
		}
		assertNoKeyMaterial(t, out.Err(), consumerMaterial(c))
	}
	closes := e.Outcome == keysetvectors.OutcomeViolation || e.Outcome == keysetvectors.OutcomeApplyFailed
	if out.ClosesStream() != closes {
		t.Fatalf("step %d: ClosesStream() = %v for outcome %q", i, out.ClosesStream(), e.Outcome)
	}
}

// Every embedded vector file runs, so a vector added without the behaviour it tests fails here.
func TestEveryVectorFileRuns(t *testing.T) {
	v, err := keysetvectors.Load()
	if err != nil {
		t.Fatalf("failed to load the vectors: %v", err)
	}
	runVectors(t, v)
}

// THE FIRST TEST (rule 1). An empty snapshot over a held set of two entries leaves the set empty
// and the cursor at 5. An applier that reads an empty snapshot as "no change", the failure
// Headscale had to fix, keeps both entries.
func TestVector01AnEmptySnapshotEmptiesTheSet(t *testing.T) {
	runFile(t, "consumer-01-empty-snapshot.json")
}

// Rule 5: Applied reports every advance, including a snapshot that changes nothing on the
// interface. Without it, a client whose target came from a no-visible-change epoch waits forever.
func TestVector11b1ASnapshotEqualToTheHeldSetIsReported(t *testing.T) {
	runFile(t, "consumer-11b1-snapshot-equal-to-held-set.json")
}

// A snapshot below the cursor is legal (rule 13): it answers a held_version above the published
// version.
func TestVector11aASnapshotBelowTheCursorIsApplied(t *testing.T) {
	runFile(t, "consumer-11a-snapshot-below-cursor.json")
}

// A snapshot at V then Delta{V to W} leaves the cursor at W (rules 1 and 3). The versions are
// above 2^53, so a consumer that parses versions as floating point fails, and W is not V + 1.
func TestVector06ASnapshotThenItsTailApply(t *testing.T) {
	runFile(t, "consumer-06-snapshot-then-tail.json")
}

// A Delta may carry zero ops (Readiness): the consumer advances its cursor and reports it.
func TestVector11bAZeroOpDeltaAdvancesTheCursorAndIsReported(t *testing.T) {
	runFile(t, "consumer-11b-zero-op-delta.json")
}

// Rule 2: ops are keyed by public_key; a Remove of an unknown key is a no-op.
func TestVector04ARemoveOfAnUnknownKeyIsANoOp(t *testing.T) {
	runFile(t, "consumer-04-remove.json")
}

// Rule 2: an op is idempotent, so a duplicated op has the effect of one.
func TestVector03ADuplicatedOpHasTheEffectOfOne(t *testing.T) {
	runFile(t, "consumer-03-duplicated-op.json")
}

// Rule 5: on a gap the node closes the stream and reconnects with its cursor unchanged.
func TestVector02AGapIsAViolationThatKeepsTheState(t *testing.T) {
	runFile(t, "consumer-02-gap.json")
}

// Rule 9: every version is at least 1, so a Delta from 0 is a violation, even at cursor 0,
// where a gap check alone would accept it.
func TestVector10ADeltaFromVersionZeroIsAViolation(t *testing.T) {
	runFile(t, "consumer-10-delta-from-version-zero.json")
}

// Rule 5: a failed apply resets the cursor to 0, because a half-applied interface no longer
// matches it; a gap keeps the cursor. After the failure only a snapshot can advance.
func TestVector11cAFailedApplyResetsTheCursorAndAGapKeepsIt(t *testing.T) {
	runFile(t, "consumer-11c-apply-failure.json")
}

// Rule 13: the stream is a state machine; anything outside it closes the stream with the cursor
// and set unchanged. One case per violation, and a legal Heartbeat.
func TestVector11EveryStateMachineViolationKeepsTheState(t *testing.T) {
	runFile(t, "consumer-11-state-machine-violations.json")
}

// Rule 11: a malformed entry is skipped, any held entry under its key is removed, the rest
// applies, the cursor advances, and the gauge counts it.
func TestVector07AMalformedEntryIsSkippedAndTheRestApplies(t *testing.T) {
	runFile(t, "consumer-07-malformed-entry.json")
}

// Rule 12 in a snapshot: every entry sharing an address with another is skipped.
func TestVector08EntriesSharingAnAddressInASnapshotAreAllSkipped(t *testing.T) {
	runFile(t, "consumer-08-snapshot-address-collision.json")
}

// Rule 12 in a Delta: an Upsert claiming an address held by a different key is skipped, and
// treated like rule 11, so the key's own held entry is removed. Remove(old) then Upsert(new)
// reuses the address, which proves in-order application.
func TestVector09AnUpsertClaimingAnotherKeysAddressIsSkipped(t *testing.T) {
	runFile(t, "consumer-09-delta-address-collision.json")
}

// Rule 10: the consumer applies ops in received order, so Upsert(new) before Remove(old) skips
// new deterministically, rather than depending on how the consumer happens to iterate.
func TestVector09aAnUpsertBeforeTheRemoveThatFreesItsAddressIsSkipped(t *testing.T) {
	runFile(t, "consumer-09a-upsert-before-remove.json")
}

// Rule 2: an Upsert changing a tunnel address replaces the entry, so its old address is free.
func TestVector05AnUpsertChangingATunnelAddressReplacesTheEntry(t *testing.T) {
	runFile(t, "consumer-05-address-change.json")
}

// Rules 11 and 12: skipped is a gauge of the entries the node currently refuses, not of the
// skips on this stream, so a refusal from a snapshot survives a resume by deltas, and a Remove
// or a later valid Upsert of the key clears it.
func TestVector11b2TheSkippedGaugeSurvivesAResume(t *testing.T) {
	runFile(t, "consumer-11b2-gauge-across-resume.json")
}

var failureWords = map[error]keysetvectors.Failure{
	keyset.ErrDeltaFromVersionZero:       keysetvectors.FailureDeltaShape,
	keyset.ErrDeltaVersionsNotIncreasing: keysetvectors.FailureDeltaShape,
	keyset.ErrOpNoArm:                    keysetvectors.FailureDeltaShape,
	keyset.ErrUpsertNoEntry:              keysetvectors.FailureDeltaShape,
	keyset.ErrDeltaVersionsMismatch:      keysetvectors.FailureVersionsMismatch,
	keyset.ErrDeltaKeyRepeated:           keysetvectors.FailureKeyRepeated,
	keyset.ErrDeltaUpsertBeforeRemove:    keysetvectors.FailureUpsertBeforeRemove,
	keyset.ErrDeltaNotSorted:             keysetvectors.FailureNotSorted,
	keyset.ErrDeltaEntryRefused:          keysetvectors.FailureEntryRefused,
	keyset.ErrDeltaResultDiffers:         keysetvectors.FailureResultDiffers,
}

func runConformanceCase(t *testing.T, c keysetvectors.ConformanceCase) {
	old, err := keyset.SetOf(c.Old)
	if err != nil {
		t.Fatalf("the old set is not a set: %v", err)
	}
	newSet, err := keyset.SetOf(c.New)
	if err != nil {
		t.Fatalf("the new set is not a set: %v", err)
	}
	err = keyset.CheckDelta(c.OldVersion, old, c.NewVersion, newSet, c.Delta)
	if c.Conforms {
		if err != nil {
			t.Fatalf("refused a conforming delta: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("conforms, want %q", c.Failure)
	}
	if got := failureWords[err]; got != c.Failure {
		t.Fatalf("failure %q (%v), want %q", got, err, c.Failure)
	}
	material := [][]byte{}
	for _, e := range append(append([]*keysetpb.KeySetEntry{}, c.Old...), c.New...) {
		material = append(material, entryMaterial(e)...)
	}
	material = append(material, messageMaterial(&keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Delta{Delta: c.Delta}})...)
	assertNoKeyMaterial(t, err, material)
}

// Rule 10: at most one op per key.
func TestVector15TwoOpsForOneKeyDoNotConform(t *testing.T) {
	runFile(t, "producer-15-conformance-key-repeated.json")
}

// Rule 10: every Remove before every Upsert, which is what lets a purged device's address go to
// a new device in one Delta.
func TestVector16EveryRemoveMustPrecedeEveryUpsert(t *testing.T) {
	runFile(t, "producer-16-conformance-remove-before-upsert.json")
}

// Rule 15: within each group, ops sorted by public_key as raw bytes, never the base64 text.
func TestVector17OpsMustBeSortedByRawKeyBytesWithinEachGroup(t *testing.T) {
	runFile(t, "producer-17-conformance-sort.json")
}

// Vector 17's premise, measured rather than recalled: the three keys sort one way as raw bytes
// and another as base64 text, in both alphabets. A measurement of the standard library, so it
// passed when written; it fails if someone swaps a key for one whose orders agree.
func TestTheSortVectorsBase64TextOrderIsNotTheirByteOrder(t *testing.T) {
	keys := [][]byte{bytes.Repeat([]byte{0x00}, 32), bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0xf8}, 32)}
	byBytes := slices.Clone(keys)
	slices.SortFunc(byBytes, bytes.Compare)
	if byBytes[0][0] != 0x00 || byBytes[1][0] != 0x11 || byBytes[2][0] != 0xf8 {
		t.Errorf("byte order %x %x %x", byBytes[0][0], byBytes[1][0], byBytes[2][0])
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		byText := slices.Clone(keys)
		slices.SortFunc(byText, func(a, b []byte) int { return strings.Compare(enc.EncodeToString(a), enc.EncodeToString(b)) })
		if byText[0][0] != 0xf8 || byText[1][0] != 0x00 || byText[2][0] != 0x11 {
			t.Errorf("text order %x %x %x, want f8 00 11", byText[0][0], byText[1][0], byText[2][0])
		}
	}
}

func runResumeCase(t *testing.T, c keysetvectors.ResumeCase) {
	log := make([]keyset.LoggedDelta, 0, len(c.Log))
	for _, d := range c.Log {
		log = append(log, keyset.LoggedDelta{From: d.From, To: d.To})
	}
	plan, err := keyset.PlanResume(c.HeldVersion, log, c.Published)
	if err != nil {
		t.Fatalf("failed to plan: %v", err)
	}
	if plan.Snapshot() != c.Snapshot {
		t.Fatalf("Snapshot() = %v, want %v", plan.Snapshot(), c.Snapshot)
	}
	if c.Snapshot {
		if plan.SnapshotVersion() != c.SnapshotVersion {
			t.Fatalf("SnapshotVersion() = %d, want %d", plan.SnapshotVersion(), c.SnapshotVersion)
		}
		return
	}
	got := plan.Deltas()
	if len(got) != len(c.Deltas) {
		t.Fatalf("%d deltas %v, want %v", len(got), got, c.Deltas)
	}
	for i := range got {
		if got[i].From != c.Deltas[i].From || got[i].To != c.Deltas[i].To {
			t.Fatalf("delta %d = %v, want %v", i, got[i], c.Deltas[i])
		}
	}
}

// Rule 3: a held_version inside the change log gets the deltas after it and no snapshot.
func TestVector14AHeldVersionInsideTheLogGetsDeltasOnly(t *testing.T) {
	runFile(t, "producer-14-resume-deltas.json")
}

// Rule 3: a held_version above the published version gets a snapshot.
func TestVector12AHeldVersionAbovePublishedGetsASnapshot(t *testing.T) {
	runFile(t, "producer-12-resume-held-version-above-published.json")
}

// Rules 3 and 7: a held_version of 0, one older than the log, one between two logged versions
// (never published, so not resumable), or any held_version when a restart has emptied the log,
// gets a snapshot, then the tail.
func TestVector13AHeldVersionOfZeroOrOutsideTheLogGetsASnapshot(t *testing.T) {
	runFile(t, "producer-13-resume-snapshot.json")
}

var nodeViolationWords = map[error]keysetvectors.Violation{
	keyset.ErrNodeMessageNoArm:    keysetvectors.ViolationNodeMessageNoArm,
	keyset.ErrAppliedBeforeHello:  keysetvectors.ViolationAppliedBeforeHello,
	keyset.ErrHelloRepeated:       keysetvectors.ViolationHelloRepeated,
	keyset.ErrAppliedNotDelivered: keysetvectors.ViolationAppliedNotDelivered,
	keyset.ErrAppliedDecreasing:   keysetvectors.ViolationAppliedDecreasing,
}

func runNodeDirectionCase(t *testing.T, c keysetvectors.NodeDirectionCase) {
	ch := keyset.NewNodeStreamChecker()
	records := []keysetvectors.NodeRecord{}
	for i, s := range c.Steps {
		if s.Sent != nil {
			ch.Sent(s.Sent)
			continue
		}
		rec, err := ch.Received(s.Received)
		switch s.Expect.Outcome {
		case keysetvectors.NodeOutcomeRecord:
			if err != nil {
				t.Fatalf("step %d: violation %v, want record", i, err)
			}
			skipped, has := rec.Skipped()
			got := keysetvectors.NodeRecord{AppliedVersion: rec.AppliedVersion(), Skipped: skipped, HasSkipped: has}
			if got != s.Expect.Record {
				t.Fatalf("step %d: record %+v, want %+v", i, got, s.Expect.Record)
			}
			records = append(records, got)
		case keysetvectors.NodeOutcomeViolation:
			if got := nodeViolationWords[err]; got != s.Expect.Violation {
				t.Fatalf("step %d: violation %q (%v), want %q", i, got, err, s.Expect.Violation)
			}
			assertNoKeyMaterial(t, err, nil)
		case keysetvectors.NodeOutcomeClosed:
			if err != keyset.ErrNodeStreamClosed {
				t.Fatalf("step %d: err %v, want %v", i, err, keyset.ErrNodeStreamClosed)
			}
		}
	}
	if !slices.Equal(records, c.Records) {
		t.Errorf("records %+v, want %+v", records, c.Records)
	}
}

// Rule 16: the node's direction is a state machine, enforced by the control plane, which records
// nothing from a violating message onward and keeps the Hello it already recorded.
func TestVector18TheNodesDirectionIsAStateMachine(t *testing.T) {
	runFile(t, "producer-18-node-direction.json")
}
