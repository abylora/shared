// SPDX-License-Identifier: AGPL-3.0-only

package keyset_test

import (
	"bytes"
	"testing"

	"github.com/abylora/shared/pkg/keyset"
	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

var own = [32]byte(bytes.Repeat([]byte{0xee}, 32))

func entry(key, last byte) *keysetpb.KeySetEntry {
	return &keysetpb.KeySetEntry{PublicKey: bytes.Repeat([]byte{key}, 32), TunnelIp: []byte{10, 64, 1, last}, ValidUntil: 1798761600}
}

func snapshotBegin(v uint64) *keysetpb.ControlPlaneMessage {
	return &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotBegin{SnapshotBegin: &keysetpb.SnapshotBegin{Version: v}}}
}

func snapshotEnd(v uint64) *keysetpb.ControlPlaneMessage {
	return &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: v}}}
}

func upsert(e *keysetpb.KeySetEntry) *keysetpb.ControlPlaneMessage {
	return &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Upsert{Upsert: &keysetpb.Upsert{Entry: e}}}
}

func succeed(keyset.Set) bool { return true }

func heldOne(t *testing.T) keyset.Set {
	t.Helper()
	s, err := keyset.SetOf([]*keysetpb.KeySetEntry{entry(0x11, 2)})
	if err != nil {
		t.Fatalf("failed to build a set: %v", err)
	}

	return s
}

// A driver that receives before opening a stream gets OutcomeMisuse with ErrStreamClosed and
// changes nothing. It is not a violation: the control plane sent nothing wrong.
func TestReceiveBeforeTheFirstHelloIsRefused(t *testing.T) {
	a, err := keyset.New(own, 4242, heldOne(t))
	if err != nil {
		t.Fatalf("failed to construct: %v", err)
	}
	out := a.Receive(snapshotBegin(4300), succeed)
	if out.Kind() != keyset.OutcomeMisuse || out.Err() != keyset.ErrStreamClosed || !out.ClosesStream() {
		t.Fatalf("outcome %v, err %v, closes %v; want misuse, %v, true", out.Kind(), out.Err(), out.ClosesStream(), keyset.ErrStreamClosed)
	}
	assertNoKeyMaterial(t, out.Err(), [][]byte{own[:], entry(0x11, 2).GetPublicKey()})
	if a.Cursor() != 4242 || a.Held().Len() != 1 {
		t.Errorf("cursor %d, %d entries; want 4242 and 1", a.Cursor(), a.Held().Len())
	}
}

// After an outcome that closes the stream, nothing is received until the next Hello.
func TestReceiveAfterAClosingOutcomeNeedsANewHello(t *testing.T) {
	a, _ := keyset.New(own, 4242, heldOne(t))
	a.Hello()
	if out := a.Receive(snapshotEnd(4300), succeed); out.Err() != keyset.ErrSnapshotEndWithoutBegin {
		t.Fatalf("err %v, want %v", out.Err(), keyset.ErrSnapshotEndWithoutBegin)
	}
	if out := a.Receive(snapshotBegin(4300), succeed); out.Kind() != keyset.OutcomeMisuse || out.Err() != keyset.ErrStreamClosed {
		t.Fatalf("outcome %v, err %v; want misuse, %v", out.Kind(), out.Err(), keyset.ErrStreamClosed)
	}
	a.Hello()
	if out := a.Receive(snapshotBegin(4300), succeed); out.Kind() != keyset.OutcomeAccumulating {
		t.Fatalf("outcome %v, want accumulating", out.Kind())
	}
}

// Rule 8: on stream loss the node keeps its last applied set, and a snapshot never spans
// streams, so a Hello discards a snapshot left open.
func TestHelloDiscardsAnOpenSnapshot(t *testing.T) {
	a, _ := keyset.New(own, 4242, heldOne(t))
	a.Hello()
	a.Receive(snapshotBegin(4300), succeed)
	a.Receive(upsert(entry(0x22, 3)), succeed)
	if got := a.Hello().GetHeldVersion(); got != 4242 {
		t.Fatalf("Hello.held_version = %d, want 4242", got)
	}
	if out := a.Receive(snapshotEnd(4300), succeed); out.Err() != keyset.ErrSnapshotEndWithoutBegin {
		t.Fatalf("err %v, want %v", out.Err(), keyset.ErrSnapshotEndWithoutBegin)
	}
	if a.Held().Len() != 1 {
		t.Errorf("%d entries, want 1", a.Held().Len())
	}
}

// Rule 11: the node never holds its own key, so it cannot start holding it either.
func TestNewRefusesAHeldSetHoldingTheNodesOwnKey(t *testing.T) {
	held, err := keyset.SetOf([]*keysetpb.KeySetEntry{{PublicKey: own[:], TunnelIp: []byte{10, 64, 1, 2}, ValidUntil: 1798761600}})
	if err != nil {
		t.Fatalf("failed to build a set: %v", err)
	}
	if _, err := keyset.New(own, 4242, held); err != keyset.ErrHeldSetHasOwnKey {
		t.Fatalf("err %v, want %v", err, keyset.ErrHeldSetHasOwnKey)
	}
}

// A nil apply is driver misuse, never a panic: Receive returns OutcomeMisuse with ErrApplyNil,
// closes the stream, and changes nothing.
func TestReceiveWithANilApplyIsMisuse(t *testing.T) {
	a, _ := keyset.New(own, 4242, heldOne(t))
	a.Hello()
	delta := &keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_Delta{Delta: &keysetpb.Delta{FromVersion: 4242, ToVersion: 4300}}}
	var out keyset.Outcome
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Receive panicked with a nil apply: %v", r)
			}
		}()
		out = a.Receive(delta, nil)
	}()
	if out.Kind() != keyset.OutcomeMisuse || out.Err() != keyset.ErrApplyNil || !out.ClosesStream() {
		t.Fatalf("outcome %v, err %v, closes %v; want misuse, %v, true", out.Kind(), out.Err(), out.ClosesStream(), keyset.ErrApplyNil)
	}
	if a.Cursor() != 4242 || a.Held().Len() != 1 {
		t.Errorf("cursor %d, %d entries; want 4242 and 1", a.Cursor(), a.Held().Len())
	}
	if out := a.Receive(delta, succeed); out.Err() != keyset.ErrStreamClosed {
		t.Errorf("err %v after misuse, want %v", out.Err(), keyset.ErrStreamClosed)
	}
}

// The kinds' numeric values are part of the API: a consumer may store or switch on them, so a
// reordering, or a kind inserted anywhere but last, fails here.
func TestOutcomeKindValuesArePinned(t *testing.T) {
	for kind, want := range map[keyset.OutcomeKind]uint8{
		keyset.OutcomeAccumulating: 1, keyset.OutcomeUnchanged: 2, keyset.OutcomeApplied: 3,
		keyset.OutcomeApplyFailed: 4, keyset.OutcomeViolation: 5, keyset.OutcomeMisuse: 6,
	} {
		if uint8(kind) != want {
			t.Errorf("%v = %d, want %d", kind, uint8(kind), want)
		}
	}
}
