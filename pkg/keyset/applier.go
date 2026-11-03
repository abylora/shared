// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// ApplyFunc applies target, the whole set the node must now hold, to the node's interface,
// as a diff against live state (rule 4), and reports whether it succeeded. Receive calls it
// once for every SnapshotEnd and every legal Delta, a no-op one included, and for nothing else.
// It must not call back into the Applier. It returns a bool, not an error, so that no kernel
// error text ever reaches this package.
type ApplyFunc func(target Set) bool

// Applier is the reference consumer of the key set stream (rules 1, 2, 5, 9 to 13). It holds a
// cursor, the held set, the keys it currently refuses, and an open snapshot. It is not safe for
// concurrent use.
type Applier struct {
	own     [32]byte
	cursor  uint64
	held    Set
	refused map[string]struct{}
	open    bool
	snap    *accumulator
}

// New returns an applier holding held at cursor, with no stream open and no key refused. A
// node starting from nothing passes 0 and the zero Set. held must not contain own.
//
// A rebuilt Applier starts with an empty refused set, so given a non-zero cursor its skipped
// gauge under-reports until the next snapshot: the refusals behind that cursor are not known. A
// driver that restarts should start at cursor 0, which brings a snapshot (rule 3).
func New(own [32]byte, cursor uint64, held Set) (*Applier, error) {
	if _, ok := held.Find(own); ok {
		return nil, ErrHeldSetHasOwnKey
	}

	return &Applier{own: own, cursor: cursor, held: held}, nil
}

// Hello opens a stream and returns the node's first message. Any open snapshot is discarded:
// a snapshot never spans streams, and on stream loss the node keeps its last applied set
// (rule 8). Calling Hello while a stream is open models that stream's loss.
func (a *Applier) Hello() *keysetpb.Hello {
	a.open, a.snap = true, nil

	return &keysetpb.Hello{HeldVersion: a.cursor}
}

// Cursor is the version of the held set, or 0 when the node holds nothing it can name.
func (a *Applier) Cursor() uint64 { return a.cursor }

// Held is the set last applied successfully. After OutcomeApplyFailed it is unchanged, and
// Cursor() is 0 (rule 5): the interface may lie anywhere between Held() and the target that
// failed, which is why the cursor no longer names it. A node relies on Held() for rule 8 and
// rule 14.
func (a *Applier) Held() Set { return a.held }

// Skipped is the gauge Applied reports: how many entries the node currently refuses under
// rules 11 and 12.
func (a *Applier) Skipped() uint64 { return uint64(len(a.refused)) }

func (*Applier) String() string   { return redacted }
func (*Applier) GoString() string { return redacted }

// Receive takes one control-plane message and returns exactly one outcome. apply is called
// only when the message would advance the cursor. A nil apply, or a call with no stream open, is
// the driver's misuse and returns OutcomeMisuse, never a panic and never OutcomeViolation.
//
// After OutcomeApplyFailed, Cursor() is 0 (rule 5) and Held() is the last set applied
// successfully, unchanged; the interface may lie anywhere between Held() and the target.
func (a *Applier) Receive(m *keysetpb.ControlPlaneMessage, apply ApplyFunc) Outcome {
	if !a.open {
		return Outcome{kind: OutcomeMisuse, err: ErrStreamClosed}
	}
	if apply == nil {
		a.open, a.snap = false, nil

		return Outcome{kind: OutcomeMisuse, err: ErrApplyNil}
	}
	if a.snap != nil {
		return a.receiveInSnapshot(m, apply)
	}

	return a.receiveOutsideSnapshot(m, apply)
}

// Outside a snapshot only SnapshotBegin{version >= 1}, Delta and Heartbeat are legal (rule 13).
func (a *Applier) receiveOutsideSnapshot(m *keysetpb.ControlPlaneMessage, apply ApplyFunc) Outcome {
	switch body := m.GetBody().(type) {
	case *keysetpb.ControlPlaneMessage_SnapshotBegin:
		version := body.SnapshotBegin.GetVersion()
		if version == 0 {
			return a.violate(ErrSnapshotVersionZero)
		}
		a.snap = newAccumulator(version)

		return Outcome{kind: OutcomeAccumulating}
	case *keysetpb.ControlPlaneMessage_Upsert:
		return a.violate(ErrUpsertOutsideSnapshot)
	case *keysetpb.ControlPlaneMessage_SnapshotEnd:
		return a.violate(ErrSnapshotEndWithoutBegin)
	case *keysetpb.ControlPlaneMessage_Delta:
		return a.receiveDelta(body.Delta, apply)
	case *keysetpb.ControlPlaneMessage_Heartbeat:
		if body.Heartbeat.GetCurrentVersion() < a.cursor {
			return a.violate(ErrHeartbeatBelowCursor)
		}

		return Outcome{kind: OutcomeUnchanged}
	default:
		// No arm, or an arm this build does not know: proto3 decodes both as no body.
		return a.violate(ErrMessageNoArm)
	}
}

// Inside a snapshot only Upsert and a SnapshotEnd of the same version are legal (rule 13).
func (a *Applier) receiveInSnapshot(m *keysetpb.ControlPlaneMessage, apply ApplyFunc) Outcome {
	switch body := m.GetBody().(type) {
	case *keysetpb.ControlPlaneMessage_Upsert:
		entry := body.Upsert.GetEntry()
		if entry == nil {
			return a.violate(ErrUpsertNoEntry)
		}
		a.snap.add(entry, &a.own)

		return Outcome{kind: OutcomeAccumulating}
	case *keysetpb.ControlPlaneMessage_SnapshotEnd:
		if body.SnapshotEnd.GetVersion() != a.snap.version {
			return a.violate(ErrSnapshotEndVersionMismatch)
		}
		version := a.snap.version
		held, refused := a.snap.finish()
		a.snap = nil

		// A snapshot replaces the held set and the refused keys (rule 1), even when it is
		// empty, equal to the held set, or below the cursor.
		return a.commit(version, held, refused, apply)
	case *keysetpb.ControlPlaneMessage_SnapshotBegin:
		return a.violate(ErrSnapshotNested)
	case *keysetpb.ControlPlaneMessage_Delta:
		return a.violate(ErrDeltaInsideSnapshot)
	case *keysetpb.ControlPlaneMessage_Heartbeat:
		return a.violate(ErrHeartbeatInsideSnapshot)
	default:
		return a.violate(ErrMessageNoArm)
	}
}

// receiveDelta checks the whole Delta before applying any op, so a violation anywhere in it
// applies nothing.
func (a *Applier) receiveDelta(d *keysetpb.Delta, apply ApplyFunc) Outcome {
	if err := deltaShape(d); err != nil {
		return a.violate(err)
	}
	if d.GetFromVersion() != a.cursor {
		return a.violate(ErrDeltaGap)
	}
	held, refused := applyOps(a.held, a.refused, d.GetOps(), &a.own)

	return a.commit(d.GetToVersion(), held, refused, apply)
}

// commit hands the target to apply. On success the cursor, the held set and the refused keys
// advance together and Applied reports the advance. On failure the cursor is reset to 0 and
// the stream closes (rule 5), and the held set stays the last set applied successfully, as rule
// 5 was ruled. The refused keys stay too; at cursor 0 every Delta is a gap, so the next advance
// is a snapshot, which replaces them.
func (a *Applier) commit(version uint64, held Set, refused map[string]struct{}, apply ApplyFunc) Outcome {
	if !apply(held) {
		a.cursor, a.open = 0, false

		return Outcome{kind: OutcomeApplyFailed, err: ErrApplyFailed}
	}
	a.cursor, a.held, a.refused = version, held, refused

	return Outcome{kind: OutcomeApplied, set: held, version: version, skipped: uint64(len(refused))}
}

// violate closes the stream and discards any open snapshot. The cursor and held set stay.
func (a *Applier) violate(err error) Outcome {
	a.open, a.snap = false, nil

	return Outcome{kind: OutcomeViolation, err: err}
}
