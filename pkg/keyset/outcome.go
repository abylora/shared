// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// OutcomeKind is what one received message did. The zero value is no outcome at all.
type OutcomeKind uint8

const (
	// OutcomeAccumulating: inside a snapshot (a SnapshotBegin or an Upsert). Nothing to send.
	OutcomeAccumulating OutcomeKind = iota + 1
	// OutcomeUnchanged: a legal Heartbeat. Nothing changes, nothing is sent, the stream stays
	// open. A current_version above the cursor is not acted on here: rule 6's reconnect waits
	// for a delta that does not arrive, which is the driver's timer.
	OutcomeUnchanged
	// OutcomeApplied: a SnapshotEnd or a legal Delta was applied. Send Applied(); the cursor
	// advanced, possibly to a lower version (a snapshot below the cursor) and possibly with
	// nothing changed on the interface. Both are reported (rule 5).
	OutcomeApplied
	// OutcomeApplyFailed: apply returned false. The cursor is 0 and the stream is closed; the
	// node reconnects with Hello{held_version: 0} (rule 5). Held() is still the last set applied
	// successfully, unchanged: the interface may now lie anywhere between it and the target,
	// which is why the cursor no longer names it.
	OutcomeApplyFailed
	// OutcomeViolation: rule 13, rule 5's gap or rule 9's version 0, and nothing else: the
	// control plane sent something outside the state machine, so a count of these points at a
	// producer defect. The stream is closed; the cursor and the held set are unchanged; the node
	// reconnects with Hello{held_version: cursor}.
	OutcomeViolation
	// OutcomeMisuse: the driver, not the control plane, did something wrong. Receive with no
	// stream open (ErrStreamClosed) or with a nil apply (ErrApplyNil). Nothing changes; the
	// stream is closed, and the driver opens a new one with Hello. Appended last, so that no
	// earlier value is renumbered; the values are pinned by a test.
	OutcomeMisuse
)

var outcomeNames = [...]string{"", "accumulating", "unchanged", "applied", "apply failed", "violation", "misuse"}

func (k OutcomeKind) String() string {
	if int(k) < len(outcomeNames) {
		return outcomeNames[k]
	}

	return "unknown"
}

// Outcome is exactly one result of Receive.
type Outcome struct {
	kind    OutcomeKind
	set     Set
	version uint64
	skipped uint64
	err     error
}

func (o Outcome) Kind() OutcomeKind { return o.kind }

// Set is the held set after OutcomeApplied, and the zero Set otherwise.
func (o Outcome) Set() Set { return o.set }

// Applied is the message to send after OutcomeApplied: the new cursor and the skipped gauge.
// It is nil for every other outcome. Each call returns a new message.
func (o Outcome) Applied() *keysetpb.Applied {
	if o.kind != OutcomeApplied {
		return nil
	}

	return &keysetpb.Applied{Version: o.version, Skipped: o.skipped}
}

// Err is the sentinel of OutcomeViolation, OutcomeApplyFailed and OutcomeMisuse, and nil otherwise.
func (o Outcome) Err() error { return o.err }

// ClosesStream reports whether the driver must close the stream and reconnect with Hello().
func (o Outcome) ClosesStream() bool {
	return o.kind == OutcomeViolation || o.kind == OutcomeApplyFailed || o.kind == OutcomeMisuse
}

func (Outcome) String() string   { return redacted }
func (Outcome) GoString() string { return redacted }
