// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "slices"

// LoggedDelta is one Delta in the producer's change log, by its versions only.
type LoggedDelta struct {
	From, To uint64
}

// ResumePlan is the producer's answer to a Hello (rule 3): either a snapshot at the published
// version, followed by the deltas published after it as they come, or the logged deltas after
// the node's held version, possibly none.
type ResumePlan struct {
	snapshot bool
	version  uint64
	deltas   []LoggedDelta
}

func (p ResumePlan) Snapshot() bool { return p.snapshot }

// SnapshotVersion is the version the snapshot carries, the published version, when Snapshot is
// true.
func (p ResumePlan) SnapshotVersion() uint64 { return p.version }

// Deltas are the logged deltas to send now, oldest first, when Snapshot is false.
func (p ResumePlan) Deltas() []LoggedDelta { return slices.Clone(p.deltas) }

// PlanResume is rule 3. published is the version of the last published epoch boundary
// (rule 15), never a live counter. log is the producer's change log, oldest first: contiguous
// deltas whose last To is published. It is empty after a restart (rule 7).
//
// The log can resume from exactly these versions: the one it starts from (the first delta's
// From) and the To of each logged delta. A number merely inside the log's range is not one of
// them, because versions between two boundaries are never published. A held version that the
// log can resume from gets every logged delta after it and no snapshot; when it is published,
// that is no delta at all. Any other held version (0, below the log, between two logged
// versions, above published, or anything when the log is empty) gets a snapshot.
func PlanResume(heldVersion uint64, log []LoggedDelta, published uint64) (ResumePlan, error) {
	if published == 0 {
		return ResumePlan{}, ErrLogInvalid
	}
	for i, d := range log {
		if d.From == 0 || d.To <= d.From || (i > 0 && log[i-1].To != d.From) {
			return ResumePlan{}, ErrLogInvalid
		}
	}
	if len(log) > 0 && log[len(log)-1].To != published {
		return ResumePlan{}, ErrLogInvalid
	}

	if len(log) > 0 && heldVersion == log[0].From {
		return ResumePlan{deltas: slices.Clone(log)}, nil
	}
	for i, d := range log {
		if d.To == heldVersion {
			return ResumePlan{deltas: slices.Clone(log[i+1:])}, nil
		}
	}

	return ResumePlan{snapshot: true, version: published}, nil
}
