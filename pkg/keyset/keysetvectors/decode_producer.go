// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import (
	"encoding/json"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

func decodeVersionedSet(raw json.RawMessage) (uint64, []*keysetpb.KeySetEntry, error) {
	var r struct {
		Version *string           `json:"version"`
		Set     []json.RawMessage `json:"set"`
	}
	if err := strict(raw, &r); err != nil {
		return 0, nil, err
	}
	if r.Version == nil || r.Set == nil {
		return 0, nil, ErrFieldMissing
	}
	v, err := decodeUint64(*r.Version)
	if err != nil {
		return 0, nil, err
	}
	entries, err := decodeEntries(r.Set)

	return v, entries, err
}

func decodeConformanceCase(raw json.RawMessage) (ConformanceCase, error) {
	var r struct {
		ID          *string         `json:"id"`
		Description *string         `json:"description"`
		Old         json.RawMessage `json:"old"`
		New         json.RawMessage `json:"new"`
		Delta       json.RawMessage `json:"delta"`
		Expect      *struct {
			Conforms *bool    `json:"conforms"`
			Failure  *Failure `json:"failure"`
		} `json:"expect"`
	}
	if err := strict(raw, &r); err != nil {
		return ConformanceCase{}, err
	}
	if r.ID == nil || r.Description == nil || r.Old == nil || r.New == nil || r.Delta == nil || r.Expect == nil || r.Expect.Conforms == nil {
		return ConformanceCase{}, ErrFieldMissing
	}
	if *r.Expect.Conforms == (r.Expect.Failure != nil) {
		return ConformanceCase{}, ErrExpectShape
	}
	c := ConformanceCase{ID: *r.ID, Description: *r.Description, Conforms: *r.Expect.Conforms}
	var err error
	if c.OldVersion, c.Old, err = decodeVersionedSet(r.Old); err != nil {
		return ConformanceCase{}, err
	}
	if c.NewVersion, c.New, err = decodeVersionedSet(r.New); err != nil {
		return ConformanceCase{}, err
	}
	if c.Delta, err = decodeDelta(r.Delta); err != nil {
		return ConformanceCase{}, err
	}
	if r.Expect.Failure != nil {
		if !knownFailures[*r.Expect.Failure] {
			return ConformanceCase{}, ErrWordUnknown
		}
		c.Failure = *r.Expect.Failure
	}

	return c, nil
}

func decodeLog(raws []json.RawMessage) ([]LogDelta, error) {
	out := make([]LogDelta, 0, len(raws))
	for _, raw := range raws {
		v, err := uint64Fields(raw, "from_version", "to_version")
		if err != nil {
			return nil, err
		}
		out = append(out, LogDelta{From: v[0], To: v[1]})
	}

	return out, nil
}

func decodeResumeCase(raw json.RawMessage) (ResumeCase, error) {
	var r struct {
		ID          *string           `json:"id"`
		Description *string           `json:"description"`
		HeldVersion *string           `json:"held_version"`
		Log         []json.RawMessage `json:"log"`
		Published   *string           `json:"published"`
		Expect      *struct {
			Send            *string           `json:"send"`
			SnapshotVersion *string           `json:"snapshot_version"`
			Deltas          []json.RawMessage `json:"deltas"`
		} `json:"expect"`
	}
	if err := strict(raw, &r); err != nil {
		return ResumeCase{}, err
	}
	if r.ID == nil || r.Description == nil || r.HeldVersion == nil || r.Log == nil || r.Published == nil || r.Expect == nil || r.Expect.Send == nil {
		return ResumeCase{}, ErrFieldMissing
	}
	c := ResumeCase{ID: *r.ID, Description: *r.Description}
	var err error
	if c.HeldVersion, err = decodeUint64(*r.HeldVersion); err != nil {
		return ResumeCase{}, err
	}
	if c.Log, err = decodeLog(r.Log); err != nil {
		return ResumeCase{}, err
	}
	if c.Published, err = decodeUint64(*r.Published); err != nil {
		return ResumeCase{}, err
	}
	switch *r.Expect.Send {
	case "snapshot":
		if r.Expect.SnapshotVersion == nil || r.Expect.Deltas != nil {
			return ResumeCase{}, ErrLogShape
		}
		c.Snapshot = true
		if c.SnapshotVersion, err = decodeUint64(*r.Expect.SnapshotVersion); err != nil {
			return ResumeCase{}, err
		}
	case "deltas":
		if r.Expect.Deltas == nil || r.Expect.SnapshotVersion != nil {
			return ResumeCase{}, ErrLogShape
		}
		if c.Deltas, err = decodeLog(r.Expect.Deltas); err != nil {
			return ResumeCase{}, err
		}
	default:
		return ResumeCase{}, ErrWordUnknown
	}

	return c, nil
}

func decodeNodeMessage(raw json.RawMessage) (*keysetpb.NodeMessage, error) {
	name, body, err := arm(raw)
	if err != nil {
		return nil, err
	}
	m := &keysetpb.NodeMessage{}
	switch name {
	case "":
	case "wire":
		if err := decodeWire(body, m); err != nil {
			return nil, err
		}
	case "hello":
		v, err := uint64Fields(body, "held_version")
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.NodeMessage_Hello{Hello: &keysetpb.Hello{HeldVersion: v[0]}}
	case "applied":
		v, err := uint64Fields(body, "version", "skipped")
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.NodeMessage_Applied{Applied: &keysetpb.Applied{Version: v[0], Skipped: v[1]}}
	default:
		return nil, ErrArmUnknown
	}

	return m, nil
}

// decodeNodeRecord is {"applied_version": "...", "skipped": "..."}, skipped optional (absent for
// a Hello's record).
func decodeNodeRecord(raw json.RawMessage) (NodeRecord, error) {
	var r struct {
		AppliedVersion *string `json:"applied_version"`
		Skipped        *string `json:"skipped"`
	}
	if err := strict(raw, &r); err != nil {
		return NodeRecord{}, err
	}
	s, err := required(r.AppliedVersion)
	if err != nil {
		return NodeRecord{}, err
	}
	rec := NodeRecord{}
	if rec.AppliedVersion, err = decodeUint64(s); err != nil {
		return NodeRecord{}, err
	}
	if r.Skipped != nil {
		if rec.Skipped, err = decodeUint64(*r.Skipped); err != nil {
			return NodeRecord{}, err
		}
		rec.HasSkipped = true
	}

	return rec, nil
}

func decodeNodeDirectionCase(raw json.RawMessage) (NodeDirectionCase, error) {
	var r struct {
		ID          *string           `json:"id"`
		Description *string           `json:"description"`
		Steps       []json.RawMessage `json:"steps"`
		Records     []json.RawMessage `json:"records"`
	}
	if err := strict(raw, &r); err != nil {
		return NodeDirectionCase{}, err
	}
	if r.ID == nil || r.Description == nil || r.Steps == nil || r.Records == nil {
		return NodeDirectionCase{}, ErrFieldMissing
	}
	c := NodeDirectionCase{ID: *r.ID, Description: *r.Description}
	closed := false
	for _, rawStep := range r.Steps {
		var s struct {
			Sent     json.RawMessage `json:"sent"`
			Received json.RawMessage `json:"received"`
			Expect   *struct {
				Outcome   *NodeOutcome    `json:"outcome"`
				Record    json.RawMessage `json:"record"`
				Violation *Violation      `json:"violation"`
			} `json:"expect"`
		}
		if err := strict(rawStep, &s); err != nil {
			return NodeDirectionCase{}, err
		}
		switch {
		case s.Sent != nil && s.Received == nil && s.Expect == nil:
			m, err := decodeControlPlaneMessage(s.Sent)
			if err != nil {
				return NodeDirectionCase{}, err
			}
			c.Steps = append(c.Steps, NodeStep{Sent: m})
		case s.Received != nil && s.Sent == nil && s.Expect != nil && s.Expect.Outcome != nil:
			m, err := decodeNodeMessage(s.Received)
			if err != nil {
				return NodeDirectionCase{}, err
			}
			o := *s.Expect.Outcome
			if !knownNodeOutcomes[o] {
				return NodeDirectionCase{}, ErrWordUnknown
			}
			if (o == NodeOutcomeRecord) != (s.Expect.Record != nil) || (o == NodeOutcomeViolation) != (s.Expect.Violation != nil) {
				return NodeDirectionCase{}, ErrExpectShape
			}
			if closed != (o == NodeOutcomeClosed) {
				return NodeDirectionCase{}, ErrStepAfterClose
			}
			e := NodeExpect{Outcome: o}
			if s.Expect.Record != nil {
				if e.Record, err = decodeNodeRecord(s.Expect.Record); err != nil {
					return NodeDirectionCase{}, err
				}
			}
			if s.Expect.Violation != nil {
				if !nodeViolations[*s.Expect.Violation] {
					return NodeDirectionCase{}, ErrWordUnknown
				}
				e.Violation = *s.Expect.Violation
				closed = true
			}
			c.Steps = append(c.Steps, NodeStep{Received: m, Expect: e})
		default:
			return NodeDirectionCase{}, ErrStepShape
		}
	}
	for _, rawRecord := range r.Records {
		rec, err := decodeNodeRecord(rawRecord)
		if err != nil {
			return NodeDirectionCase{}, err
		}
		c.Records = append(c.Records, rec)
	}

	return c, nil
}
