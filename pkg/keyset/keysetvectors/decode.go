// SPDX-License-Identifier: AGPL-3.0-only

package keysetvectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// strict decodes exactly one JSON value into v, refusing null, an unknown key and trailing data.
func strict(raw []byte, v any) error {
	if isNull(raw) {
		return ErrNull
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.Join(ErrJSON, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrTrailingData
	}

	return nil
}

func isNull(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// refuseDuplicateKeys walks the whole document once, refusing any object that repeats a key, so
// that a reader taking the first value and one taking the last cannot disagree. Copied in shape
// from pkg/signingcert/decode.go's scan; test helpers and unexported code cannot be shared.
func refuseDuplicateKeys(octets []byte) error {
	dec := json.NewDecoder(bytes.NewReader(octets))
	dec.UseNumber()

	return scanValue(dec)
}

func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.Join(ErrJSON, err)
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return errors.Join(ErrJSON, err)
			}
			key, _ := kt.(string)
			if seen[key] {
				return ErrDuplicateKey
			}
			seen[key] = true
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errors.Join(ErrJSON, err)
		}
	case json.Delim('['):
		for dec.More() {
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errors.Join(ErrJSON, err)
		}
	}

	return nil
}

// decodeHex is lowercase, even-length hex, possibly empty.
func decodeHex(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, ErrHexInvalid
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrHexInvalid
	}

	return b, nil
}

// decodeUint64 is a canonical decimal: no sign, no leading zero, within uint64.
func decodeUint64(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, ErrDecimalInvalid
	}

	return v, nil
}

// decodeInt64 is a canonical decimal: an optional "-", no leading zero, never "-0", within int64.
func decodeInt64(s string) (int64, error) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(v, 10) != s {
		return 0, ErrDecimalInvalid
	}

	return v, nil
}

// uint64Fields decodes an object whose keys are exactly names, each a decimal string.
func uint64Fields(raw json.RawMessage, names ...string) ([]uint64, error) {
	var m map[string]json.RawMessage
	if err := strict(raw, &m); err != nil {
		return nil, err
	}
	if len(m) != len(names) {
		return nil, ErrFieldMissing
	}
	out := make([]uint64, len(names))
	for i, name := range names {
		value, ok := m[name]
		if !ok {
			return nil, ErrFieldMissing
		}
		var s string
		if err := strict(value, &s); err != nil {
			return nil, err
		}
		v, err := decodeUint64(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}

	return out, nil
}

func required(p *string) (string, error) {
	if p == nil {
		return "", ErrFieldMissing
	}

	return *p, nil
}

// decodeEntry is an entry: all four keys required, bytes in hex, valid_until a signed decimal.
func decodeEntry(raw json.RawMessage) (*keysetpb.KeySetEntry, error) {
	var r struct {
		PublicKey  *string `json:"public_key"`
		TunnelIP   *string `json:"tunnel_ip"`
		TunnelIP6  *string `json:"tunnel_ip6"`
		ValidUntil *string `json:"valid_until"`
	}
	if err := strict(raw, &r); err != nil {
		return nil, err
	}
	if r.PublicKey == nil || r.TunnelIP == nil || r.TunnelIP6 == nil || r.ValidUntil == nil {
		return nil, ErrFieldMissing
	}
	key, err := decodeHex(*r.PublicKey)
	if err != nil {
		return nil, err
	}
	ip, err := decodeHex(*r.TunnelIP)
	if err != nil {
		return nil, err
	}
	ip6, err := decodeHex(*r.TunnelIP6)
	if err != nil {
		return nil, err
	}
	until, err := decodeInt64(*r.ValidUntil)
	if err != nil {
		return nil, err
	}

	return &keysetpb.KeySetEntry{PublicKey: key, TunnelIp: ip, TunnelIp6: ip6, ValidUntil: until}, nil
}

func decodeEntries(raws []json.RawMessage) ([]*keysetpb.KeySetEntry, error) {
	out := make([]*keysetpb.KeySetEntry, 0, len(raws))
	for _, raw := range raws {
		e, err := decodeEntry(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}

	return out, nil
}

// arm returns a message object's one key and its value, or "" for {}, which is a message with
// no arm.
func arm(raw json.RawMessage) (string, json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := strict(raw, &m); err != nil {
		return "", nil, err
	}
	if len(m) > 1 {
		return "", nil, ErrArmsRepeated
	}
	for name, body := range m {
		return name, body, nil
	}

	return "", nil, nil
}

func decodeWire(body json.RawMessage, m proto.Message) error {
	var s string
	if err := strict(body, &s); err != nil {
		return err
	}
	b, err := decodeHex(s)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(b, m); err != nil {
		return ErrWireInvalid
	}

	return nil
}

// decodeUpsert is {"entry": ENTRY}, or {} for an Upsert with no entry.
func decodeUpsert(raw json.RawMessage) (*keysetpb.Upsert, error) {
	var r struct {
		Entry json.RawMessage `json:"entry"`
	}
	if err := strict(raw, &r); err != nil {
		return nil, err
	}
	if r.Entry == nil {
		return &keysetpb.Upsert{}, nil
	}
	e, err := decodeEntry(r.Entry)
	if err != nil {
		return nil, err
	}

	return &keysetpb.Upsert{Entry: e}, nil
}

func decodeDelta(raw json.RawMessage) (*keysetpb.Delta, error) {
	var r struct {
		FromVersion *string           `json:"from_version"`
		ToVersion   *string           `json:"to_version"`
		Ops         []json.RawMessage `json:"ops"`
	}
	if err := strict(raw, &r); err != nil {
		return nil, err
	}
	if r.FromVersion == nil || r.ToVersion == nil || r.Ops == nil {
		return nil, ErrFieldMissing
	}
	from, err := decodeUint64(*r.FromVersion)
	if err != nil {
		return nil, err
	}
	to, err := decodeUint64(*r.ToVersion)
	if err != nil {
		return nil, err
	}
	d := &keysetpb.Delta{FromVersion: from, ToVersion: to, Ops: make([]*keysetpb.DeltaOp, 0, len(r.Ops))}
	for _, rawOp := range r.Ops {
		op, err := decodeOp(rawOp)
		if err != nil {
			return nil, err
		}
		d.Ops = append(d.Ops, op)
	}

	return d, nil
}

func decodeOp(raw json.RawMessage) (*keysetpb.DeltaOp, error) {
	name, body, err := arm(raw)
	if err != nil {
		return nil, err
	}
	switch name {
	case "":
		return &keysetpb.DeltaOp{}, nil
	case "upsert":
		u, err := decodeUpsert(body)
		if err != nil {
			return nil, err
		}

		return &keysetpb.DeltaOp{Op: &keysetpb.DeltaOp_Upsert{Upsert: u}}, nil
	case "remove":
		var r struct {
			PublicKey *string `json:"public_key"`
		}
		if err := strict(body, &r); err != nil {
			return nil, err
		}
		s, err := required(r.PublicKey)
		if err != nil {
			return nil, err
		}
		key, err := decodeHex(s)
		if err != nil {
			return nil, err
		}

		return &keysetpb.DeltaOp{Op: &keysetpb.DeltaOp_Remove{Remove: &keysetpb.Remove{PublicKey: key}}}, nil
	default:
		return nil, ErrArmUnknown
	}
}

func decodeControlPlaneMessage(raw json.RawMessage) (*keysetpb.ControlPlaneMessage, error) {
	name, body, err := arm(raw)
	if err != nil {
		return nil, err
	}
	m := &keysetpb.ControlPlaneMessage{}
	switch name {
	case "":
		return m, nil
	case "wire":
		if err := decodeWire(body, m); err != nil {
			return nil, err
		}

		return m, nil
	case "snapshot_begin":
		v, err := uint64Fields(body, "version")
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.ControlPlaneMessage_SnapshotBegin{SnapshotBegin: &keysetpb.SnapshotBegin{Version: v[0]}}
	case "upsert":
		u, err := decodeUpsert(body)
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.ControlPlaneMessage_Upsert{Upsert: u}
	case "snapshot_end":
		v, err := uint64Fields(body, "version")
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: v[0]}}
	case "delta":
		d, err := decodeDelta(body)
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.ControlPlaneMessage_Delta{Delta: d}
	case "heartbeat":
		v, err := uint64Fields(body, "current_version")
		if err != nil {
			return nil, err
		}
		m.Body = &keysetpb.ControlPlaneMessage_Heartbeat{Heartbeat: &keysetpb.Heartbeat{CurrentVersion: v[0]}}
	default:
		return nil, ErrArmUnknown
	}

	return m, nil
}

func decodeConsumerCase(raw json.RawMessage) (ConsumerCase, error) {
	var r struct {
		ID           *string `json:"id"`
		Description  *string `json:"description"`
		OwnPublicKey *string `json:"own_public_key"`
		Initial      *struct {
			Cursor *string           `json:"cursor"`
			Set    []json.RawMessage `json:"set"`
		} `json:"initial"`
		Steps []json.RawMessage `json:"steps"`
		Final *struct {
			Cursor  *string         `json:"cursor"`
			Set     json.RawMessage `json:"set"`
			Skipped *string         `json:"skipped"`
		} `json:"final"`
	}
	if err := strict(raw, &r); err != nil {
		return ConsumerCase{}, err
	}
	if r.ID == nil || r.Description == nil || r.OwnPublicKey == nil || r.Initial == nil || r.Initial.Cursor == nil ||
		r.Initial.Set == nil || r.Steps == nil || r.Final == nil || r.Final.Cursor == nil {
		return ConsumerCase{}, ErrFieldMissing
	}

	c := ConsumerCase{ID: *r.ID, Description: *r.Description}
	own, err := decodeHex(*r.OwnPublicKey)
	if err != nil {
		return ConsumerCase{}, err
	}
	if len(own) != 32 {
		return ConsumerCase{}, ErrOwnKeyLength
	}
	c.OwnPublicKey = [32]byte(own)
	if c.InitialCursor, err = decodeUint64(*r.Initial.Cursor); err != nil {
		return ConsumerCase{}, err
	}
	if c.InitialSet, err = decodeEntries(r.Initial.Set); err != nil {
		return ConsumerCase{}, err
	}
	if c.Steps, err = decodeConsumerSteps(r.Steps); err != nil {
		return ConsumerCase{}, err
	}

	if c.Final.Cursor, err = decodeUint64(*r.Final.Cursor); err != nil {
		return ConsumerCase{}, err
	}
	if r.Final.Set != nil {
		var raws []json.RawMessage
		if err := strict(r.Final.Set, &raws); err != nil {
			return ConsumerCase{}, err
		}
		if c.Final.Set, err = decodeEntries(raws); err != nil {
			return ConsumerCase{}, err
		}
		c.Final.SetAsserted = true
	}
	if r.Final.Skipped != nil {
		if c.Final.Skipped, err = decodeUint64(*r.Final.Skipped); err != nil {
			return ConsumerCase{}, err
		}
		c.Final.SkippedAsserted = true
	}
	if !c.Final.SetAsserted || (!c.Final.SkippedAsserted && lastOutcome(c.Steps) != OutcomeApplyFailed) {
		return ConsumerCase{}, ErrFinalUnasserted
	}

	return c, nil
}

func lastOutcome(steps []ConsumerStep) Outcome {
	for i := len(steps) - 1; i >= 0; i-- {
		if !steps[i].Hello {
			return steps[i].Expect.Outcome
		}
	}

	return ""
}

// decodeConsumerSteps also holds the stream discipline: the first step is a hello, and after an
// outcome that closes the stream the next receive needs a hello first.
func decodeConsumerSteps(raws []json.RawMessage) ([]ConsumerStep, error) {
	steps := make([]ConsumerStep, 0, len(raws))
	open := false
	for _, raw := range raws {
		var r struct {
			Hello         json.RawMessage `json:"hello"`
			Receive       json.RawMessage `json:"receive"`
			ApplySucceeds *bool           `json:"apply_succeeds"`
			Expect        json.RawMessage `json:"expect"`
		}
		if err := strict(raw, &r); err != nil {
			return nil, err
		}
		switch {
		case r.Hello != nil && r.Receive == nil && r.ApplySucceeds == nil && r.Expect == nil:
			v, err := uint64Fields(r.Hello, "held_version")
			if err != nil {
				return nil, err
			}
			steps = append(steps, ConsumerStep{Hello: true, HeldVersion: v[0]})
			open = true
		case r.Receive != nil && r.Hello == nil && r.Expect != nil:
			if !open {
				return nil, ErrStepWithoutHello
			}
			m, err := decodeControlPlaneMessage(r.Receive)
			if err != nil {
				return nil, err
			}
			e, err := decodeConsumerExpect(r.Expect)
			if err != nil {
				return nil, err
			}
			succeeds := r.ApplySucceeds == nil || *r.ApplySucceeds
			if (e.Outcome == OutcomeApplyFailed) == succeeds {
				return nil, ErrApplySucceedsInconsistent
			}
			steps = append(steps, ConsumerStep{Message: m, ApplySucceeds: succeeds, Expect: e})
			if e.Outcome == OutcomeViolation || e.Outcome == OutcomeApplyFailed {
				open = false
			}
		default:
			return nil, ErrStepShape
		}
	}
	if len(steps) == 0 || !steps[0].Hello {
		return nil, ErrStepWithoutHello
	}

	return steps, nil
}

func decodeConsumerExpect(raw json.RawMessage) (ConsumerExpect, error) {
	var r struct {
		Outcome   *Outcome        `json:"outcome"`
		Applied   json.RawMessage `json:"applied"`
		Violation *Violation      `json:"violation"`
	}
	if err := strict(raw, &r); err != nil {
		return ConsumerExpect{}, err
	}
	if r.Outcome == nil {
		return ConsumerExpect{}, ErrFieldMissing
	}
	if !knownOutcomes[*r.Outcome] {
		return ConsumerExpect{}, ErrWordUnknown
	}
	if (*r.Outcome == OutcomeApplied) != (r.Applied != nil) || (*r.Outcome == OutcomeViolation) != (r.Violation != nil) {
		return ConsumerExpect{}, ErrExpectShape
	}
	e := ConsumerExpect{Outcome: *r.Outcome}
	if r.Applied != nil {
		v, err := uint64Fields(r.Applied, "version", "skipped")
		if err != nil {
			return ConsumerExpect{}, err
		}
		e.Applied = &keysetpb.Applied{Version: v[0], Skipped: v[1]}
	}
	if r.Violation != nil {
		if !consumerViolations[*r.Violation] {
			return ConsumerExpect{}, ErrWordUnknown
		}
		e.Violation = *r.Violation
	}

	return e, nil
}
