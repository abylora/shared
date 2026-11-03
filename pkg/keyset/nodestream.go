// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// NodeRecord is what the control plane may record from one node message: the node's applied
// version, and its skipped gauge when the message was an Applied. A Hello records its
// held_version as the applied version at once (key-set.md, Readiness) and carries no gauge.
type NodeRecord struct {
	appliedVersion uint64
	skipped        uint64
	hasSkipped     bool
}

func (r NodeRecord) AppliedVersion() uint64 { return r.appliedVersion }

// Skipped is the gauge, and false for a Hello's record.
func (r NodeRecord) Skipped() (uint64, bool) { return r.skipped, r.hasSkipped }

// NodeStreamChecker is rule 16, the node's direction of one stream, as the control plane
// enforces it. Sent is told every message the control plane sends on the stream; Received
// judges every message the node sends.
type NodeStreamChecker struct {
	hello     bool
	closed    bool
	delivered map[uint64]struct{}
	applied   bool
	last      uint64
}

func NewNodeStreamChecker() *NodeStreamChecker {
	return &NodeStreamChecker{delivered: map[uint64]struct{}{}}
}

// Sent records a version as delivered on this stream when m completes a set: a SnapshotEnd's
// version or a Delta's to_version (rule 16). A SnapshotBegin, a Heartbeat and the Hello's own
// held_version deliver nothing. A version at or below the last accepted Applied is not kept: it
// can never become legal.
func (c *NodeStreamChecker) Sent(m *keysetpb.ControlPlaneMessage) {
	var version uint64
	switch body := m.GetBody().(type) {
	case *keysetpb.ControlPlaneMessage_SnapshotEnd:
		version = body.SnapshotEnd.GetVersion()
	case *keysetpb.ControlPlaneMessage_Delta:
		version = body.Delta.GetToVersion()
	default:
		return
	}
	if c.applied && version <= c.last {
		return
	}
	c.delivered[version] = struct{}{}
}

// Received returns the record m allows, or the violation it is. Checked in order: no known arm,
// an Applied before the Hello, a second Hello, an Applied below the previous Applied on this
// stream, an Applied naming a version not delivered on this stream. Equal to the previous
// Applied is legal ("no lower"), and it was delivered. "No lower" never compares with the
// Hello: a snapshot answering a held_version above the published version is legitimately
// lower. Each accepted Applied forgets every delivered version at or below it, since only a
// version above it can still be legal; that bounds the checker's memory. A violation closes the
// checker: every later message returns ErrNodeStreamClosed, so nothing is recorded from the
// violating message onward, and records already returned, the Hello's included, stand.
func (c *NodeStreamChecker) Received(m *keysetpb.NodeMessage) (NodeRecord, error) {
	if c.closed {
		return NodeRecord{}, ErrNodeStreamClosed
	}
	switch body := m.GetBody().(type) {
	case *keysetpb.NodeMessage_Hello:
		if c.hello {
			return c.violate(ErrHelloRepeated)
		}
		c.hello = true

		return NodeRecord{appliedVersion: body.Hello.GetHeldVersion()}, nil
	case *keysetpb.NodeMessage_Applied:
		if !c.hello {
			return c.violate(ErrAppliedBeforeHello)
		}
		version := body.Applied.GetVersion()
		if c.applied && version < c.last {
			return c.violate(ErrAppliedDecreasing)
		}
		if _, ok := c.delivered[version]; !ok && (!c.applied || version != c.last) {
			return c.violate(ErrAppliedNotDelivered)
		}
		c.applied, c.last = true, version
		for v := range c.delivered {
			if v <= version {
				delete(c.delivered, v)
			}
		}

		return NodeRecord{appliedVersion: version, skipped: body.Applied.GetSkipped(), hasSkipped: true}, nil
	default:
		return c.violate(ErrNodeMessageNoArm)
	}
}

func (c *NodeStreamChecker) violate(err error) (NodeRecord, error) {
	c.closed = true

	return NodeRecord{}, err
}
