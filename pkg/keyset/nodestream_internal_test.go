// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import (
	"testing"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// The checker's memory is bounded: only versions above the last accepted Applied can still be
// legal, so each accepted Applied drops every delivered version at or below it. A stream that
// lives for months delivers a version every minute (rule 15); without this the set grows for
// as long as the stream lives.
func TestTheCheckerForgetsDeliveredVersionsAtOrBelowEachApplied(t *testing.T) {
	c := NewNodeStreamChecker()
	if _, err := c.Received(&keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Hello{Hello: &keysetpb.Hello{HeldVersion: 0}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	for v := uint64(130000); v < 131000; v++ {
		c.Sent(&keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: v}}})
		if _, err := c.Received(&keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Applied{Applied: &keysetpb.Applied{Version: v}}}); err != nil {
			t.Fatalf("applied %d: %v", v, err)
		}
		if n := len(c.delivered); n > 1 {
			t.Fatalf("after applied %d the checker holds %d delivered versions, want at most 1", v, n)
		}
	}
}

// A version delivered at or below the last accepted Applied can never become legal (an Applied
// of it would be lower, or equal and already accepted), so it is not kept either.
func TestTheCheckerKeepsNoDeliveredVersionAtOrBelowTheLastApplied(t *testing.T) {
	c := NewNodeStreamChecker()
	c.Received(&keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Hello{Hello: &keysetpb.Hello{HeldVersion: 0}}})
	c.Sent(&keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: 130000}}})
	if _, err := c.Received(&keysetpb.NodeMessage{Body: &keysetpb.NodeMessage_Applied{Applied: &keysetpb.Applied{Version: 130000}}}); err != nil {
		t.Fatalf("applied: %v", err)
	}
	for _, v := range []uint64{129000, 130000} {
		c.Sent(&keysetpb.ControlPlaneMessage{Body: &keysetpb.ControlPlaneMessage_SnapshotEnd{SnapshotEnd: &keysetpb.SnapshotEnd{Version: v}}})
	}
	if n := len(c.delivered); n != 0 {
		t.Fatalf("the checker holds %d delivered versions at or below the last Applied, want 0", n)
	}
}
