// SPDX-License-Identifier: AGPL-3.0-only

package keysetpb

import "testing"

// THE METHOD PATH IS WIRE CONTRACT, the same way transport.Kind's strings are. A node sends
// exactly this path, so renaming the proto package, the service or the method breaks every
// deployed node.
func TestTheMethodIsExactlyAbyloraKeysetV1KeySetStream(t *testing.T) {
	if KeySet_Stream_FullMethodName != "/abylora.keyset.v1.KeySet/Stream" {
		t.Errorf("the method is %q, want /abylora.keyset.v1.KeySet/Stream", KeySet_Stream_FullMethodName)
	}
	if KeySet_ServiceDesc.ServiceName != "abylora.keyset.v1.KeySet" {
		t.Errorf("the service is %q, want abylora.keyset.v1.KeySet", KeySet_ServiceDesc.ServiceName)
	}
}

// ONE BIDIRECTIONAL STREAM AND NO OTHER METHOD. The node opens it (D9) and sends NodeMessage;
// the control plane sends ControlPlaneMessage. Enrollment (Slice 6) is a separate service.
func TestKeySetHasOneMethodABidirectionalStreamFromNodeMessageToControlPlaneMessage(t *testing.T) {
	services := File_abylora_keyset_v1_keyset_proto.Services()
	if services.Len() != 1 {
		t.Fatalf("the file defines %d services, want 1", services.Len())
	}
	methods := services.Get(0).Methods()
	if methods.Len() != 1 {
		t.Fatalf("KeySet has %d methods, want 1", methods.Len())
	}
	m := methods.Get(0)
	if m.Name() != "Stream" || !m.IsStreamingClient() || !m.IsStreamingServer() {
		t.Errorf("the method is %s, client streaming %v, server streaming %v; want Stream, both", m.Name(), m.IsStreamingClient(), m.IsStreamingServer())
	}
	if m.Input().FullName() != "abylora.keyset.v1.NodeMessage" || m.Output().FullName() != "abylora.keyset.v1.ControlPlaneMessage" {
		t.Errorf("Stream takes %s and returns %s", m.Input().FullName(), m.Output().FullName())
	}

	desc := KeySet_ServiceDesc
	if len(desc.Methods) != 0 || len(desc.Streams) != 1 {
		t.Fatalf("the service descriptor has %d unary methods and %d streams, want 0 and 1", len(desc.Methods), len(desc.Streams))
	}
	if s := desc.Streams[0]; s.StreamName != "Stream" || !s.ClientStreams || !s.ServerStreams {
		t.Errorf("the stream is %+v, want Stream streaming both ways", s)
	}
}
