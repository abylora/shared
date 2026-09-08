package plain_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/abylora/shared/pkg/transport"
	"github.com/abylora/shared/pkg/transport/plain"
)

// listenRelay stands in for a node's WireGuard UDP socket.
func listenRelay(t *testing.T) (net.PacketConn, transport.Endpoint) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	addr := pc.LocalAddr().(*net.UDPAddr)
	return pc, transport.Endpoint{
		Kind: transport.KindPlain,
		Host: "127.0.0.1",
		Port: uint16(addr.Port),
	}
}

func TestDialerDeliversDatagramToRelay(t *testing.T) {
	relay, endpoint := listenRelay(t)

	conn, err := plain.NewDialer().Dial(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("wg-handshake-initiation")); err != nil {
		t.Fatalf("write: %v", err)
	}

	relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := relay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}

	if got := string(buf[:n]); got != "wg-handshake-initiation" {
		t.Errorf("relay received %q, want %q", got, "wg-handshake-initiation")
	}
}

func TestDialerDeliversRelayReplyToCaller(t *testing.T) {
	relay, endpoint := listenRelay(t)

	conn, err := plain.NewDialer().Dial(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The relay only learns the client's address once it has heard from it.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	_, client, err := relay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}

	if _, err := relay.WriteTo([]byte("wg-handshake-response"), client); err != nil {
		t.Fatalf("relay write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got := string(buf[:n]); got != "wg-handshake-response" {
		t.Errorf("caller received %q, want %q", got, "wg-handshake-response")
	}
}
