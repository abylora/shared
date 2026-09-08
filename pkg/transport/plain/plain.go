// Package plain carries WireGuard over UDP exactly as WireGuard intends, with
// no obfuscation. It is the baseline every other transport is measured against.
package plain

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/abylora/shared/pkg/transport"
)

// Dialer opens plain UDP connections to a relay.
type Dialer struct{}

// NewDialer returns a Dialer.
func NewDialer() *Dialer { return &Dialer{} }

// Kind implements transport.Dialer.
func (d *Dialer) Kind() transport.Kind { return transport.KindPlain }

// Dial implements transport.Dialer. The returned Conn is a connected UDP
// socket, so datagram boundaries are preserved and no framing is added.
func (d *Dialer) Dial(ctx context.Context, ep transport.Endpoint) (transport.Conn, error) {
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))

	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("plain: failed to dial %s: %w", addr, err)
	}

	return conn, nil
}
