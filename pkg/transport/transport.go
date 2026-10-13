// Package transport defines how WireGuard datagrams travel between a client and
// a relay. Vanilla WireGuard is one transport among several; the obfuscating
// transports exist so that a network which fingerprints and drops WireGuard
// cannot tell our traffic apart from ordinary internet traffic.
//
// The seam is deliberately narrow: a transport is a connected datagram pipe to
// exactly one relay. That keeps every implementation testable on its own and
// keeps WireGuard itself unaware that any of this exists.
package transport

import (
	"context"
	"slices"
	"time"
)

// Kind names a transport implementation. It appears verbatim in the signed
// relay list, so these strings are part of the wire contract.
type Kind string

const (
	// KindPlain is vanilla WireGuard over UDP, with no obfuscation.
	KindPlain Kind = "plain"
	// KindUDP2TCP wraps WireGuard's UDP inside a TCP stream, for networks that
	// block UDP outright.
	KindUDP2TCP Kind = "udp2tcp"
	// KindShadowsocks disguises the traffic using the Shadowsocks protocol.
	KindShadowsocks Kind = "shadowsocks"
	// KindQUIC carries the traffic inside QUIC, which is hard to distinguish
	// from ordinary HTTPS.
	KindQUIC Kind = "quic"
)

// kinds is the whole value set. A package-level var cloned by Kinds, so no caller can
// rewrite the set for every other caller in the process.
var kinds = []Kind{KindPlain, KindUDP2TCP, KindShadowsocks, KindQUIC}

// Kinds returns every transport kind, as a copy. It is the one value set for the relay
// list's endpoints[].kind; consumers drift-test their own enums against it.
func Kinds() []Kind { return slices.Clone(kinds) }

// Valid reports whether k is one of the transport kinds.
func (k Kind) Valid() bool { return slices.Contains(kinds, k) }

// Endpoint is one advertised way to reach a relay's WireGuard listener.
// Relays announce their endpoints in the relay list; clients pick one.
type Endpoint struct {
	Kind Kind
	Host string
	Port uint16
	// Params carries transport-specific settings, such as a Shadowsocks cipher
	// or a QUIC server name. Kept opaque so adding a transport does not change
	// the relay list schema.
	Params map[string]string
}

// Conn is a connected datagram pipe carrying WireGuard packets to one relay.
// Datagram boundaries are preserved: one Write is one Read on the far side.
type Conn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// Dialer opens a Conn to a relay. Clients hold dialers.
type Dialer interface {
	Kind() Kind
	Dial(ctx context.Context, ep Endpoint) (Conn, error)
}
