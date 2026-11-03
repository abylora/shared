// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// secondsPerDay is the day boundary valid_until sits on (key-set.md, Record).
const secondsPerDay = 86400

// redacted is how every type here renders through %v, %s, %x, %q, %+v and %#v, and so through
// slog's text and JSON handlers. A verb such as %d still walks the fields: fmt.Formatter would
// need fmt, which this package does not import. The values are public facts; this keeps them
// out of a consumer's log line by accident, which rule 11 forbids for entries.
const redacted = "keyset.[redacted]"

// Entry is one well-formed key set entry, held by value: a device's public key, its IPv4
// tunnel address, its IPv6 tunnel address if it has one, and valid_until. It is built only by
// rule 11's check, so every Entry is well-formed.
type Entry struct {
	publicKey    [32]byte
	tunnelIP     [4]byte
	tunnelIP6    [16]byte
	hasTunnelIP6 bool
	validUntil   int64
}

// PublicKey is the device's WireGuard public key.
func (e Entry) PublicKey() [32]byte { return e.publicKey }

// TunnelIP is the device's IPv4 tunnel address, inside 10.64.0.0/10 and outside 10.64.0.0/24.
func (e Entry) TunnelIP() [4]byte { return e.tunnelIP }

// TunnelIP6 is the device's IPv6 tunnel address, and false when it has none. When it is false the
// array is all zero and is not an address: never read it as ::. Until an IPv6 pool is ruled, a
// node installs nothing for it (rule 11).
func (e Entry) TunnelIP6() ([16]byte, bool) { return e.tunnelIP6, e.hasTunnelIP6 }

// ValidUntil is the entitlement expiry in Unix seconds, a multiple of 86400. The entry is
// valid while now < valid_until; judging that is the node's, locally. This package has no clock.
func (e Entry) ValidUntil() int64 { return e.validUntil }

func (Entry) String() string   { return redacted }
func (Entry) GoString() string { return redacted }

// keyOf returns raw as a public key when it is exactly 32 bytes.
func keyOf(raw []byte) ([32]byte, bool) {
	if len(raw) != 32 {
		return [32]byte{}, false
	}

	return [32]byte(raw), true
}

// wellFormed is rule 11. It returns the entry and true, or false when the entry is malformed:
// a key that is not 32 bytes; a key equal to own, the receiving node's own interface key (nil
// on the producer's side, where a Delta goes to every node); a tunnel_ip that is not exactly 4
// bytes, lies outside 10.64.0.0/10 or inside the reserved 10.64.0.0/24; a tunnel_ip6 of any
// length but 0 (absent) or 16; a valid_until that is not a multiple of 86400. The address
// tests are on raw bytes. A 16-byte IPv4-mapped tunnel_ip is malformed: the length is tested
// first.
func wellFormed(m *keysetpb.KeySetEntry, own *[32]byte) (Entry, bool) {
	key, ok := keyOf(m.GetPublicKey())
	if !ok || (own != nil && key == *own) {
		return Entry{}, false
	}
	ip := m.GetTunnelIp()
	if len(ip) != 4 || !inDevicePool(ip) {
		return Entry{}, false
	}
	ip6 := m.GetTunnelIp6()
	if len(ip6) != 0 && len(ip6) != 16 {
		return Entry{}, false
	}
	if m.GetValidUntil()%secondsPerDay != 0 {
		return Entry{}, false
	}

	e := Entry{publicKey: key, tunnelIP: [4]byte(ip), validUntil: m.GetValidUntil()}
	if len(ip6) == 16 {
		e.tunnelIP6, e.hasTunnelIP6 = [16]byte(ip6), true
	}

	return e, true
}

// inDevicePool reports whether a 4-byte address lies in 10.64.0.0/10 (second octet 64..127,
// so its top two bits are 01) and outside 10.64.0.0/24, which is reserved for infrastructure
// (key-set.md, In-tunnel addresses).
func inDevicePool(ip []byte) bool {
	inPool := ip[0] == 10 && ip[1]&0xc0 == 0x40
	reserved := ip[0] == 10 && ip[1] == 64 && ip[2] == 0

	return inPool && !reserved
}
