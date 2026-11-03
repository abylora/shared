// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import (
	"bytes"
	"maps"
	"slices"

	"github.com/abylora/shared/pkg/keyset/keysetpb"
)

// Set is a key set: well-formed entries keyed by public key, no two sharing a tunnel address.
// A Set never changes once returned; the applier builds a new one for every change. The zero
// Set is empty.
type Set struct {
	entries map[[32]byte]Entry
	byAddr  map[[4]byte][32]byte
}

// SetOf builds the set a producer holds, or the set a consumer starts from, and so is the
// producer's snapshot conformance check. It refuses a malformed entry (rule 11), a repeated
// public key, a repeated tunnel_ip, and a repeated non-empty tunnel_ip6: a producer's projection
// has none of these (rule 12: "producer conformance cover[s] both"). Any number of entries may
// have an empty tunnel_ip6, which is absence. Rule 11's own-key check is not part of it: it
// depends on which node receives the set (New refuses a held set holding the node's own key).
func SetOf(entries []*keysetpb.KeySetEntry) (Set, error) {
	s := Set{entries: make(map[[32]byte]Entry, len(entries)), byAddr: make(map[[4]byte][32]byte, len(entries))}
	ip6 := map[[16]byte]struct{}{}
	for _, m := range entries {
		e, ok := wellFormed(m, nil)
		if !ok {
			return Set{}, ErrEntryMalformed
		}
		if _, dup := s.entries[e.publicKey]; dup {
			return Set{}, ErrSetKeyRepeated
		}
		if _, dup := s.byAddr[e.tunnelIP]; dup {
			return Set{}, ErrSetAddressRepeated
		}
		if e.hasTunnelIP6 {
			if _, dup := ip6[e.tunnelIP6]; dup {
				return Set{}, ErrSetAddressRepeated
			}
			ip6[e.tunnelIP6] = struct{}{}
		}
		s.entries[e.publicKey] = e
		s.byAddr[e.tunnelIP] = e.publicKey
	}

	return s, nil
}

// Len is the number of entries.
func (s Set) Len() int { return len(s.entries) }

// Find returns the entry with publicKey, if the set holds one.
func (s Set) Find(publicKey [32]byte) (Entry, bool) {
	e, ok := s.entries[publicKey]

	return e, ok
}

// Entries returns every entry, sorted by public key as raw bytes (bytes.Compare).
func (s Set) Entries() []Entry {
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b Entry) int { return bytes.Compare(a.publicKey[:], b.publicKey[:]) })

	return out
}

// Equal reports whether s and o hold exactly the same entries.
func (s Set) Equal(o Set) bool { return maps.Equal(s.entries, o.entries) }

func (Set) String() string   { return redacted }
func (Set) GoString() string { return redacted }
