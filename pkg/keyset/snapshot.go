// SPDX-License-Identifier: AGPL-3.0-only

package keyset

import "github.com/abylora/shared/pkg/keyset/keysetpb"

// accumulator is an open snapshot: the entries received so far, keyed by public key, and the
// keys refused so far under rule 11. An Upsert of a key already accumulated replaces it
// (rule 2), so a duplicated op has the effect of one.
type accumulator struct {
	version uint64
	valid   map[[32]byte]Entry
	refused map[string]struct{}
}

func newAccumulator(version uint64) *accumulator {
	return &accumulator{version: version, valid: map[[32]byte]Entry{}, refused: map[string]struct{}{}}
}

func (s *accumulator) add(m *keysetpb.KeySetEntry, own *[32]byte) {
	raw := m.GetPublicKey()
	e, ok := wellFormed(m, own)
	if !ok {
		s.refused[string(raw)] = struct{}{}
		if key, isKey := keyOf(raw); isKey {
			delete(s.valid, key)
		}

		return
	}
	delete(s.refused, string(raw))
	s.valid[e.publicKey] = e
}

// finish is rule 12 in a snapshot: every entry whose tunnel_ip is claimed by more than one
// accumulated entry is refused. Rule 11 applies first (key-set.md, workspace root fc9a77b): only
// entries that passed it take part, since a malformed entry is never installed and so cannot
// claim an address. Rule 12 covers tunnel_ip only: nothing is installed for tunnel_ip6.
func (s *accumulator) finish() (Set, map[string]struct{}) {
	claims := make(map[[4]byte]int, len(s.valid))
	for _, e := range s.valid {
		claims[e.tunnelIP]++
	}
	held := Set{entries: make(map[[32]byte]Entry, len(s.valid)), byAddr: make(map[[4]byte][32]byte, len(s.valid))}
	for key, e := range s.valid {
		if claims[e.tunnelIP] > 1 {
			s.refused[string(key[:])] = struct{}{}

			continue
		}
		held.entries[key] = e
		held.byAddr[e.tunnelIP] = key
	}

	return held, s.refused
}
